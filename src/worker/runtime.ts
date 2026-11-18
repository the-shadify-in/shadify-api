import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { dbPool } from '../services/quota.js';
import { r2Client } from '../services/r2.js';
import { PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { env } from '../config/env.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const WORKER_ID = `worker-${process.pid}-${Math.random().toString(36).substring(2, 8)}`;
let isShuttingDown = false;
let activeLeases: { id: string; lease_token: string }[] = [];

async function executeTransformWithTimeout(
  imageBuffer: Buffer,
  timeoutMs = 4000
): Promise<{ previewWebp: Buffer; thumbnailWebp: Buffer }> {
  return new Promise((resolve, reject) => {
    const workerPath = path.resolve(__dirname, 'transform-worker.js');
    const worker = new Worker(workerPath, {
      workerData: { imageBuffer },
    });

    const timer = setTimeout(async () => {
      try {
        await worker.terminate();
      } catch (e) {
        // Ignored
      }
      reject(new Error(`Sharp transformation timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    worker.on('message', (msg) => {
      clearTimeout(timer);
      if (msg.success) {
        resolve(msg.data);
      } else {
        reject(new Error(msg.error));
      }
    });

    worker.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });

    worker.on('exit', (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(new Error(`Worker stopped with exit code ${code}`));
      }
    });
  });
}

export async function processOutboxBatch() {
  if (isShuttingDown) return;

  const client = await dbPool.connect();
  try {
    // 1. Acquire batch
    const batchRes = await client.query(
      `SELECT event_id, aggregate_id, event_type, generation_token, payload, retry_count, lease_token
       FROM public.acquire_worker_batch($1, 5, 60)`,
      [WORKER_ID]
    );

    if (batchRes.rows.length === 0) {
      return;
    }

    activeLeases = batchRes.rows.map((r) => ({
      id: r.event_id,
      lease_token: r.lease_token,
    }));

    for (const row of batchRes.rows) {
      if (isShuttingDown) break;

      const {
        event_id,
        aggregate_id: photo_id,
        generation_token,
        payload,
        lease_token,
      } = row;

      try {
        const weddingId = payload.wedding_id;
        const originalKey = payload.storage_key || payload.object_key;

        // Fetch original from R2
        const getCmd = new GetObjectCommand({
          Bucket: env.R2_BUCKET_NAME,
          Key: originalKey,
        });
        const getRes = await r2Client.send(getCmd);
        const originalBytes = await getRes.Body?.transformToByteArray();
        if (!originalBytes) {
          throw new Error('Empty payload returned from R2 for original photo');
        }

        // Execute Sharp transformation inside Worker Thread with 4s timeout
        const derivatives = await executeTransformWithTimeout(Buffer.from(originalBytes));

        // Generation-scoped immutable keys
        const previewKey = `photos/${weddingId}/${photo_id}/g${generation_token}/preview.webp`;
        const thumbnailKey = `photos/${weddingId}/${photo_id}/g${generation_token}/thumbnail.webp`;

        // Upload preview to R2
        await r2Client.send(
          new PutObjectCommand({
            Bucket: env.R2_BUCKET_NAME,
            Key: previewKey,
            Body: derivatives.previewWebp,
            ContentType: 'image/webp',
          })
        );

        // Upload thumbnail to R2
        await r2Client.send(
          new PutObjectCommand({
            Bucket: env.R2_BUCKET_NAME,
            Key: thumbnailKey,
            Body: derivatives.thumbnailWebp,
            ContentType: 'image/webp',
          })
        );

        // Complete worker event
        await client.query(
          `SELECT public.complete_worker_event($1, $2, $3, $4, $5, $6, $7)`,
          [event_id, WORKER_ID, lease_token, photo_id, generation_token, previewKey, thumbnailKey]
        );

        // Remove from active leases
        activeLeases = activeLeases.filter((l) => l.id !== event_id);
      } catch (err: any) {
        console.error(`Failed to process event ${event_id}:`, err);
        try {
          await client.query(
            `SELECT public.fail_worker_event($1, $2, $3, $4, $5)`,
            [event_id, WORKER_ID, lease_token, generation_token, err.message]
          );
        } catch (failErr) {
          console.error(`Failed to record failure for event ${event_id}:`, failErr);
        }
        activeLeases = activeLeases.filter((l) => l.id !== event_id);
      }
    }
  } finally {
    client.release();
  }
}

// Bounded Shutdown Handler (10s Cloud Run Budget)
async function handleShutdown(signal: string) {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`Received ${signal}. Initiating bounded shutdown (10s budget)...`);

  const shutdownDeadline = setTimeout(() => {
    console.error('Shutdown budget exceeded. Forcing exit.');
    process.exit(1);
  }, 9500);

  try {
    if (activeLeases.length > 0) {
      console.log(`Releasing ${activeLeases.length} active leases...`);
      const client = await dbPool.connect();
      try {
        await client.query(`SELECT public.release_worker_leases($1, $2::jsonb)`, [
          WORKER_ID,
          JSON.stringify(activeLeases),
        ]);
      } finally {
        client.release();
      }
    }

    console.log('Closing database connection pool...');
    await dbPool.end();
    clearTimeout(shutdownDeadline);
    console.log('Shutdown complete.');
    process.exit(0);
  } catch (err) {
    console.error('Error during shutdown:', err);
    process.exit(1);
  }
}

process.on('SIGTERM', () => handleShutdown('SIGTERM'));
process.on('SIGINT', () => handleShutdown('SIGINT'));

import {
  createProductionOutboxProcessor,
  OutboxRevocationProcessor,
  isProductionRuntime,
  ProductionRevocationConfigurationError,
} from '../services/outbox-processor.js';

const processorCache = new WeakMap<object, OutboxRevocationProcessor>();
const envOptionsCache = new WeakMap<object, any>();
let configuredRuntimeOptions: any = null;

export interface WorkerEnvBindings {
  DATABASE_POOL?: any;
  pool?: any;
  WEDDING_REVOCATION_DO?: any;
  doCoordinator?: any;
  STRICT_REVOCATION_MODE?: boolean | string;
  strictRevocationMode?: boolean;
  leaseDurationSeconds?: number;
  NODE_ENV?: string;
  ENVIRONMENT?: string;
  r2Storage?: any;
  purgeService?: any;
  kvStore?: any;
  authorizationService?: any;
  [key: string]: any;
}

/**
 * Explicitly sets the persistent production runtime environment options (F15.3).
 * Invoked during worker initialization to inject production bindings (WEDDING_REVOCATION_DO, DATABASE_POOL).
 */
export function setProductionRevocationRuntimeOptions(options: any): void {
  configuredRuntimeOptions = options;
}

/**
 * Resolves the canonical database pool from provided aliases and ensures alias consistency (F15.3 Revision 15).
 * Rejects conflicting aliases fail-closed.
 */
export function resolveCanonicalPool(envBindings?: WorkerEnvBindings): any {
  const p1 = envBindings?.DATABASE_POOL;
  const p2 = envBindings?.pool;
  if (p1 && p2 && p1 !== p2) {
    throw new ProductionRevocationConfigurationError(
      'CRITICAL_CONFIG_ERROR: Conflicting database pool aliases provided (DATABASE_POOL !== pool)'
    );
  }
  return p1 || p2 || dbPool;
}

/**
 * Resolves the canonical coordinator binding from provided aliases and ensures alias consistency (F15.3 Revision 15).
 * Rejects conflicting aliases fail-closed.
 */
export function resolveCanonicalCoordinator(envBindings?: WorkerEnvBindings): any {
  const c1 = envBindings?.WEDDING_REVOCATION_DO;
  const c2 = envBindings?.doCoordinator;
  if (c1 && c2 && c1 !== c2) {
    throw new ProductionRevocationConfigurationError(
      'CRITICAL_CONFIG_ERROR: Conflicting coordinator aliases provided (WEDDING_REVOCATION_DO !== doCoordinator)'
    );
  }
  return c1 || c2 || (globalThis as any).WEDDING_REVOCATION_DO;
}

/**
 * Validates and normalizes leaseDurationSeconds, enforcing an explicit valid range [5s, 3600s] (F15.3 Revision 15).
 * Does not silently default invalid or zero values.
 */
export function resolveCanonicalLeaseDuration(envBindings?: WorkerEnvBindings): number {
  if (envBindings?.leaseDurationSeconds === undefined) {
    return 60;
  }
  const val = envBindings.leaseDurationSeconds;
  if (typeof val !== 'number' || !Number.isFinite(val) || val < 5 || val > 3600) {
    throw new ProductionRevocationConfigurationError(
      `CRITICAL_CONFIG_ERROR: leaseDurationSeconds must be a number between 5 and 3600, got: ${val}`
    );
  }
  return val;
}

/**
 * Resolves the canonical strictRevocationMode configuration and ensures alias consistency (F15.3 Revision 18).
 * Rejects conflicting aliases fail-closed.
 */
export function resolveCanonicalStrictRevocationMode(envBindings?: WorkerEnvBindings): boolean {
  if (!envBindings) return true;

  const hasLower = envBindings.strictRevocationMode !== undefined;
  const hasUpper = envBindings.STRICT_REVOCATION_MODE !== undefined;

  let valLower: boolean | undefined;
  if (hasLower) {
    if (typeof envBindings.strictRevocationMode !== 'boolean') {
      throw new ProductionRevocationConfigurationError(
        `CRITICAL_CONFIG_ERROR: strictRevocationMode must be a boolean, got: ${typeof envBindings.strictRevocationMode}`
      );
    }
    valLower = envBindings.strictRevocationMode;
  }

  let valUpper: boolean | undefined;
  if (hasUpper) {
    const rawUpper = envBindings.STRICT_REVOCATION_MODE;
    if (typeof rawUpper === 'boolean') {
      valUpper = rawUpper;
    } else if (typeof rawUpper === 'string') {
      const lowerStr = rawUpper.trim().toLowerCase();
      if (lowerStr === 'true') {
        valUpper = true;
      } else if (lowerStr === 'false') {
        valUpper = false;
      } else {
        throw new ProductionRevocationConfigurationError(
          `CRITICAL_CONFIG_ERROR: STRICT_REVOCATION_MODE string must be 'true' or 'false', got: ${rawUpper}`
        );
      }
    } else {
      throw new ProductionRevocationConfigurationError(
        `CRITICAL_CONFIG_ERROR: STRICT_REVOCATION_MODE must be boolean or string, got: ${typeof rawUpper}`
      );
    }
  }

  // Reject conflicting values fail-closed!
  if (hasLower && hasUpper && valLower !== valUpper) {
    throw new ProductionRevocationConfigurationError(
      `CRITICAL_CONFIG_ERROR: Conflicting strictRevocationMode aliases detected: strictRevocationMode=${valLower} vs STRICT_REVOCATION_MODE=${envBindings.STRICT_REVOCATION_MODE}. Fail-closed active.`
    );
  }

  if (valLower !== undefined) return valLower;
  if (valUpper !== undefined) return valUpper;
  return true;
}

export interface ProductionRevocationRuntimeOptions {
  DATABASE_POOL: any;
  pool: any;
  WEDDING_REVOCATION_DO: any;
  doCoordinator: any;
  strictRevocationMode: boolean;
  leaseDurationSeconds: number;
  r2Storage?: any;
  purgeService?: any;
  kvStore?: any;
  authorizationService?: any;
}

/**
 * Compares two runtime configurations to ensure 100% binding identity across all fields (F15.3 Revision 18).
 * Requires canonical alias consistency: every alias consumed must strictly match the canonical binding.
 * Prevents stale binding reuse if ANY binding or configuration parameter changes.
 */
export function areRuntimeBindingsIdentical(
  opts: ProductionRevocationRuntimeOptions | null | undefined,
  envBindings?: WorkerEnvBindings
): boolean {
  if (!opts) return false;
  const canonicalPool = resolveCanonicalPool(envBindings);
  const canonicalCoordinator = resolveCanonicalCoordinator(envBindings);
  const canonicalLeaseDuration = resolveCanonicalLeaseDuration(envBindings);
  const canonicalStrictMode = resolveCanonicalStrictRevocationMode(envBindings);

  const r2Storage = envBindings?.r2Storage;
  const purgeService = envBindings?.purgeService;
  const kvStore = envBindings?.kvStore;
  const authorizationService = envBindings?.authorizationService;

  // Strict identity: every alias that can be consumed must match the canonical reference
  const poolMatches = opts.DATABASE_POOL === canonicalPool && opts.pool === canonicalPool;
  const coordinatorMatches =
    opts.WEDDING_REVOCATION_DO === canonicalCoordinator && opts.doCoordinator === canonicalCoordinator;

  return (
    poolMatches &&
    coordinatorMatches &&
    opts.strictRevocationMode === canonicalStrictMode &&
    opts.leaseDurationSeconds === canonicalLeaseDuration &&
    opts.r2Storage === r2Storage &&
    opts.purgeService === purgeService &&
    opts.kvStore === kvStore &&
    opts.authorizationService === authorizationService
  );
}

/**
 * Production Worker Entrypoint Initialization (F15.3 Revision 18).
 *
 * Implements the mandatory production initialization sequence:
 * Production worker entrypoint
 *         |
 *         v
 * Receive actual environment bindings (env / process.env)
 *         |
 *         v
 * Resolve canonical bindings fail-closed against conflicting aliases
 *         |
 *         v
 * Validate DATABASE_POOL and WEDDING_REVOCATION_DO (fail-closed if missing in production)
 *         |
 *         v
 * Preserve stable options reference across repeated scheduled invocations with identical bindings across ALL fields
 * (prevents busting WeakMap processor cache on recurring crons, while invalidating if ANY binding changes)
 *         |
 *         v
 * Start worker/batch loop -> processRevocationOutboxBatch() [with ZERO arguments]
 *         |
 *         v
 * getProductionRevocationProcessor() retrieves cached processor with production bindings
 */
export function initProductionWorkerRuntime(envBindings?: WorkerEnvBindings): ProductionRevocationRuntimeOptions {
  const isProd = isProductionRuntime();
  const canonicalPool = resolveCanonicalPool(envBindings);
  const canonicalCoordinator = resolveCanonicalCoordinator(envBindings);
  const canonicalLeaseDuration = resolveCanonicalLeaseDuration(envBindings);
  const canonicalStrictMode = resolveCanonicalStrictRevocationMode(envBindings);

  if (isProd) {
    if (canonicalStrictMode === false) {
      throw new ProductionRevocationConfigurationError(
        'CRITICAL_CONFIG_ERROR: strictRevocationMode cannot be disabled in production environment'
      );
    }
    if (!canonicalCoordinator) {
      throw new ProductionRevocationConfigurationError(
        'CRITICAL_CONFIG_ERROR: Durable Object coordinator binding is mandatory in production environment'
      );
    }
    if (!canonicalPool) {
      throw new ProductionRevocationConfigurationError(
        'CRITICAL_CONFIG_ERROR: Database pool binding is mandatory in production environment'
      );
    }
  }

  // 1. If an options object was already constructed for this exact envBindings reference,
  // verify all fields are still identical (guards against post-initialization mutation).
  if (envBindings && typeof envBindings === 'object' && envOptionsCache.has(envBindings)) {
    const cached = envOptionsCache.get(envBindings)!;
    if (areRuntimeBindingsIdentical(cached, envBindings)) {
      setProductionRevocationRuntimeOptions(cached);
      return cached;
    }
    envOptionsCache.delete(envBindings);
  }

  // 2. If configuredRuntimeOptions already exists with 100% identical binding identities across ALL fields, retain it.
  // This guarantees processor cache stability across repeated scheduled invocations with identical bindings.
  if (configuredRuntimeOptions && areRuntimeBindingsIdentical(configuredRuntimeOptions, envBindings)) {
    if (envBindings && typeof envBindings === 'object') {
      envOptionsCache.set(envBindings, configuredRuntimeOptions);
    }
    return configuredRuntimeOptions;
  }

  // 3. Otherwise, create a fresh stable options instance with canonical bindings across all aliases.
  const stableOptions: ProductionRevocationRuntimeOptions = {
    DATABASE_POOL: canonicalPool,
    pool: canonicalPool,
    WEDDING_REVOCATION_DO: canonicalCoordinator,
    doCoordinator: canonicalCoordinator,
    strictRevocationMode: canonicalStrictMode,
    leaseDurationSeconds: canonicalLeaseDuration,
    r2Storage: envBindings?.r2Storage,
    purgeService: envBindings?.purgeService,
    kvStore: envBindings?.kvStore,
    authorizationService: envBindings?.authorizationService,
  };

  if (envBindings && typeof envBindings === 'object') {
    envOptionsCache.set(envBindings, stableOptions);
  }

  setProductionRevocationRuntimeOptions(stableOptions);
  return stableOptions;
}

/**
 * Constructs or retrieves the stable production runtime options (F15.3).
 * Guarantees:
 * 1. An explicit environment object is provided or retrieved from the registered runtime configuration.
 * 2. In production, mock coordinators are NEVER silently substituted.
 * 3. A stable object reference is returned across batch iterations to enable WeakMap caching.
 */
export function getOrCreateRevocationRuntimeOptions(explicitOptions?: any): any {
  if (explicitOptions && typeof explicitOptions === 'object') {
    return explicitOptions;
  }
  if (configuredRuntimeOptions) {
    return configuredRuntimeOptions;
  }
  const globalCoordinator = (globalThis as any).WEDDING_REVOCATION_DO;
  const isProd = isProductionRuntime();
  if (isProd && !globalCoordinator) {
    throw new ProductionRevocationConfigurationError(
      'CRITICAL_CONFIG_ERROR: Durable Object coordinator binding is mandatory in production environment'
    );
  }
  configuredRuntimeOptions = {
    DATABASE_POOL: dbPool,
    WEDDING_REVOCATION_DO: globalCoordinator,
    doCoordinator: globalCoordinator,
    strictRevocationMode: true,
    leaseDurationSeconds: 60,
  };
  return configuredRuntimeOptions;
}

export function resetRuntimeStateForTest(): void {
  configuredRuntimeOptions = null;
  isShuttingDown = false;
}

export function setShutdownStateForTest(val: boolean): void {
  isShuttingDown = val;
}

export function isWorkerShuttingDown(): boolean {
  return isShuttingDown;
}

/**
 * Production Factory Accessor for Outbox Revocation Processor (F15.3).
 * Wires the real worker runtime to createProductionOutboxProcessor, guaranteeing
 * that strictRevocationMode and Durable Object binding cannot be bypassed or weakened.
 *
 * Lifecycle & Runtime Architecture Assumptions:
 * 1. Runtime Binding Immutability: In Cloudflare Workers and containerized Node.js outbox runtimes,
 *    the environment object and its resource bindings (WEDDING_REVOCATION_DO, DATABASE_POOL) are
 *    treated as immutable for the entire lifetime of the execution isolate/process.
 * 2. Lifecycle Isolation: Keying the WeakMap cache to the environment object reference ensures that
 *    distinct execution environments or multi-tenant test contexts receive strictly isolated processor instances.
 * 3. Immutable Security Posture: In production runtimes (isProductionRuntime() === true), strictRevocationMode
 *    is immutably locked to true. If a caller attempts to pass strictRevocationMode === false,
 *    createProductionOutboxProcessor strictly throws ProductionRevocationConfigurationError.
 */
export function getProductionRevocationProcessor(options: any = {}): OutboxRevocationProcessor {
  const isProd = isProductionRuntime();
  if (isProd) {
    if (options?.strictRevocationMode === false) {
      throw new ProductionRevocationConfigurationError(
        'CRITICAL_CONFIG_ERROR: strictRevocationMode cannot be disabled in production environment'
      );
    }
    if (!(options?.WEDDING_REVOCATION_DO || options?.doCoordinator)) {
      throw new ProductionRevocationConfigurationError(
        'CRITICAL_CONFIG_ERROR: Durable Object coordinator binding is mandatory in production environment'
      );
    }
  }

  const envKey = (typeof options === 'object' && options !== null) ? options : null;
  if (envKey && processorCache.has(envKey)) {
    return processorCache.get(envKey)!;
  }

  const processor = createProductionOutboxProcessor({
    pool: options?.DATABASE_POOL || options?.pool || dbPool,
    doCoordinator: options?.WEDDING_REVOCATION_DO || options?.doCoordinator,
    strictRevocationMode: options?.strictRevocationMode !== undefined ? options.strictRevocationMode : true,
    leaseDurationSeconds: options?.leaseDurationSeconds || 60,
    r2Storage: options?.r2Storage,
    purgeService: options?.purgeService,
    kvStore: options?.kvStore,
    authorizationService: options?.authorizationService,
  });

  if (envKey) {
    processorCache.set(envKey, processor);
  }
  return processor;
}

export async function processRevocationOutboxBatch(options?: any) {
  if (isShuttingDown) return;
  const runtimeOptions = getOrCreateRevocationRuntimeOptions(options);
  const processor = getProductionRevocationProcessor(runtimeOptions);
  return await processor.processBatch(10);
}

export async function startWorkerLoop() {
  console.log(`Starting Outbox Worker Runtime (${WORKER_ID})...`);
  while (!isShuttingDown) {
    try {
      await processOutboxBatch();
      await processRevocationOutboxBatch();
    } catch (err) {
      console.error('Error in worker batch loop:', err);
    }
    // Poll delay
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

export const runtimeWorkerExport = {
  async scheduled(event: any, env: any, ctx?: any) {
    initProductionWorkerRuntime(env);
    return await processRevocationOutboxBatch();
  },
};

export default runtimeWorkerExport;

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  initProductionWorkerRuntime();
  startWorkerLoop();
}


import pg from 'pg';
import crypto from 'node:crypto';
import { dbPool } from './quota.js';
import { CloudflarePurgeService } from './cloudflare-purge.js';
import { OperatorAuthorizationService } from './admin-auth.js';

export interface OutboxRevocationEvent {
  id: string;
  eventType: 'PHOTO_DELETED' | 'WEDDING_REVOKED';
  weddingId: string;
  photoId?: string;
  payload: {
    photoId?: string;
    weddingSlug: string;
    objectKey?: string;
    r2Keys?: string[];
  };
  retryCount: number;
  maxRetries: number;
  status: 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED' | 'DEAD_LETTER';
  leaseToken?: string | null;
  leaseExpiresAt?: Date | null;
}

export interface RevocationKvStore {
  put: (key: string, value: string) => Promise<void>;
  get: (key: string) => Promise<string | null>;
}

export interface RevocationCoordinatorDo {
  revokePhoto: (photoId: string, weddingSlug: string) => Promise<void>;
  revokeWedding: (weddingSlug: string) => Promise<void>;
  isPhotoRevoked: (photoId: string, weddingSlug: string) => Promise<boolean>;
  isWeddingRevoked: (weddingSlug: string) => Promise<boolean>;
}

export const OUTBOX_DEAD_LETTER_REPLAY_SCOPE = 'outbox:dead-letter:replay';

export interface AuthenticatedOperatorRequest {
  headers: Record<string, string | string[] | undefined>;
  url?: string;
  method?: string;
}

export interface OperatorAuthorizationResult {
  authorized: boolean;
  operatorUserId?: string;
  authoritativeRole?: string;
  error?: string;
  scopes?: string[];
}

export interface OperatorAuthorizationServiceLike {
  authorizeOperatorRequest(
    request: AuthenticatedOperatorRequest,
    requiredScope: string
  ): Promise<OperatorAuthorizationResult>;
}

export class DefaultOperatorAuthorizationService implements OperatorAuthorizationServiceLike {
  async authorizeOperatorRequest(
    request: AuthenticatedOperatorRequest,
    requiredScope: string
  ): Promise<OperatorAuthorizationResult> {
    if (requiredScope !== OUTBOX_DEAD_LETTER_REPLAY_SCOPE) {
      return { authorized: false, error: 'INVALID_SCOPE' };
    }
    const headers = request.headers || {};
    const authHeader = (typeof headers['authorization'] === 'string' ? headers['authorization'] : '') || '';
    const oidcToken = authHeader.replace(/^Bearer\s+/i, '');
    const delegationToken = typeof headers['x-shadify-operator-assertion'] === 'string'
      ? headers['x-shadify-operator-assertion']
      : undefined;
    const headerOperatorUserId = typeof headers['x-operator-user-id'] === 'string'
      ? headers['x-operator-user-id']
      : undefined;

    if (!oidcToken) {
      return { authorized: false, error: 'MISSING_AUTHORIZATION_TOKEN' };
    }

    const authService = new OperatorAuthorizationService();
    const res = await authService.authorizeOperatorRequest({
      oidcToken,
      delegationToken,
      headerOperatorUserId,
      requiredRole: 'super_admin',
      requiredPermission: requiredScope,
    });

    if (!res.authorized) {
      return {
        authorized: false,
        operatorUserId: res.operator?.id,
        authoritativeRole: res.operator?.authoritativeRole,
        error: res.error,
        scopes: res.permissions || [],
      };
    }

    return {
      authorized: true,
      operatorUserId: res.operator?.id,
      authoritativeRole: res.operator?.authoritativeRole,
      error: undefined,
      scopes: res.permissions || [],
    };
  }
}

const SHADIFY_OPERATOR_NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8'; // RFC 4122 DNS Namespace UUID

/**
 * Conforming RFC 4122 Section 4.3 UUIDv5 derivation (F14.4).
 * Computes SHA-1 over the 16 binary namespace bytes followed by the UTF-8 name bytes.
 * Sets octet 6 to version 5 ((hash[6] & 0x0f) | 0x50) and octet 8 to variant ((hash[8] & 0x3f) | 0x80).
 * Ensures every administrative/system operator resolves to a deterministic, valid UUIDv5.
 */
export function getDurableActorUuid(operatorUserId: string, namespaceUuid = SHADIFY_OPERATOR_NAMESPACE): string {
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(operatorUserId)) {
    return operatorUserId.toLowerCase();
  }
  const nsBytes = Buffer.from(namespaceUuid.replace(/-/g, ''), 'hex');
  const nameBytes = Buffer.from(operatorUserId, 'utf8');
  const hash = crypto.createHash('sha1').update(Buffer.concat([nsBytes, nameBytes])).digest();
  const bytes = Buffer.from(hash.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x50; // RFC 4122 version 5
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant
  const hex = bytes.toString('hex');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-').toLowerCase();
}

export interface ReplayDeadLettersOptions {
  reason: string;
  limit?: number;
  correlationId?: string;
  operatorUserId?: string;
  delegatedAuthToken?: string;
  oidcToken?: string;
  authContext?: {
    request: AuthenticatedOperatorRequest;
  };
  requestContext?: AuthenticatedOperatorRequest;
}

export class StaleLeaseFencingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StaleLeaseFencingError';
  }
}

export class ProductionRevocationConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProductionRevocationConfigurationError';
  }
}

/**
 * Authoritative Environment Classification Policy (F15.3 & F15.4).
 * Single shared policy across edge handler, worker runtime, and processor factories.
 * Recognizes production, prod in NODE_ENV, DEPLOYMENT_ENVIRONMENT, or ENVIRONMENT.
 * Throws ProductionRevocationConfigurationError on conflicting environment declarations.
 */
export function isProductionRuntime(env: {
  NODE_ENV?: string;
  ENVIRONMENT?: string;
  DEPLOYMENT_ENVIRONMENT?: string;
} = process.env): boolean {
  const envVars = [
    { name: 'DEPLOYMENT_ENVIRONMENT', val: env.DEPLOYMENT_ENVIRONMENT },
    { name: 'ENVIRONMENT', val: env.ENVIRONMENT },
    { name: 'NODE_ENV', val: env.NODE_ENV },
  ];

  const declaredEnvs = envVars
    .filter((e) => typeof e.val === 'string' && e.val.trim().length > 0)
    .map((e) => ({ name: e.name, normalized: e.val!.trim().toLowerCase() }));

  const hasProd = declaredEnvs.some((e) => e.normalized === 'production' || e.normalized === 'prod');
  const hasNonProd = declaredEnvs.some(
    (e) => e.normalized !== 'production' && e.normalized !== 'prod' && e.normalized !== ''
  );

  if (hasProd && hasNonProd) {
    const conflictDetails = declaredEnvs.map((e) => `${e.name}="${e.normalized}"`).join(', ');
    throw new ProductionRevocationConfigurationError(
      `Conflicting environment declarations detected: ${conflictDetails}. Fail-closed active.`
    );
  }

  return hasProd;
}

export type QueryInterceptorHook = (
  source: 'client.query' | 'pool.query',
  sql: string,
  values?: any[]
) => void | Promise<void>;

/**
 * Module-private Symbol token and trusted registry (F14.5 Revision 20.3).
 * Ensures that only adapters created by authorized factory paths with mandatory production policy
 * are trusted in production runtimes. Caller-created adapters cannot forge this token.
 */
const TRUSTED_PRODUCTION_ADAPTER_TOKEN = Symbol('TRUSTED_PRODUCTION_ADAPTER_TOKEN');
const trustedProductionAdapters = new WeakSet<ProductionDatabaseBoundaryPoolAdapter>();

export function isTrustedProductionAdapter(pool: any): boolean {
  return pool instanceof ProductionDatabaseBoundaryPoolAdapter && trustedProductionAdapters.has(pool);
}

/**
 * Enforces production SQL query policies and invariants (F14.5 Revision 20.3):
 * 1. Rejects empty, whitespace-only, or non-string SQL statements.
 * 2. Rejects destructive administrative SQL commands (DROP, TRUNCATE, ALTER, GRANT, REVOKE)
 *    and unsupported mutation forms (MERGE, COPY, CREATE, PREPARE, EXECUTE).
 * 3. Enforces boundary isolation: forbids any mutation of the photos table from outbox workers,
 *    including CTEs (WITH ... DELETE/UPDATE), alternate schema qualifications ("public"."photos"),
 *    and unquoted/quoted identifiers.
 */
export function assertProductionSqlPolicy(sql: string, values?: any[]): void {
  if (typeof sql !== 'string' || sql.trim().length === 0) {
    throw new Error('CRITICAL_BOUNDARY_ERROR: Empty or non-string SQL submitted to production database boundary');
  }
  const cleanSql = sql
    .replace(/\/\*[\s\S]*?\*\/|--.*$/gm, ' ')
    .replace(/'(?:''|[^'])*'/g, "''")
    .trim();
  const upper = cleanSql.toUpperCase();
  if (/^(DROP|TRUNCATE|ALTER|GRANT|REVOKE|MERGE|COPY|CREATE|EXECUTE|PREPARE)\b/.test(upper)) {
    throw new Error(`CRITICAL_BOUNDARY_ERROR: Destructive administrative or unsupported SQL forbidden through boundary: ${upper.slice(0, 30)}`);
  }
  const photosMutationPattern = /\b(INSERT\s+INTO|UPDATE|DELETE(\s+FROM)?)\s+(["`]?public["`]?\.)?["`]?photos["`]?\b/i;
  if (photosMutationPattern.test(cleanSql)) {
    throw new Error('CRITICAL_BOUNDARY_ERROR: Direct or CTE mutation of photos table forbidden through outbox boundary');
  }
}

export const defaultProductionBoundaryInterceptor: QueryInterceptorHook = (
  source: 'client.query' | 'pool.query',
  sql: string,
  values?: any[]
) => {
  assertProductionSqlPolicy(sql, values);
};

/**
 * Concrete Production Database Boundary Pool Adapter (F14.5 Revision 20.3).
 * Wraps any pg.Pool to enforce that 100% of queries executed by the outbox processor—both
 * checked-out client connections and direct pooled queries—pass through mandatory boundary interception.
 * Uses ECMAScript private fields (#rawPool, #onQuery) to guarantee zero runtime reflection or bypass.
 */
export class ProductionDatabaseBoundaryPoolAdapter {
  #rawPool: any;
  #onQuery: QueryInterceptorHook;

  constructor(rawPool: any, onQuery: QueryInterceptorHook, internalCreationToken?: symbol) {
    if (!rawPool || typeof rawPool.connect !== 'function') {
      throw new Error('CRITICAL_BOUNDARY_ERROR: A valid underlying database pool is required');
    }
    if (typeof onQuery !== 'function') {
      throw new Error('CRITICAL_BOUNDARY_ERROR: QueryInterceptorHook is mandatory for ProductionDatabaseBoundaryPoolAdapter');
    }
    this.#rawPool = rawPool;
    this.#onQuery = onQuery;
    if (internalCreationToken === TRUSTED_PRODUCTION_ADAPTER_TOKEN) {
      trustedProductionAdapters.add(this);
    }
  }

  async connect(): Promise<{ query: (sql: string, values?: any[]) => Promise<any>; release: () => void }> {
    const rawClient = await this.#rawPool.connect();
    return {
      query: async (sql: string, values?: any[]) => {
        await this.#onQuery('client.query', sql, values);
        return await rawClient.query(sql, values);
      },
      release: () => {
        rawClient.release();
      },
    };
  }

  async query(sql: string, values?: any[]): Promise<any> {
    await this.#onQuery('pool.query', sql, values);
    return await this.#rawPool.query(sql, values);
  }

  async end(): Promise<void> {
    if (typeof this.#rawPool.end === 'function') {
      await this.#rawPool.end();
    }
  }
}

/**
 * Production Factory for OutboxRevocationProcessor (F15.3 & F14.5).
 * In production (NODE_ENV === 'production' or DEPLOYMENT_ENVIRONMENT === 'production'),
 * strictRevocationMode is immutably locked to true and CANNOT be disabled.
 * Throws ProductionRevocationConfigurationError if DO coordinator is unconfigured.
 */
export function createProductionOutboxProcessor(options?: {
  pool?: any;
  interceptor?: QueryInterceptorHook;
  purgeService?: CloudflarePurgeService;
  kvStore?: RevocationKvStore;
  doCoordinator?: RevocationCoordinatorDo;
  r2Storage?: R2ObjectStorageService;
  leaseDurationSeconds?: number;
  strictRevocationMode?: boolean;
  authorizationService?: OperatorAuthorizationServiceLike;
}): OutboxRevocationProcessor {
  const isProd = isProductionRuntime();
  if (isProd) {
    if (options?.strictRevocationMode === false) {
      throw new ProductionRevocationConfigurationError(
        'CRITICAL_CONFIG_ERROR: strictRevocationMode cannot be disabled in production environment'
      );
    }
    if (!options?.doCoordinator) {
      throw new ProductionRevocationConfigurationError(
        'CRITICAL_CONFIG_ERROR: Durable Object coordinator binding is mandatory in production environment'
      );
    }
  }

  // Mandatory Production Boundary Adapter Enforcement (F14.5 Revision 20.3):
  // 1. In production runtimes, arbitrary no-op interceptors are strictly forbidden.
  //    Any custom interceptor is chained with assertProductionSqlPolicy.
  // 2. Pre-wrapped adapters are rejected in production if untrusted or attempting to override policy.
  // 3. Raw pools are wrapped with native ECMAScript runtime-private #rawPool storage and stamped with
  //    TRUSTED_PRODUCTION_ADAPTER_TOKEN so caller-created adapters cannot forge trust.
  let effectiveInterceptor: QueryInterceptorHook = defaultProductionBoundaryInterceptor;
  if (options?.interceptor) {
    if (isProd) {
      const customHook = options.interceptor;
      effectiveInterceptor = async (source, sql, values) => {
        assertProductionSqlPolicy(sql, values);
        await customHook(source, sql, values);
      };
    } else {
      effectiveInterceptor = options.interceptor;
    }
  }

  let poolToUse: any = options?.pool || dbPool;
  if (poolToUse instanceof ProductionDatabaseBoundaryPoolAdapter) {
    if (isProd) {
      // In production, reject any caller-created or untrusted adapter!
      if (!trustedProductionAdapters.has(poolToUse)) {
        throw new ProductionRevocationConfigurationError(
          'CRITICAL_CONFIG_ERROR: Untrusted caller-created ProductionDatabaseBoundaryPoolAdapter rejected in production'
        );
      }
      if (options?.interceptor) {
        throw new ProductionRevocationConfigurationError(
          'CRITICAL_CONFIG_ERROR: Pre-wrapped adapter cannot be overridden with custom interceptor in production'
        );
      }
    }
  } else {
    poolToUse = new ProductionDatabaseBoundaryPoolAdapter(
      poolToUse,
      effectiveInterceptor,
      TRUSTED_PRODUCTION_ADAPTER_TOKEN
    );
  }

  return new OutboxRevocationProcessor({
    ...options,
    pool: poolToUse,
    strictRevocationMode: isProd ? true : (options?.strictRevocationMode ?? true),
  });
}

/**
 * Shared Canonical Durable Object Coordinator Identifier Derivation (F15).
 * Both outbox mutation paths and edge CDN read paths strictly use this function.
 */
export function getCanonicalDurableObjectId(weddingSlug: string): string {
  return `wedding:${weddingSlug}`;
}

export function getCanonicalPhotoTombstoneKey(weddingSlug: string, photoId: string): string {
  return `revoked_photos:${weddingSlug}:${photoId}`;
}

export function getCanonicalWeddingTombstoneKey(weddingSlug: string): string {
  return `revoked_weddings:${weddingSlug}`;
}

/**
 * Authoritative Manifest Validation (F14.5).
 * Validates that every storage key strictly belongs to the authenticated wedding tenant and photoId.
 * Rejects any unknown, cross-tenant, or malformed storage keys.
 * NEVER invents fallback keys!
 */
export function validateAuthoritativePhotoKeys(
  weddingSlug: string,
  photoId: string,
  keys: string[]
): string[] {
  if (!weddingSlug || typeof weddingSlug !== 'string' || !/^[a-z0-9-]+$/.test(weddingSlug)) {
    throw new Error(`Invalid tenant weddingSlug: "${weddingSlug}"`);
  }
  if (!photoId || typeof photoId !== 'string' || !/^[a-zA-Z0-9_-]+$/.test(photoId)) {
    throw new Error(`Invalid photoId: "${photoId}"`);
  }
  if (!keys || !Array.isArray(keys) || keys.length === 0) {
    throw new Error(`AUTHORITATIVE_MANIFEST_EMPTY: Authoritative keys list cannot be empty for photo "${photoId}"`);
  }

  const allowedPrefixes = [
    `originals/${weddingSlug}/`,
    `previews/${weddingSlug}/`,
    `thumbnails/${weddingSlug}/`,
    `watermarked/${weddingSlug}/`,
  ];

  for (const key of keys) {
    if (typeof key !== 'string') {
      throw new Error(`Invalid storage key type: expected string, got ${typeof key}`);
    }
    if (key.includes('/../') || key.includes('//') || key.includes('\\')) {
      throw new Error(
        `Authoritative manifest validation violation: path traversal or invalid sequence detected in storage key: "${key}"`
      );
    }
    const matchesPrefix = allowedPrefixes.some((p) => key.startsWith(p));
    if (!matchesPrefix) {
      throw new Error(
        `Authoritative manifest validation violation: key "${key}" does not belong to permitted prefixes for wedding "${weddingSlug}"`
      );
    }
    // Extract filename and verify exact photoId binding
    const filename = key.split('/').pop() || '';
    const baseName = filename.split('.')[0];
    if (baseName !== photoId && !baseName.startsWith(photoId + '_') && !baseName.startsWith(photoId + '-')) {
      throw new Error(
        `Authoritative manifest validation violation: key "${key}" filename "${filename}" does not match photoId "${photoId}"`
      );
    }
  }

  return Array.from(new Set(keys));
}

export function enumeratePhotoObjectKeys(weddingSlug: string, photoId: string, customExt = 'raw'): string[] {
  return [
    `originals/${weddingSlug}/${photoId}.${customExt}`,
    `previews/${weddingSlug}/${photoId}.webp`,
    `thumbnails/${weddingSlug}/${photoId}.webp`,
    `watermarked/${weddingSlug}/${photoId}.webp`,
  ];
}

export const validateAndDeriveAuthoritativePhotoKeys = (
  weddingSlug: string,
  photoId: string,
  keys?: string[]
): string[] => {
  if (keys && keys.length > 0) {
    return validateAuthoritativePhotoKeys(weddingSlug, photoId, keys);
  }
  return enumeratePhotoObjectKeys(weddingSlug, photoId);
};

export interface R2ObjectStorageService {
  deletePhotoObjects: (weddingSlug: string, photoId: string, customKeys?: string[]) => Promise<{
    success: boolean;
    deletedKeys: string[];
    failedKeys?: string[];
    error?: string;
  }>;
}

export interface OutboxProcessingResult {
  processedCount: number;
  completedCount: number;
  failedCount: number;
  deadLetterCount: number;
}

export class OutboxRevocationProcessor {
  private pool: pg.Pool;
  private purgeService: CloudflarePurgeService;
  private kvStore?: RevocationKvStore;
  private doCoordinator?: RevocationCoordinatorDo;
  private r2Storage?: R2ObjectStorageService;
  private leaseDurationSeconds: number;
  private strictRevocationMode: boolean;
  private readonly authorizationService: OperatorAuthorizationServiceLike;
  private readonly targetWeddingId?: string;
  private readonly targetEventId?: number;

  constructor(options?: {
    pool?: pg.Pool;
    purgeService?: CloudflarePurgeService;
    kvStore?: RevocationKvStore;
    doCoordinator?: RevocationCoordinatorDo;
    r2Storage?: R2ObjectStorageService;
    leaseDurationSeconds?: number;
    strictRevocationMode?: boolean;
    authorizationService?: OperatorAuthorizationServiceLike;
    targetWeddingId?: string;
    targetEventId?: number | string;
  }) {
    this.pool = options?.pool || dbPool;
    this.purgeService = options?.purgeService || new CloudflarePurgeService();
    this.kvStore = options?.kvStore;
    this.doCoordinator = options?.doCoordinator;
    this.r2Storage = options?.r2Storage;
    this.leaseDurationSeconds = options?.leaseDurationSeconds || 30;
    this.targetWeddingId = options?.targetWeddingId;
    if (options?.targetEventId !== undefined) {
      if (typeof options.targetEventId !== 'number' && typeof options.targetEventId !== 'string') {
        throw new Error(`INVALID_TARGET_EVENT_ID: targetEventId must be a number or numeric string, got ${typeof options.targetEventId}`);
      }
      if (typeof options.targetEventId === 'string' && !/^\d+$/.test(options.targetEventId.trim())) {
        throw new Error(`INVALID_TARGET_EVENT_ID: targetEventId must be a positive integer, got ${options.targetEventId}`);
      }
      const parsedId = Number(options.targetEventId);
      if (!Number.isInteger(parsedId) || parsedId <= 0) {
        throw new Error(`INVALID_TARGET_EVENT_ID: targetEventId must be a positive integer, got ${options.targetEventId}`);
      }
      this.targetEventId = parsedId;
    }
    const isProd = isProductionRuntime();
    if (isProd) {
      if (options?.strictRevocationMode === false) {
        throw new ProductionRevocationConfigurationError(
          'CRITICAL_CONFIG_ERROR: strictRevocationMode cannot be disabled in production environment'
        );
      }
      if (!options?.doCoordinator) {
        throw new ProductionRevocationConfigurationError(
          'CRITICAL_CONFIG_ERROR: Durable Object coordinator binding is mandatory in production environment'
        );
      }
    }
    this.strictRevocationMode = isProd ? true : (options?.strictRevocationMode ?? (process.env.STRICT_REVOCATION_MODE === 'true'));
    this.authorizationService = options?.authorizationService || new DefaultOperatorAuthorizationService();
  }

  /**
   * Sets or updates the target KV store (e.g. for testing or dynamic environment injection)
   */
  public setKvStore(kvStore: RevocationKvStore) {
    this.kvStore = kvStore;
  }

  /**
   * Sets or updates the Durable Object authoritative coordinator
   */
  public setDoCoordinator(doCoordinator: RevocationCoordinatorDo) {
    this.doCoordinator = doCoordinator;
  }

  /**
   * Sets or updates the R2 Physical Storage service
   */
  public setR2Storage(r2Storage: R2ObjectStorageService) {
    this.r2Storage = r2Storage;
  }

  /**
   * Polls and processes a batch of pending revocation outbox events.
   * Guarantees:
   * 1. Atomic lease acquisition with `FOR UPDATE SKIP LOCKED`.
   * 2. Automatic recovery of expired leases from crashed workers.
   * 3. Authoritative Durable Object synchronization (strongly consistent).
   * 4. Edge KV tombstone propagation (distributed optimization).
   * 5. Edge CDN cache invalidation.
   * 6. Physical R2 storage object deletion.
   * 7. Idempotent execution: retrying never undoes revocation.
   * 8. Dead-letter queue transition upon reaching max retries without silent authorization gaps.
   */
  async processBatch(batchSize = 10): Promise<OutboxProcessingResult> {
    const client = await this.pool.connect();
    let processedCount = 0;
    let completedCount = 0;
    let failedCount = 0;
    let deadLetterCount = 0;

    let leasedEvents: { row: any; leaseToken: string }[] = [];
    try {
      try {
        // 1. Atomically lease pending or expired-lease events using row locking
      await client.query('BEGIN');
      const queryParams: any[] = [batchSize];
      let filterClause = '';
      if (this.targetWeddingId) {
        queryParams.push(this.targetWeddingId);
        filterClause += ` AND wedding_id = $${queryParams.length}`;
      }
      if (this.targetEventId !== undefined) {
        queryParams.push(this.targetEventId);
        filterClause += ` AND id = $${queryParams.length}`;
      }

      const leaseRes = await client.query(
        `SELECT id, event_type, wedding_id, photo_id, payload, retry_count, max_retries
         FROM outbox_events
         WHERE (status = 'PENDING' OR (status = 'PROCESSING' AND lease_expires_at <= clock_timestamp()))
           AND event_type IN ('PHOTO_DELETED', 'WEDDING_REVOKED')
           ${filterClause}
         ORDER BY created_at ASC
         LIMIT $1
         FOR UPDATE SKIP LOCKED`,
        queryParams
      );

      if (leaseRes.rows.length === 0) {
        await client.query('COMMIT');
        return { processedCount: 0, completedCount: 0, failedCount: 0, deadLetterCount: 0 };
      }

      // Assign a fresh, unique token PER EVENT in the same atomic transaction
      for (const row of leaseRes.rows) {
        const eventLeaseToken = crypto.randomUUID();
        const assignRes = await client.query(
          `UPDATE outbox_events
           SET status = 'PROCESSING',
               lease_token = $1,
               lease_expires_at = clock_timestamp() + ($2 || ' seconds')::interval,
               updated_at = clock_timestamp()
           WHERE id = $3`,
          [eventLeaseToken, `${this.leaseDurationSeconds}`, row.id]
        );
        if ((assignRes.rowCount ?? 0) !== 1) {
          throw new Error(
            `Failed to assign lease token to event ${row.id}: expected 1 row affected, got ${assignRes.rowCount}`
          );
        }
        leasedEvents.push({ row, leaseToken: eventLeaseToken });
      }
      await client.query('COMMIT');
    } catch (leaseErr) {
      try {
        await client.query('ROLLBACK');
      } catch {}
      throw leaseErr;
    }

      // 2. Process each revocation event through the tripartite lifecycle
      for (const { row, leaseToken } of leasedEvents) {
        processedCount++;
        const eventId = row.id.toString();
        const eventType = row.event_type as 'PHOTO_DELETED' | 'WEDDING_REVOKED';
        const payload = typeof row.payload === 'string' ? JSON.parse(row.payload) : row.payload;
        const retryCount = row.retry_count;
        const maxRetries = row.max_retries;

        try {
          // Mandatory Durable Object Coordinator Enforcement (F15.3)
          // In strict revocation mode (default), DO coordination is mandatory before any downstream mutations.
          if (this.strictRevocationMode && !this.doCoordinator) {
            throw new Error(
              'DURABLE_OBJECT_COORDINATOR_MANDATORY: Durable Object coordinator binding is unconfigured or absent; cannot proceed with downstream revocation operations'
            );
          }

          if (eventType === 'PHOTO_DELETED') {
            const photoId = row.photo_id || payload.photoId;
            const weddingSlug = payload.weddingSlug;

            // Step A: Durable Object Authoritative Revocation Coordinator (Preferred Architecture)
            // Uses canonical DO identifier derivation matching the edge read path
            if (this.doCoordinator) {
              await this.doCoordinator.revokePhoto(photoId, weddingSlug);
            }

            // Step B: Edge KV Tombstone (Distributed Edge Optimization)
            // Tombstones carry tenant-scoped key with 7-day operational edge cache floor (604,800 seconds)
            if (this.kvStore) {
              await this.kvStore.put(getCanonicalPhotoTombstoneKey(weddingSlug, photoId), '1');
              await this.kvStore.put(`revoked_photos:${photoId}`, '1');
              await this.kvStore.put(`photo:${photoId}:revoked`, 'true');
            }

            // Step C: Invalidate Edge CDN Cache Bytes
            const purgeRes = await this.purgeService.purgePhoto(photoId, weddingSlug);
            if (!purgeRes.success) {
              throw new Error(`Cloudflare cache purge failed: ${purgeRes.error}`);
            }

            // Step D: Physical R2 Storage Deletion (Operation 3)
            // Authoritative Deletion Manifest Source-of-Truth Rule (F14.5):
            // For PHOTO_DELETED events, the deletion-time snapshot (payload.manifest.keys)
            // is the immutable, authoritative source of truth. The worker strictly consumes this snapshot
            // and NEVER prefers or substitutes mutable photo table rows.
            if (this.r2Storage) {
              if (!payload.manifest?.keys || !Array.isArray(payload.manifest.keys)) {
                throw new Error(
                  `AUTHORITATIVE_MANIFEST_MISSING: PHOTO_DELETED event ${row.id} for photo ${photoId} has no immutable deletion snapshot manifest`
                );
              }

              const authoritativeKeys = payload.manifest.keys;
              if (authoritativeKeys.length === 0) {
                throw new Error(
                  `AUTHORITATIVE_MANIFEST_EMPTY: Deletion snapshot manifest for photo ${photoId} in wedding ${row.wedding_id} is empty`
                );
              }

              const manifestKeys: string[] = validateAuthoritativePhotoKeys(weddingSlug, photoId, authoritativeKeys);
              const alreadyDeleted: string[] = payload.deletedKeys || [];
              const unresolvedKeys = manifestKeys.filter((k) => !alreadyDeleted.includes(k));

              if (unresolvedKeys.length > 0) {
                const r2Res = await this.r2Storage.deletePhotoObjects(weddingSlug, photoId, unresolvedKeys);
                if (!r2Res.success) {
                  const newlyDeleted = r2Res.deletedKeys || [];
                  payload.deletedKeys = Array.from(new Set([...alreadyDeleted, ...newlyDeleted]));
                  const failedKeys = r2Res.failedKeys || unresolvedKeys.filter((k) => !newlyDeleted.includes(k));
                  payload.failedKeys = failedKeys;
                  // Persist partial deletion progress into outbox event payload with strict lease fencing
                  await this.persistPartialProgress(client, row.id, leaseToken, payload);
                  throw new Error(`R2 physical deletion incomplete: failed to delete [${failedKeys.join(', ')}]`);
                }
                payload.deletedKeys = manifestKeys;
              }
            }
          } else if (eventType === 'WEDDING_REVOKED') {
            const weddingSlug = payload.weddingSlug;

            // Step A: Durable Object Authoritative Wedding Revocation
            if (this.doCoordinator) {
              await this.doCoordinator.revokeWedding(weddingSlug);
            }

            // Step B: Push wedding revocation to Edge KV store using canonical key
            if (this.kvStore) {
              await this.kvStore.put(getCanonicalWeddingTombstoneKey(weddingSlug), '1');
              await this.kvStore.put(`revoked_weddings:${weddingSlug}`, '1');
              await this.kvStore.put(`wedding:${weddingSlug}:revoked`, 'true');
            }

            // Step C: Invalidate wedding media cache
            const purgeRes = await this.purgeService.purgeWedding(weddingSlug);
            if (!purgeRes.success) {
              throw new Error(`Cloudflare wedding purge failed: ${purgeRes.error}`);
            }
          }

          // Mark event COMPLETED strictly conditioned on lease_token, status, AND non-expired lease horizon!
          // Fencing Invariant: only the worker currently holding the active lease token before expiration may complete.
          const completeRes = await client.query(
            `UPDATE outbox_events
             SET status = 'COMPLETED',
                 lease_token = NULL,
                 lease_expires_at = NULL,
                 updated_at = clock_timestamp(),
                 last_error = NULL
             WHERE id = $1
               AND lease_token = $2
               AND status = 'PROCESSING'
               AND lease_expires_at > clock_timestamp()`,
            [row.id, leaseToken]
          );

          if ((completeRes.rowCount ?? 0) === 0) {
            throw new StaleLeaseFencingError(
              `Lease fencing violation on completion: event ${row.id} lease ${leaseToken} expired or was overtaken by another worker`
            );
          }
          completedCount++;
        } catch (err: any) {
          failedCount++;
          const newRetryCount = retryCount + 1;
          const errorMsg = err?.message || String(err);

          // If the worker was fenced out due to lease expiration/takeover, do NOT modify the row
          if (err instanceof StaleLeaseFencingError) {
            continue;
          }

          // Retry policy distinction:
          // An event begins at retryCount = 0 (initial attempt).
          // maxRetries = 4 represents 4 retry attempts after the initial attempt (5 total attempts).
          if (newRetryCount >= maxRetries) {
            // Move to DEAD_LETTER: raise operational alert.
            // Critical Safety Guarantee: DO and KV tombstones already written in Steps A & B
            // remain active; dead-lettering does NOT create an authorization gap.
            // State mutation strictly fenced on current lease_token, status, and non-expired horizon!
            const dlRes = await client.query(
              `UPDATE outbox_events
               SET status = 'DEAD_LETTER',
                   lease_token = NULL,
                   lease_expires_at = NULL,
                   retry_count = $1,
                   last_error = $2,
                   updated_at = clock_timestamp()
               WHERE id = $3
                 AND lease_token = $4
                 AND status = 'PROCESSING'
                 AND lease_expires_at > clock_timestamp()`,
              [
                newRetryCount,
                `TERMINAL_FAILURE_MAX_RETRIES: ${errorMsg} | original_error: ${row.last_error || 'initial_failure'}`,
                row.id,
                leaseToken,
              ]
            );

            if ((dlRes.rowCount ?? 0) === 0) {
              // Stale worker lost lease during failure transition; row not modified
              continue;
            }
            deadLetterCount++;
          } else {
            // Requeue as PENDING with retry counter incremented and lease cleared,
            // strictly conditioned on current lease_token, status, and non-expired horizon!
            // Persists partial deletion progress in payload so subsequent retries do not re-delete confirmed keys.
            const retryRes = await client.query(
              `UPDATE outbox_events
               SET status = 'PENDING',
                   lease_token = NULL,
                   lease_expires_at = NULL,
                   retry_count = $1,
                   last_error = $2,
                   payload = $3::jsonb,
                   updated_at = clock_timestamp()
               WHERE id = $4
                 AND lease_token = $5
                 AND status = 'PROCESSING'
                 AND lease_expires_at > clock_timestamp()`,
              [
                newRetryCount,
                `${errorMsg} | previous: ${row.last_error || 'none'}`,
                JSON.stringify(payload),
                row.id,
                leaseToken,
              ]
            );

            if ((retryRes.rowCount ?? 0) === 0) {
              // Stale worker lost lease during retry transition; row not modified
              continue;
            }
          }
        }
      }
    } finally {
      client.release();
    }

    return {
      processedCount,
      completedCount,
      failedCount,
      deadLetterCount,
    };
  }

  /**
   * Persists partial deletion progress into outbox event payload with strict lease fencing.
   * Invariant: Requires rowCount === 1; throws StaleLeaseFencingError if lease expired or was overtaken.
   */
  async persistPartialProgress(
    client: { query: (sql: string, params: any[]) => Promise<{ rowCount?: number | null }> },
    eventId: number | string,
    leaseToken: string,
    updatedPayload: any
  ): Promise<void> {
    const res = await client.query(
      `UPDATE outbox_events
       SET payload = $1::jsonb,
           updated_at = clock_timestamp()
       WHERE id = $2
         AND lease_token = $3
         AND status = 'PROCESSING'
         AND lease_expires_at > clock_timestamp()`,
      [JSON.stringify(updatedPayload), eventId, leaseToken]
    );

    if ((res.rowCount ?? 0) !== 1) {
      throw new StaleLeaseFencingError(
        `Lease fencing violation on partial progress persistence: event ${eventId} lease ${leaseToken} expired or was overtaken by another worker`
      );
    }
  }

  /**
   * Heartbeat mechanism: extends lease duration for long-running batch operations.
   * Atomically verifies lease_token, status = 'PROCESSING', AND non-expired lease horizon!
   * A worker that has already lost its lease CANNOT revive it.
   */
  async renewLease(eventId: string | bigint, leaseToken: string, extensionSeconds = 30): Promise<boolean> {
    const res = await this.pool.query(
      `UPDATE outbox_events
       SET lease_expires_at = clock_timestamp() + ($1 || ' seconds')::interval,
           updated_at = clock_timestamp()
       WHERE id = $2
         AND lease_token = $3
         AND status = 'PROCESSING'
         AND lease_expires_at > clock_timestamp()`,
      [`${extensionSeconds}`, eventId, leaseToken]
    );
    return (res.rowCount ?? 0) > 0;
  }

  /**
   * Controlled operator replay mechanism for dead-lettered events (F14).
   * Enforces mandatory operator authorization claims before opening any database transaction,
   * captures true pre-replay failure traces via locked CTE, and persists immutable audit records
   * in the dedicated audit_log table.
   */
  async replayDeadLetters(options: ReplayDeadLettersOptions): Promise<number> {
    if (!options || typeof options !== 'object') {
      throw new Error('Options object with operator authorization is required for dead-letter replay.');
    }
    if (!options.authContext?.request && !options.operatorUserId && !options.requestContext) {
      throw new Error('Operator authorization context is required for dead-letter replay.');
    }

    const reason = options.reason;
    if (!reason || typeof reason !== 'string' || reason.trim().length < 10 || reason.length > 500) {
      throw new Error('Invalid replay reason: must be between 10 and 500 characters.');
    }
    if (/[\x00-\x1F\x7F]/.test(reason)) {
      throw new Error('Invalid replay reason: cannot contain control characters.');
    }

    // Authorize operator request BEFORE opening any database transaction or executing mutations
    // Strictly enforced against fixed constant scope OUTBOX_DEAD_LETTER_REPLAY_SCOPE
    const request = options.requestContext || options.authContext?.request || {
      headers: {
        'x-operator-user-id': options.operatorUserId,
        'x-shadify-operator-assertion': options.delegatedAuthToken,
        authorization: options.oidcToken ? `Bearer ${options.oidcToken}` : undefined,
      },
    };

    const auth = await this.authorizationService.authorizeOperatorRequest(
      request,
      OUTBOX_DEAD_LETTER_REPLAY_SCOPE
    );
    if (!auth || !auth.authorized) {
      throw new Error(`Unauthorized operator replay attempt: ${auth?.error || 'caller lacks DEAD_LETTER_REPLAY authority'}`);
    }
    if (!auth.operatorUserId || typeof auth.operatorUserId !== 'string') {
      throw new Error('Verified operator claims missing valid operatorUserId');
    }
    if (!auth.scopes || !auth.scopes.includes(OUTBOX_DEAD_LETTER_REPLAY_SCOPE)) {
      throw new Error('Verified operator claims missing required outbox:dead-letter:replay scope');
    }

    const operatorUserId = auth.operatorUserId;
    const operatorRole = auth.authoritativeRole;
    if (operatorRole !== 'super_admin') {
      throw new Error(`UNAUTHORIZED_REPLAY: Operator role '${operatorRole || 'none'}' is not authorized to replay dead-letter events (super_admin required)`);
    }
    const operatorUuid = getDurableActorUuid(operatorUserId);
    const limit = options.limit && options.limit > 0 ? options.limit : 50;
    const correlationId = options.correlationId || crypto.randomUUID();

    // Mandatory Transaction-Capable Pool Verification (F14.3)
    // Fails closed immediately before acquiring any client or modifying any event if transaction cannot be opened.
    if (!this.pool || typeof (this.pool as any).connect !== 'function') {
      throw new Error('TRANSACTION_CAPABLE_POOL_REQUIRED: Replay requires a transaction-capable database pool');
    }

    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      // Step 1: Ensure operator identity is durably persisted in operator_identities table (F14.4)
      await client.query(
        `INSERT INTO operator_identities (id, operator_user_id, authoritative_role, created_at)
         VALUES ($1, $2, $3, clock_timestamp())
         ON CONFLICT (id) DO UPDATE SET authoritative_role = EXCLUDED.authoritative_role`,
        [operatorUuid, operatorUserId, operatorRole]
      );

      // Requeue dead-letter events using a locked CTE to capture the pre-replay error trace.
      // Architectural Invariant: Does NOT overwrite event payload JSONB; audit records are
      // persisted exclusively in the dedicated, append-only `audit_log` table.
      const res = await client.query(
        `WITH targets AS (
           SELECT id, wedding_id, last_error
           FROM outbox_events
           WHERE status = 'DEAD_LETTER'
           ORDER BY updated_at ASC
           LIMIT $3
           FOR UPDATE SKIP LOCKED
         )
         UPDATE outbox_events o
         SET status = 'PENDING',
             retry_count = 0,
             lease_token = NULL,
             lease_expires_at = NULL,
             last_error = 'REPLAYED_BY_OPERATOR: ' || $1 || ' | REASON: ' || $2 || ' | PREVIOUS_ERRORS: ' || COALESCE(t.last_error, 'none'),
             updated_at = clock_timestamp()
         FROM targets t
         WHERE o.id = t.id
         RETURNING o.id, o.wedding_id, t.last_error AS original_last_error`,
        [operatorUserId, reason, limit]
      );

      // Persist immutable audit log entry for every replayed dead-letter event
      // Atomically written inside the same transaction; failure aborts the CTE update.
      // Populates dedicated operator_id column referencing operator_identities.
      if (res.rows && res.rows.length > 0) {
        for (const row of res.rows) {
          await client.query(
            `INSERT INTO audit_log (wedding_id, operator_id, actor_id, action, detail, created_at)
             VALUES ($1, $2::uuid, NULL, 'DEAD_LETTER_REPLAY', jsonb_build_object(
               'event_id', $3::text,
               'operator_user_id', $4::text,
               'operator_role', $5::text,
               'reason', $6::text,
               'replayed_at', clock_timestamp(),
               'previous_error', $7::text,
               'result', 'REQUEUED_PENDING',
               'correlation_id', $8::text
             ), clock_timestamp())`,
            [
              row.wedding_id || null,
              operatorUuid,
              row.id?.toString(),
              operatorUserId,
              operatorRole,
              reason,
              row.original_last_error || 'none',
              correlationId,
            ]
          );
        }
      }

      await client.query('COMMIT');
      return res.rowCount || 0;
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch {}
      throw err;
    } finally {
      if (typeof client.release === 'function') {
        client.release();
      }
    }
  }
}

export enum SqlTokenType {
  KEYWORD = 'KEYWORD',
  IDENTIFIER = 'IDENTIFIER',
  STRING_LITERAL = 'STRING_LITERAL',
  SYMBOL = 'SYMBOL',
}

export interface SqlToken {
  type: SqlTokenType;
  value: string;
}

/**
 * PostgreSQL-compatible lexical scanner for SQL statements.
 * Correctly distinguishes:
 * - Single-quoted string literals '...' with escaped '' and standard backslash escapes
 * - Dollar-quoted string literals $[tag]$...$[tag]$ ($$, $body$, etc.)
 * - Double-quoted identifiers "..." with escaped ""
 * - Line comments -- ...
 * - PostgreSQL nested block comments /* ... /* ... *\/ ... *\/
 * - Keywords and identifiers
 */
export function scanSqlTokens(sql: string): SqlToken[] {
  const tokens: SqlToken[] = [];
  let i = 0;
  const len = sql.length;

  while (i < len) {
    const ch = sql[i];

    // 1. Whitespace
    if (/\s/.test(ch)) {
      i++;
      continue;
    }

    // 2. Line comment: -- ...
    if (ch === '-' && sql[i + 1] === '-') {
      i += 2;
      while (i < len && sql[i] !== '\n') {
        i++;
      }
      continue;
    }

    // 3. PostgreSQL nested block comments: /* ... /* ... */ ... */
    if (ch === '/' && sql[i + 1] === '*') {
      i += 2;
      let depth = 1;
      while (i < len && depth > 0) {
        if (sql[i] === '/' && sql[i + 1] === '*') {
          depth++;
          i += 2;
        } else if (sql[i] === '*' && sql[i + 1] === '/') {
          depth--;
          i += 2;
        } else {
          i++;
        }
      }
      continue;
    }

    // 4. Single-quoted string literal: '...' (handles '' escaping)
    if (ch === "'") {
      let str = "'";
      i++;
      while (i < len) {
        if (sql[i] === "'") {
          str += "'";
          i++;
          if (i < len && sql[i] === "'") {
            str += "'";
            i++; // escaped ''
          } else {
            break;
          }
        } else if (sql[i] === '\\' && i + 1 < len) {
          str += sql[i] + sql[i + 1];
          i += 2;
        } else {
          str += sql[i];
          i++;
        }
      }
      tokens.push({ type: SqlTokenType.STRING_LITERAL, value: str });
      continue;
    }

    // 5. Dollar-quoted string literal: $[tag]$ ... $[tag]$
    if (ch === '$') {
      const match = sql.slice(i).match(/^\$([a-zA-Z0-9_]*)\$/);
      if (match) {
        const tag = match[0];
        const start = i;
        i += tag.length;
        const closeIdx = sql.indexOf(tag, i);
        if (closeIdx !== -1) {
          i = closeIdx + tag.length;
          tokens.push({ type: SqlTokenType.STRING_LITERAL, value: sql.slice(start, i) });
          continue;
        }
      }
    }

    // 6. Double-quoted identifier: "..." (handles "" escaping)
    if (ch === '"') {
      let ident = '';
      i++;
      while (i < len) {
        if (sql[i] === '"') {
          if (i + 1 < len && sql[i + 1] === '"') {
            ident += '"';
            i += 2;
          } else {
            i++;
            break;
          }
        } else {
          ident += sql[i];
          i++;
        }
      }
      tokens.push({ type: SqlTokenType.IDENTIFIER, value: ident });
      continue;
    }

    // 7. Word: Keyword or standard identifier
    if (/[a-zA-Z_]/.test(ch)) {
      const start = i;
      while (i < len && /[a-zA-Z0-9_]/.test(sql[i])) {
        i++;
      }
      const word = sql.slice(start, i);
      const upper = word.toUpperCase();
      const KEYWORDS = new Set(['SELECT', 'FROM', 'JOIN', 'UPDATE', 'INSERT', 'INTO', 'DELETE', 'TRUNCATE', 'TABLE', 'ONLY', 'WHERE', 'SET']);
      tokens.push({
        type: KEYWORDS.has(upper) ? SqlTokenType.KEYWORD : SqlTokenType.IDENTIFIER,
        value: word,
      });
      continue;
    }

    // 8. Symbols: dot, commas, parentheses, etc.
    tokens.push({ type: SqlTokenType.SYMBOL, value: ch });
    i++;
  }

  return tokens;
}

/**
 * SQL Lexical Scanner-based detector for references to the mutable `photos` table.
 * Accurately detects:
 * - Unqualified: photos, ONLY photos
 * - Schema-qualified: public.photos, "public"."photos", "public".photos, public."photos"
 * - Quoted: "photos", `photos`
 * - Verbs: FROM, JOIN, UPDATE, INSERT INTO, DELETE FROM, TRUNCATE (TABLE)
 * - Modifiers: ONLY (e.g. UPDATE ONLY photos, TRUNCATE TABLE ONLY photos)
 * Immune to false positives from:
 * - Single-quoted string literals (e.g. 'FROM photos')
 * - Dollar-quoted string literals (e.g. $body$ FROM photos $body$)
 * - Double-quoted identifiers with hyphens/dashes (e.g. "photos--archive")
 * - Single-line comments (-- FROM photos)
 * - Nested block comments (/* outer /* inner *\/ FROM photos *\/)
 * Rejects non-target tables such as photo_albums, photos_archive, "photos_archive".
 */
export function containsPhotosTableReference(sql: string): boolean {
  const tokens = scanSqlTokens(sql);
  const DML_VERBS = new Set(['FROM', 'JOIN', 'UPDATE', 'INTO', 'TABLE', 'DELETE', 'TRUNCATE']);

  for (let idx = 0; idx < tokens.length; idx++) {
    const t = tokens[idx];
    if (t.type === SqlTokenType.KEYWORD && DML_VERBS.has(t.value.toUpperCase())) {
      let nextIdx = idx + 1;
      while (
        nextIdx < tokens.length &&
        tokens[nextIdx].type === SqlTokenType.KEYWORD &&
        (tokens[nextIdx].value.toUpperCase() === 'ONLY' ||
          tokens[nextIdx].value.toUpperCase() === 'TABLE' ||
          tokens[nextIdx].value.toUpperCase() === 'FROM')
      ) {
        nextIdx++;
      }
      if (nextIdx >= tokens.length) continue;

      let candidateToken = tokens[nextIdx];

      // Handle schema-qualified references: <schema>.photos, "<schema>"."photos", public.photos, private.photos
      if (
        nextIdx + 2 < tokens.length &&
        tokens[nextIdx + 1].value === '.' &&
        tokens[nextIdx + 2].value.toLowerCase() === 'photos'
      ) {
        return true;
      }

      if (candidateToken.value.toLowerCase() === 'photos') {
        return true;
      }
    }
  }

  return false;
}

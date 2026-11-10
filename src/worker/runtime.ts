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

export async function startWorkerLoop() {
  console.log(`Starting Outbox Worker Runtime (${WORKER_ID})...`);
  while (!isShuttingDown) {
    try {
      await processOutboxBatch();
    } catch (err) {
      console.error('Error in worker batch loop:', err);
    }
    // Poll delay
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  startWorkerLoop();
}


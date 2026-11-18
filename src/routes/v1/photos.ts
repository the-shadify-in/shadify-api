import { FastifyPluginAsync } from 'fastify';
import { GuestAuthorizationService, PhotoRecord } from '../../services/guest-auth.js';
import { CdnService } from '../../services/cdn.js';
import { dbPool } from '../../services/quota.js';
import { CloudflarePurgeService } from '../../services/cloudflare-purge.js';
import { validateAuthoritativePhotoKeys, getDurableActorUuid } from '../../services/outbox-processor.js';

// In-memory registry for photo records (populated via DB or tests)
export const PHOTO_DIRECTORY: Map<string, PhotoRecord> = new Map([
  [
    'photo-public-001',
    {
      id: 'photo-public-001',
      weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
      weddingSlug: 'priya-rohan-2026',
      status: 'approved',
      visibility: 'visibility_public',
      keyOriginal: 'originals/priya-rohan-2026/photo-public-001.jpg',
      keyPreview: 'previews/priya-rohan-2026/photo-public-001.webp',
      keyThumb: 'thumbnails/priya-rohan-2026/photo-public-001.webp',
    },
  ],
  [
    'photo-family-001',
    {
      id: 'photo-family-001',
      weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
      weddingSlug: 'priya-rohan-2026',
      status: 'approved',
      visibility: 'visibility_family',
      keyThumb: 'photos/3fa85f64-5717-4562-b3fc-2c963f66afa6/photo-family-001/thumb.jpg',
      keyPreview: 'photos/3fa85f64-5717-4562-b3fc-2c963f66afa6/photo-family-001/preview.jpg',
    },
  ],
  [
    'photo-other-wedding-001',
    {
      id: 'photo-other-wedding-001',
      weddingId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      weddingSlug: 'ananya-kabir-2026',
      status: 'approved',
      visibility: 'visibility_family',
      keyThumb: 'photos/other/thumb.jpg',
      keyPreview: 'photos/other/preview.jpg',
    },
  ],
  [
    'photo-unapproved-001',
    {
      id: 'photo-unapproved-001',
      weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
      weddingSlug: 'priya-rohan-2026',
      status: 'processing',
      visibility: 'visibility_public',
      keyThumb: 'photos/unapproved/thumb.jpg',
      keyPreview: 'photos/unapproved/preview.jpg',
    },
  ],
]);

function extractGuestToken(request: any): string | undefined {
  const header = request.headers['x-shadify-guest-token'];
  if (typeof header === 'string' && header.length > 0) {
    return header;
  }
  const authHeader = request.headers.authorization;
  if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  return undefined;
}

export const photoRoutes: FastifyPluginAsync = async (fastify) => {
  // 1. Photo Metadata Endpoint
  fastify.get('/v1/weddings/:slug/photos/:id', async (request, reply) => {
    const { slug, id } = request.params as { slug: string; id: string };
    const photo = PHOTO_DIRECTORY.get(id);

    if (!photo || photo.weddingSlug !== slug || photo.status !== 'approved') {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'Photo not found or inaccessible in this wedding',
      });
    }

    const token = extractGuestToken(request);
    if (!(await GuestAuthorizationService.canViewPhotoDurable(photo, token))) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        code: 'PIN_REQUIRED',
        message: 'PIN verification required to access private wedding photos',
      });
    }

    return reply.status(200).send({
      id: photo.id,
      weddingId: photo.weddingId,
      weddingSlug: photo.weddingSlug,
      visibility: photo.visibility,
      status: photo.status,
      previewUrl: `/v1/weddings/${slug}/photos/${id}/preview`,
      downloadUrl: `/v1/weddings/${slug}/photos/${id}/download`,
    });
  });

  // 2. Photo Preview Signed CDN Endpoint (1h TTL, Cache-Control: private, no-transform, max-age=3600)
  fastify.get('/v1/weddings/:slug/photos/:id/preview', async (request, reply) => {
    const { slug, id } = request.params as { slug: string; id: string };
    const photo = PHOTO_DIRECTORY.get(id);

    if (!photo || photo.weddingSlug !== slug || photo.status !== 'approved') {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'Photo not found or inaccessible in this wedding',
      });
    }

    const token = extractGuestToken(request);
    if (!(await GuestAuthorizationService.canViewPhotoDurable(photo, token))) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        code: 'PIN_REQUIRED',
        message: 'PIN verification required to access private wedding photos',
      });
    }

    // Set Cache-Control header as required by F14 & F15
    reply.header('Cache-Control', 'private, no-transform, max-age=3600');

    const signedCdn = CdnService.generateSignedCdnUrl({
      objectKey: photo.keyPreview,
      expiresInSeconds: 3600, // 1 hour TTL
    });

    return reply.status(200).send({
      photoId: photo.id,
      previewUrl: signedCdn.url,
      expiresAt: signedCdn.expiresAt,
      expiresInSeconds: 3600,
    });
  });

  // 3. Photo Download Signed CDN Endpoint (15m TTL, Cache-Control: private, no-transform, max-age=900)
  fastify.get('/v1/weddings/:slug/photos/:id/download', async (request, reply) => {
    const { slug, id } = request.params as { slug: string; id: string };
    const photo = PHOTO_DIRECTORY.get(id);

    if (!photo || photo.weddingSlug !== slug || photo.status !== 'approved') {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'Photo not found or inaccessible in this wedding',
      });
    }

    const token = extractGuestToken(request);
    if (!(await GuestAuthorizationService.canViewPhotoDurable(photo, token))) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        code: 'PIN_REQUIRED',
        message: 'PIN verification required to access private wedding photos',
      });
    }

    // Set Cache-Control header as required by F14 & F15
    reply.header('Cache-Control', 'private, no-transform, max-age=900');

    const filename = `${photo.id}-original.jpg`;
    const signedCdn = CdnService.generateSignedCdnUrl({
      objectKey: photo.keyPreview.replace('preview.jpg', 'original.jpg'),
      expiresInSeconds: 900, // 15 minutes TTL
      contentDisposition: `attachment; filename="${filename}"`,
    });

    return reply.status(200).send({
      photoId: photo.id,
      downloadUrl: signedCdn.url,
      filename,
      expiresAt: signedCdn.expiresAt,
      expiresInSeconds: 900,
    });
  });

  // 4. Photo Deletion & Edge Invalidation Endpoint (F14.5 & F15.5 Outbox Durability)
  fastify.delete('/v1/weddings/:slug/photos/:id', async (request, reply) => {
    const { slug, id } = request.params as { slug: string; id: string };
    const photoUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)
      ? id
      : getDurableActorUuid(id);

    // Mandatory transactional pool check: fail closed if database is unavailable
    const pool = (request.server as any)?.dbPool || (fastify as any)?.dbPool || dbPool;
    if (!pool || typeof pool.connect !== 'function') {
      return reply.status(503).send({
        statusCode: 503,
        error: 'Service Unavailable',
        message: 'DATABASE_POOL_UNAVAILABLE: Durable transaction required for photo deletion',
      });
    }

    const client = await pool.connect();
    let outboxEventId: string;
    try {
      await client.query('BEGIN');

      // 1. Authoritative Database Read & Row Lock: query wedding and photo together to enforce tenant boundary
      const photoRes = await client.query(
        `SELECT p.id, p.wedding_id, p.key_original, p.key_preview, p.key_thumb, w.slug AS wedding_slug
         FROM photos p
         JOIN weddings w ON p.wedding_id = w.id
         WHERE p.id = $1 AND w.slug = $2
         FOR UPDATE OF p`,
        [photoUuid, slug]
      );

      if (photoRes.rows.length === 0) {
        await client.query('ROLLBACK');
        return reply.status(404).send({
          statusCode: 404,
          error: 'Not Found',
          message: 'Photo not found in this wedding',
        });
      }

      const photoRow = photoRes.rows[0];
      const authoritativeKeys = [photoRow.key_original, photoRow.key_preview, photoRow.key_thumb].filter(
        (k): k is string => typeof k === 'string' && k.length > 0
      );

      // Strict Validation: fail closed if no authoritative keys are resolved from the database
      if (authoritativeKeys.length === 0) {
        await client.query('ROLLBACK');
        return reply.status(400).send({
          statusCode: 400,
          error: 'Bad Request',
          code: 'AUTHORITATIVE_MANIFEST_EMPTY',
          message: `Photo ${id} has no valid storage keys in database; cannot delete without authoritative manifest`,
        });
      }

      // Validate keys against tenant prefix and photoId binding
      const validatedKeys = validateAuthoritativePhotoKeys(slug, id, authoritativeKeys);

      // 2. Mandatory Transactional Outbox Event Creation (must succeed before deletion commits)
      const outboxRes = await client.query(
        `INSERT INTO outbox_events (event_type, wedding_id, photo_id, payload, status)
         VALUES ($1, $2, $3, $4, 'PENDING')
         RETURNING id`,
        [
          'PHOTO_DELETED',
          photoRow.wedding_id,
          photoRow.id,
          JSON.stringify({
            photoId: photoRow.id,
            weddingSlug: slug,
            manifest: {
              keys: validatedKeys,
              snapshottedAt: new Date().toISOString(),
            },
            deletedKeys: [],
            failedKeys: [],
          }),
        ]
      );

      if (!outboxRes.rows || outboxRes.rows.length === 0 || !outboxRes.rows[0].id) {
        throw new Error('OUTBOX_INSERT_FAILED: Database did not return created outbox event id');
      }
      outboxEventId = outboxRes.rows[0].id.toString();

      // 3. Delete from photos table inside the same transaction
      const delRes = await client.query(`DELETE FROM photos WHERE id = $1 AND wedding_id = $2`, [
        photoRow.id,
        photoRow.wedding_id,
      ]);
      if ((delRes.rowCount ?? 0) === 0) {
        throw new Error('PHOTO_DELETE_FAILED: Zero rows deleted from photos table');
      }

      // 4. Commit transaction: photo deletion and outbox event are atomically committed together
      await client.query('COMMIT');
    } catch (err: any) {
      try {
        await client.query('ROLLBACK');
      } catch {}
      return reply.status(500).send({
        statusCode: 500,
        error: 'Internal Server Error',
        code: 'PHOTO_DELETION_FAILED',
        message: err.message || 'Failed to process photo deletion transaction',
      });
    } finally {
      client.release();
    }

    // 5. Remove from in-memory directory if present
    PHOTO_DIRECTORY.delete(id);

    // 6. Trigger immediate best-effort edge cache invalidation
    let edgePurged = false;
    let purgedCount = 0;
    try {
      const purgeService = new CloudflarePurgeService();
      const purgeResult = await purgeService.purgePhoto(id, slug);
      edgePurged = purgeResult.success;
      purgedCount = purgeResult.purgedCount || 0;
    } catch {
      fastify.log.warn('Cloudflare purge unavailable; relying on durable outbox processor');
    }

    return reply.status(200).send({
      success: true,
      photoId: id,
      outboxEventId,
      edgePurged,
      purgedCount,
      queuedForOutboxSync: true,
    });
  });
};


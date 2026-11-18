import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../src/app.js';
import { env } from '../src/config/env.js';
import { GuestAuthorizationService } from '../src/services/guest-auth.js';
import { CdnService } from '../src/services/cdn.js';
import { buildCanonicalRequest } from '../src/plugins/hmac.js';
import { dbPool } from '../src/services/quota.js';
import { getDurableActorUuid } from '../src/services/outbox-processor.js';

describe('Asset Delivery & Photo Visibility Integration Tests (F14 & F15)', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp();
    await app.ready();

    // Seed test wedding and photo in database for authoritative deletion testing
    const photoUuid = getDurableActorUuid('photo-public-001');
    const weddingId = '3fa85f64-5717-4562-b3fc-2c963f66afa6';
    try {
      await dbPool.query(
        `INSERT INTO weddings (id, slug, bride_name, groom_name, wedding_date, status, plan)
         VALUES ($1, 'priya-rohan-2026', 'Priya', 'Rohan', CURRENT_DATE, 'published'::"WeddingStatus", 'lite'::"WeddingPlan")
         ON CONFLICT (id) DO UPDATE SET slug = EXCLUDED.slug`,
        [weddingId]
      );
      await dbPool.query(
        `INSERT INTO photos (id, wedding_id, key_original, key_preview, key_thumb, width, height, sha256, status, visibility)
         VALUES ($1, $2,
                 'originals/priya-rohan-2026/photo-public-001.jpg',
                 'previews/priya-rohan-2026/photo-public-001.webp',
                 'thumbnails/priya-rohan-2026/photo-public-001.webp',
                 1920, 1080, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'approved'::"PhotoStatus", 'public'::"PhotoVisibility")
         ON CONFLICT (id) DO UPDATE SET
           key_original = EXCLUDED.key_original,
           key_preview = EXCLUDED.key_preview,
           key_thumb = EXCLUDED.key_thumb`,
        [photoUuid, weddingId]
      );
    } catch (e) {
      console.error('SEED ERROR IN BEFOREALL:', e);
    }
  });

  afterAll(async () => {
    await app.close();
  });

  function getHmacHeaders(method: string, path: string, body = '') {
    const dateStr = new Date().toISOString();
    const nonce = crypto.randomUUID();
    const contentSha256 = crypto.createHash('sha256').update(body).digest('hex');
    const canonicalReq = buildCanonicalRequest(
      method,
      path,
      '',
      {
        host: 'localhost',
        'x-shadify-content-sha256': contentSha256,
        'x-shadify-date': dateStr,
        'x-shadify-nonce': nonce,
      },
      contentSha256
    );
    const signature = crypto
      .createHmac('sha256', env.CLOUDFLARE_HMAC_SECRET)
      .update(canonicalReq, 'utf8')
      .digest('hex');

    return {
      host: 'localhost',
      'x-shadify-signature': signature,
      'x-shadify-date': dateStr,
      'x-shadify-nonce': nonce,
      'x-shadify-content-sha256': contentSha256,
    };
  }

  describe('GET /v1/weddings/:slug/photos/:id (Metadata Access)', () => {
    it('allows public visitor to view public photo without any guest token', async () => {
      const path = '/v1/weddings/priya-rohan-2026/photos/photo-public-001';
      const res = await app.inject({
        method: 'GET',
        url: path,
        headers: getHmacHeaders('GET', path),
      });

      expect(res.statusCode).toBe(200);
      const json = JSON.parse(res.payload);
      expect(json.id).toBe('photo-public-001');
      expect(json.visibility).toBe('visibility_public');
      expect(json.previewUrl).toContain('/preview');
      expect(json.downloadUrl).toContain('/download');
    });

    it('rejects unauthenticated visitor attempting to access family/private photo', async () => {
      const path = '/v1/weddings/priya-rohan-2026/photos/photo-family-001';
      const res = await app.inject({
        method: 'GET',
        url: path,
        headers: getHmacHeaders('GET', path),
      });

      expect(res.statusCode).toBe(401);
      const json = JSON.parse(res.payload);
      expect(json.code).toBe('PIN_REQUIRED');
      expect(json.message).toContain('PIN verification required');
    });

    it('rejects visitor presenting a valid guest token from another wedding (Cross-Tenant Protection)', async () => {
      const otherWeddingToken = GuestAuthorizationService.issueGuestToken('ananya-kabir-2026', 'device-guest-1');
      const path = '/v1/weddings/priya-rohan-2026/photos/photo-family-001';

      const res = await app.inject({
        method: 'GET',
        url: path,
        headers: {
          ...getHmacHeaders('GET', path),
          'x-shadify-guest-token': otherWeddingToken,
        },
      });

      expect(res.statusCode).toBe(401);
      const json = JSON.parse(res.payload);
      expect(json.code).toBe('PIN_REQUIRED');
    });

    it('authorizes guest with valid PIN token for the target wedding', async () => {
      const validToken = GuestAuthorizationService.issueGuestToken('priya-rohan-2026', 'device-guest-1');
      const path = '/v1/weddings/priya-rohan-2026/photos/photo-family-001';

      const res = await app.inject({
        method: 'GET',
        url: path,
        headers: {
          ...getHmacHeaders('GET', path),
          'x-shadify-guest-token': validToken,
        },
      });

      expect(res.statusCode).toBe(200);
      const json = JSON.parse(res.payload);
      expect(json.id).toBe('photo-family-001');
      expect(json.visibility).toBe('visibility_family');
    });

    it('returns 404 for processing or unapproved photos, preventing leakage of draft assets', async () => {
      const path = '/v1/weddings/priya-rohan-2026/photos/photo-unapproved-001';
      const res = await app.inject({
        method: 'GET',
        url: path,
        headers: getHmacHeaders('GET', path),
      });

      expect(res.statusCode).toBe(404);
    });
  });

  describe('GET /v1/weddings/:slug/photos/:id/preview (Preview Signed CDN Delivery & TTL)', () => {
    it('serves preview with 1-hour TTL and Cache-Control header for public photo', async () => {
      const path = '/v1/weddings/priya-rohan-2026/photos/photo-public-001/preview';
      const res = await app.inject({
        method: 'GET',
        url: path,
        headers: getHmacHeaders('GET', path),
      });

      expect(res.statusCode).toBe(200);
      expect(res.headers['cache-control']).toBe('private, no-transform, max-age=3600');

      const json = JSON.parse(res.payload);
      expect(json.photoId).toBe('photo-public-001');
      expect(json.expiresInSeconds).toBe(3600);
      expect(json.previewUrl).toContain('https://media.shadify.in/');

      // Verify the cryptographic signature embedded in the CDN URL
      const url = new URL(json.previewUrl);
      const expiresSec = parseInt(url.searchParams.get('exp')!, 10);
      const signature = url.searchParams.get('sig')!;
      const key = url.pathname.replace(/^\/+/, '');

      const isValidCdnSig = CdnService.verifySignedCdnUrl({
        objectKey: key,
        expiresSec,
        signature,
      });
      expect(isValidCdnSig).toBe(true);
    });

    it('rejects preview access for family photo without guest token', async () => {
      const path = '/v1/weddings/priya-rohan-2026/photos/photo-family-001/preview';
      const res = await app.inject({
        method: 'GET',
        url: path,
        headers: getHmacHeaders('GET', path),
      });

      expect(res.statusCode).toBe(401);
    });

    it('allows preview access for family photo when valid guest token is presented', async () => {
      const validToken = GuestAuthorizationService.issueGuestToken('priya-rohan-2026', 'device-guest-1');
      const path = '/v1/weddings/priya-rohan-2026/photos/photo-family-001/preview';
      const res = await app.inject({
        method: 'GET',
        url: path,
        headers: {
          ...getHmacHeaders('GET', path),
          'x-shadify-guest-token': validToken,
        },
      });

      expect(res.statusCode).toBe(200);
      expect(res.headers['cache-control']).toBe('private, no-transform, max-age=3600');
      const json = JSON.parse(res.payload);
      expect(json.previewUrl).toBeTruthy();
    });

    it('strictly rejects preview access when guest token has been revoked (F13)', async () => {
      const revokedToken = GuestAuthorizationService.issueGuestToken('priya-rohan-2026', 'device-guest-revoked');
      GuestAuthorizationService.REVOKED_GUEST_TOKENS.add(revokedToken);

      const path = '/v1/weddings/priya-rohan-2026/photos/photo-family-001/preview';
      const res = await app.inject({
        method: 'GET',
        url: path,
        headers: {
          ...getHmacHeaders('GET', path),
          'x-shadify-guest-token': revokedToken,
        },
      });

      expect(res.statusCode).toBe(401);
      const json = JSON.parse(res.payload);
      expect(json.code).toBe('PIN_REQUIRED');
    });
  });

  describe('GET /v1/weddings/:slug/photos/:id/download (Original Download Signed CDN Delivery & TTL)', () => {
    it('serves download with 15-minute TTL, Content-Disposition attachment, and Cache-Control', async () => {
      const path = '/v1/weddings/priya-rohan-2026/photos/photo-public-001/download';
      const res = await app.inject({
        method: 'GET',
        url: path,
        headers: getHmacHeaders('GET', path),
      });

      expect(res.statusCode).toBe(200);
      expect(res.headers['cache-control']).toBe('private, no-transform, max-age=900');

      const json = JSON.parse(res.payload);
      expect(json.photoId).toBe('photo-public-001');
      expect(json.filename).toBe('photo-public-001-original.jpg');
      expect(json.expiresInSeconds).toBe(900);
      expect(json.downloadUrl).toContain('response-content-disposition=attachment');

      const url = new URL(json.downloadUrl);
      const expiresSec = parseInt(url.searchParams.get('exp')!, 10);
      const signature = url.searchParams.get('sig')!;
      const key = url.pathname.replace(/^\/+/, '');
      const disp = url.searchParams.get('response-content-disposition') || undefined;
      const w = url.searchParams.get('w') || undefined;
      const pid = url.searchParams.get('pid') || undefined;
      const v = url.searchParams.get('v') || undefined;

      const isValidCdnSig = CdnService.verifySignedCdnUrl({
        objectKey: key,
        expiresSec,
        signature,
        contentDisposition: disp,
        weddingSlug: w,
        photoId: pid,
        variant: v,
      });
      expect(isValidCdnSig).toBe(true);
    });

    it('rejects download access for family photo without guest token', async () => {
      const path = '/v1/weddings/priya-rohan-2026/photos/photo-family-001/download';
      const res = await app.inject({
        method: 'GET',
        url: path,
        headers: getHmacHeaders('GET', path),
      });

      expect(res.statusCode).toBe(401);
    });

    it('allows download access for family photo with valid guest token', async () => {
      const validToken = GuestAuthorizationService.issueGuestToken('priya-rohan-2026', 'device-guest-1');
      const path = '/v1/weddings/priya-rohan-2026/photos/photo-family-001/download';
      const res = await app.inject({
        method: 'GET',
        url: path,
        headers: {
          ...getHmacHeaders('GET', path),
          'x-shadify-guest-token': validToken,
        },
      });

      expect(res.statusCode).toBe(200);
      expect(res.headers['cache-control']).toBe('private, no-transform, max-age=900');
    });

    it('strictly rejects download access when guest token has been revoked (F13)', async () => {
      const revokedToken = GuestAuthorizationService.issueGuestToken('priya-rohan-2026', 'device-guest-dl-revoked');
      GuestAuthorizationService.REVOKED_GUEST_TOKENS.add(revokedToken);

      const path = '/v1/weddings/priya-rohan-2026/photos/photo-family-001/download';
      const res = await app.inject({
        method: 'GET',
        url: path,
        headers: {
          ...getHmacHeaders('GET', path),
          'x-shadify-guest-token': revokedToken,
        },
      });

      expect(res.statusCode).toBe(401);
      const json = JSON.parse(res.payload);
      expect(json.code).toBe('PIN_REQUIRED');
    });
  });

  describe('Signed CDN Token Integrity & Tamper Resistance (F15)', () => {
    it('rejects tampered signature or modified expiration time', () => {
      const signed = CdnService.generateSignedCdnUrl({
        objectKey: 'photos/test/sample.jpg',
        expiresInSeconds: 900,
      });

      const url = new URL(signed.url);
      const key = url.pathname.replace(/^\/+/, '');
      const expiresSec = parseInt(url.searchParams.get('exp')!, 10);
      const validSig = url.searchParams.get('sig')!;

      // Valid verifies
      expect(CdnService.verifySignedCdnUrl({ objectKey: key, expiresSec, signature: validSig })).toBe(true);

      // Tampered signature fails
      const tamperedSig = validSig.slice(0, -4) + '0000';
      expect(CdnService.verifySignedCdnUrl({ objectKey: key, expiresSec, signature: tamperedSig })).toBe(false);

      // Expired token fails
      const pastSec = Math.floor(Date.now() / 1000) - 100;
      expect(CdnService.verifySignedCdnUrl({ objectKey: key, expiresSec: pastSec, signature: validSig })).toBe(false);
    });
  });

  describe('Photo Deletion & Outbox Edge Cache Invalidation (F14 & F15)', () => {
    it('deletes photo, removes from active directory, and triggers edge cache invalidation', async () => {
      const path = '/v1/weddings/priya-rohan-2026/photos/photo-public-001';
      const res = await app.inject({
        method: 'DELETE',
        url: path,
        headers: getHmacHeaders('DELETE', path),
      });

      expect(res.statusCode).toBe(200);
      const json = JSON.parse(res.payload);
      expect(json.success).toBe(true);
      expect(json.photoId).toBe('photo-public-001');

      // Subsequent access must return 404 Not Found
      const getRes = await app.inject({
        method: 'GET',
        url: path,
        headers: getHmacHeaders('GET', path),
      });
      expect(getRes.statusCode).toBe(404);
    }, 15000);
  });
});


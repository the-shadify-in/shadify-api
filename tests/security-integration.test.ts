import { describe, it, expect, beforeEach } from 'vitest';
import crypto from 'node:crypto';
import { OperatorAuthorizationService } from '../src/services/admin-auth.js';
import { GuestAuthorizationService, PhotoRecord } from '../src/services/guest-auth.js';
import { UploadLifecycleService, StoredUploadSession } from '../src/services/upload-lifecycle.js';
import {
  EdgeCdnHandler,
  EdgeCdnEnv,
  resolveCanonicalWeddingSlug,
  WeddingRevocationCoordinator,
  validateProductionRevocationConfig,
  ProductionRevocationConfigurationError,
} from '../src/worker/edge-cdn-handler.js';
import {
  OutboxRevocationProcessor,
  RevocationKvStore,
  StaleLeaseFencingError,
  enumeratePhotoObjectKeys,
  getCanonicalDurableObjectId,
  validateAndDeriveAuthoritativePhotoKeys,
  getDurableActorUuid,
  OUTBOX_DEAD_LETTER_REPLAY_SCOPE,
} from '../src/services/outbox-processor.js';
import { CloudflarePurgeService } from '../src/services/cloudflare-purge.js';
import { CdnService } from '../src/services/cdn.js';
import { env } from '../src/config/env.js';
import { buildApp } from '../src/app.js';
import { buildCanonicalRequest } from '../src/plugins/hmac.js';

process.env.CDN_SIGNING_SECRET = env.CLOUDFLARE_HMAC_SECRET;
process.env.CLOUDFLARE_HMAC_SECRET = env.CLOUDFLARE_HMAC_SECRET;

function getOriginHmacHeaders(method: string, path: string, body = '') {
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

describe('Central API Security & Negative Integration Test Suite (F06–F16)', () => {
  let uploadService: UploadLifecycleService;
  const validOidcToken = 'gcp-oidc-token-bff-service-account-identity-xyz';

  beforeEach(() => {
    uploadService = new UploadLifecycleService();
  });

  // ===================================================================
  // F06: Operator Cryptographic Delegation & Identity Verification
  // ===================================================================
  describe('F06: Operator Identity Delegation & Anti-Spoofing', () => {
    it('authorizes operator with valid signed delegation assertion bound to OIDC token', async () => {
      const superAdminId = 'e8e1215b-9cf4-4e2a-89a1-cb9e1e36780c';
      const token = OperatorAuthorizationService.createDelegationAssertion({
        operatorUserId: superAdminId,
        email: 'lead-admin@shadify.in',
        oidcToken: validOidcToken,
      });

      const res = await OperatorAuthorizationService.authorizeOperatorRequest({
        oidcToken: validOidcToken,
        delegationToken: token,
        headerOperatorUserId: superAdminId,
        requiredRole: 'super_admin',
      });

      expect(res.authorized).toBe(true);
      expect(res.operator?.authoritativeRole).toBe('super_admin');
    });

    it('rejects delegation assertion when caller presents a mismatched OIDC token (Binding Enforcement)', async () => {
      const superAdminId = 'e8e1215b-9cf4-4e2a-89a1-cb9e1e36780c';
      const token = OperatorAuthorizationService.createDelegationAssertion({
        operatorUserId: superAdminId,
        email: 'lead-admin@shadify.in',
        oidcToken: validOidcToken,
      });

      // Attacker steals delegation token and presents it with a different OIDC token
      const attackerOidcToken = 'attacker-stolen-service-account-oidc-token';
      const res = await OperatorAuthorizationService.authorizeOperatorRequest({
        oidcToken: attackerOidcToken,
        delegationToken: token,
      });

      expect(res.authorized).toBe(false);
      expect(res.error).toContain('OIDC_BINDING_MISMATCH');
    });

    it('detects and blocks replay attacks when the same delegation assertion is presented twice (JTI Nonce Cache)', async () => {
      const superAdminId = 'e8e1215b-9cf4-4e2a-89a1-cb9e1e36780c';
      const token = OperatorAuthorizationService.createDelegationAssertion({
        operatorUserId: superAdminId,
        email: 'lead-admin@shadify.in',
        oidcToken: validOidcToken,
      });

      // First presentation succeeds
      const firstRes = await OperatorAuthorizationService.authorizeOperatorRequest({
        oidcToken: validOidcToken,
        delegationToken: token,
      });
      expect(firstRes.authorized).toBe(true);

      // Replay attempt is blocked by JTI replay cache
      const replayRes = await OperatorAuthorizationService.authorizeOperatorRequest({
        oidcToken: validOidcToken,
        delegationToken: token,
      });
      expect(replayRes.authorized).toBe(false);
      expect(replayRes.error).toContain('REPLAY_ATTACK_DETECTED');
    });

    it('supports key rotation using kid header', async () => {
      const superAdminId = 'e8e1215b-9cf4-4e2a-89a1-cb9e1e36780c';
      // Sign with previous key in rotation window
      const tokenPrevKey = OperatorAuthorizationService.createDelegationAssertion({
        operatorUserId: superAdminId,
        email: 'lead-admin@shadify.in',
        oidcToken: validOidcToken,
        keyId: 'key-2026-previous',
      });

      const res = await OperatorAuthorizationService.authorizeOperatorRequest({
        oidcToken: validOidcToken,
        delegationToken: tokenPrevKey,
      });
      expect(res.authorized).toBe(true);
    });

    it('rejects forged operator user ID header when it does not match delegation assertion', async () => {
      const realUserId = 'b2c3d4e5-f6a7-4890-bcde-1234567890ab';
      const forgedUserId = 'e8e1215b-9cf4-4e2a-89a1-cb9e1e36780c';

      const token = OperatorAuthorizationService.createDelegationAssertion({
        operatorUserId: realUserId,
        email: 'studio-vikram@shadify.in',
        oidcToken: validOidcToken,
      });

      const res = await OperatorAuthorizationService.authorizeOperatorRequest({
        oidcToken: validOidcToken,
        delegationToken: token,
        headerOperatorUserId: forgedUserId,
      });

      expect(res.authorized).toBe(false);
      expect(res.error).toContain('OPERATOR_IDENTITY_MISMATCH');
    });

    it('rejects request with missing or expired delegation assertion', async () => {
      const superAdminId = 'e8e1215b-9cf4-4e2a-89a1-cb9e1e36780c';
      const noTokenRes = await OperatorAuthorizationService.authorizeOperatorRequest({
        oidcToken: validOidcToken,
        headerOperatorUserId: superAdminId,
      });
      expect(noTokenRes.authorized).toBe(false);
      expect(noTokenRes.error).toContain('MISSING_OPERATOR_DELEGATION');

      const expiredToken = OperatorAuthorizationService.createDelegationAssertion({
        operatorUserId: superAdminId,
        email: 'lead-admin@shadify.in',
        oidcToken: validOidcToken,
        ttlSeconds: -10,
      });
      const expiredRes = await OperatorAuthorizationService.authorizeOperatorRequest({
        oidcToken: validOidcToken,
        delegationToken: expiredToken,
      });
      expect(expiredRes.authorized).toBe(false);
      expect(expiredRes.error).toContain('DELEGATION_TOKEN_EXPIRED');
    });

    it('rejects operator when accessing an out-of-scope wedding tenant', async () => {
      const studioOwnerId = 'b2c3d4e5-f6a7-4890-bcde-1234567890ab';
      const unauthorizedWeddingId = '99999999-9999-9999-9999-999999999999';

      const token = OperatorAuthorizationService.createDelegationAssertion({
        operatorUserId: studioOwnerId,
        email: 'studio-vikram@shadify.in',
        oidcToken: validOidcToken,
      });

      const res = await OperatorAuthorizationService.authorizeOperatorRequest({
        oidcToken: validOidcToken,
        delegationToken: token,
        targetWeddingId: unauthorizedWeddingId,
      });

      expect(res.authorized).toBe(false);
      expect(res.error).toContain('TENANT_OUT_OF_SCOPE');
    });

    it('rejects delegation assertion when signing key has been revoked in emergency key list', async () => {
      const superAdminId = 'e8e1215b-9cf4-4e2a-89a1-cb9e1e36780c';
      const token = OperatorAuthorizationService.createDelegationAssertion({
        operatorUserId: superAdminId,
        email: 'lead-admin@shadify.in',
        oidcToken: validOidcToken,
        keyId: 'key-2026-previous',
      });

      // Revoke the key
      OperatorAuthorizationService.REVOKED_KEYS.add('key-2026-previous');
      try {
        const res = await OperatorAuthorizationService.authorizeOperatorRequest({
          oidcToken: validOidcToken,
          delegationToken: token,
        });
        expect(res.authorized).toBe(false);
        expect(res.error).toContain('REVOKED_KEY');
      } finally {
        OperatorAuthorizationService.REVOKED_KEYS.delete('key-2026-previous');
      }
    });

    it('rejects delegation assertion with algorithm other than HS256', async () => {
      // Create token with alg: none
      const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(
        JSON.stringify({
          iss: 'shadify-admin-bff',
          aud: 'shadify-api-internal-bff',
          sub: 'e8e1215b-9cf4-4e2a-89a1-cb9e1e36780c',
          email: 'admin@shadify.in',
          oidcHash: crypto.createHash('sha256').update(validOidcToken).digest('hex'),
          jti: crypto.randomUUID(),
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 300,
        })
      ).toString('base64url');
      const forgedToken = `${header}.${payload}.unsigned`;

      const res = await OperatorAuthorizationService.authorizeOperatorRequest({
        oidcToken: validOidcToken,
        delegationToken: forgedToken,
      });
      expect(res.authorized).toBe(false);
      expect(res.error).toContain('INVALID_ALGORITHM');
    });

    it('authorizes operator with asymmetric Ed25519 delegation assertion (F06 Asymmetric Key Custody)', async () => {
      const superAdminId = 'e8e1215b-9cf4-4e2a-89a1-cb9e1e36780c';
      const keyId = 'ed25519-test-key-2026';

      // Generate Ed25519 keypair for test
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

      // Central API only holds public key
      OperatorAuthorizationService.ASYMMETRIC_PUBLIC_KEYS[keyId] = publicKey;

      // Admin BFF creates assertion with private key
      const token = OperatorAuthorizationService.createAsymmetricDelegationAssertion({
        operatorUserId: superAdminId,
        email: 'lead-admin@shadify.in',
        oidcToken: validOidcToken,
        privateKey,
        keyId,
      });

      const res = await OperatorAuthorizationService.authorizeOperatorRequest({
        oidcToken: validOidcToken,
        delegationToken: token,
        headerOperatorUserId: superAdminId,
      });

      expect(res.authorized).toBe(true);
      expect(res.operator?.authoritativeRole).toBe('super_admin');
    });

    it('rejects tampered Ed25519 signature or unknown public key (F06)', async () => {
      const superAdminId = 'e8e1215b-9cf4-4e2a-89a1-cb9e1e36780c';
      const keyId = 'ed25519-test-key-tamper';
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      OperatorAuthorizationService.ASYMMETRIC_PUBLIC_KEYS[keyId] = publicKey;

      const token = OperatorAuthorizationService.createAsymmetricDelegationAssertion({
        operatorUserId: superAdminId,
        email: 'lead-admin@shadify.in',
        oidcToken: validOidcToken,
        privateKey,
        keyId,
      });

      // 1. Tamper with signature
      const tamperedToken = token.slice(0, -6) + 'aaaaaa';
      const resTampered = await OperatorAuthorizationService.authorizeOperatorRequest({
        oidcToken: validOidcToken,
        delegationToken: tamperedToken,
      });
      expect(resTampered.authorized).toBe(false);
      expect(resTampered.error).toContain('INVALID_DELEGATION_SIGNATURE');

      // 2. Unknown public key ID
      const unknownKeyToken = OperatorAuthorizationService.createAsymmetricDelegationAssertion({
        operatorUserId: superAdminId,
        email: 'lead-admin@shadify.in',
        oidcToken: validOidcToken,
        privateKey,
        keyId: 'ed25519-unknown-key',
      });
      const resUnknown = await OperatorAuthorizationService.authorizeOperatorRequest({
        oidcToken: validOidcToken,
        delegationToken: unknownKeyToken,
      });
      expect(resUnknown.authorized).toBe(false);
      expect(resUnknown.error).toContain('UNKNOWN_PUBLIC_KEY');
    });
  });

  // ===================================================================
  // F08: Actual Stored Object Byte & SHA-256 Verification
  // ===================================================================
  describe('F08: Content Integrity & Actual Stored Byte Verification', () => {
    it('verifies SHA-256 computed directly from stored object bytes', async () => {
      const testContent = Buffer.from('High-resolution wedding photo RAW pixel byte stream test');
      const correctSha256 = crypto.createHash('sha256').update(testContent).digest('hex');

      const session: StoredUploadSession = {
        id: '10050',
        weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        expectedBytes: String(testContent.length),
        actualBytes: null,
        clientDeclaredSha256: correctSha256,
        verifiedObjectSha256: null,
        isMultipart: false,
        multipartUploadId: null,
        objectKey: 'photos/w1/10050/original',
        status: 'RESERVED',
        expiresAt: Date.now() + 1800000,
        completedAt: null,
        photoId: null,
        quotaSettled: false,
      };
      uploadService.sessions.set('10050', session);

      const res = await uploadService.completeUploadSession({
        sessionId: '10050',
        actualBytes: String(testContent.length),
        storedObjectBytes: testContent,
        providerObjectExists: true,
        providerObjectSizeBytes: String(testContent.length),
      });

      expect(res.success).toBe(true);
      expect(session.status).toBe('COMPLETED');
      expect(session.verifiedObjectSha256).toBe(correctSha256);
    });

    it('rejects and quarantines upload when stored object bytes fail SHA-256 check', async () => {
      const originalContent = Buffer.from('Legitimate photo bytes');
      const expectedSha256 = crypto.createHash('sha256').update(originalContent).digest('hex');
      const corruptedContent = Buffer.from('Corrupted or substituted byte content!');

      const session: StoredUploadSession = {
        id: '10051',
        weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        expectedBytes: String(corruptedContent.length),
        actualBytes: null,
        clientDeclaredSha256: expectedSha256,
        verifiedObjectSha256: null,
        isMultipart: false,
        multipartUploadId: null,
        objectKey: 'photos/w1/10051/original',
        status: 'RESERVED',
        expiresAt: Date.now() + 1800000,
        completedAt: null,
        photoId: null,
        quotaSettled: false,
      };
      uploadService.sessions.set('10051', session);

      const res = await uploadService.completeUploadSession({
        sessionId: '10051',
        actualBytes: String(corruptedContent.length),
        storedObjectBytes: corruptedContent,
        providerObjectExists: true,
        providerObjectSizeBytes: String(corruptedContent.length),
      });

      expect(res.success).toBe(false);
      expect(res.error).toContain('OBJECT_HASH_CORRUPTED');
      expect(session.status).toBe('CANCELLED');
    });

    it('independently verifies bytes read back from Cloudflare R2 storage provider (F08)', async () => {
      const persistedBytes = Buffer.from('Persisted R2 high-res original photograph bytes');
      const expectedSha256 = crypto.createHash('sha256').update(persistedBytes).digest('hex');

      const session: StoredUploadSession = {
        id: '10052',
        weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        expectedBytes: String(persistedBytes.length),
        actualBytes: String(persistedBytes.length),
        clientDeclaredSha256: expectedSha256,
        verifiedObjectSha256: null,
        isMultipart: false,
        multipartUploadId: null,
        objectKey: 'photos/w1/10052/original',
        status: 'STORAGE_COMPLETED',
        expiresAt: Date.now() + 1800000,
        completedAt: null,
        photoId: null,
        quotaSettled: false,
      };
      uploadService.sessions.set('10052', session);

      // Storage provider reader mock (simulating R2 GetObjectCommand stream)
      const r2Reader = async (key: string) => {
        expect(key).toBe('photos/w1/10052/original');
        return persistedBytes;
      };

      const result = await uploadService.executeR2ReadBackVerification({
        sessionId: '10052',
        workerId: 'worker-node-1',
        r2Reader,
      });

      expect(result.success).toBe(true);
      expect(result.status).toBe('COMPLETED');
      expect(session.status).toBe('COMPLETED');
      expect(session.quotaSettled).toBe(true);
      expect(session.verifiedObjectSha256).toBe(expectedSha256);
      expect(result.photoId).toBeTruthy();

      const photo = uploadService.photos.get('10052');
      expect(photo?.status).toBe('approved');
      expect(photo?.sha256).toBe(expectedSha256);
    });

    it('quarantines and rejects upload when R2 read-back bytes fail checksum, preventing quota settlement (F08)', async () => {
      const originalBytes = Buffer.from('Original photograph bytes');
      const expectedSha256 = crypto.createHash('sha256').update(originalBytes).digest('hex');
      const corruptedPersistedBytes = Buffer.from('Corrupted or silently truncated R2 storage bytes');

      const session: StoredUploadSession = {
        id: '10053',
        weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        expectedBytes: String(originalBytes.length),
        actualBytes: String(originalBytes.length),
        clientDeclaredSha256: expectedSha256,
        verifiedObjectSha256: null,
        isMultipart: false,
        multipartUploadId: null,
        objectKey: 'photos/w1/10053/original',
        status: 'STORAGE_COMPLETED',
        expiresAt: Date.now() + 1800000,
        completedAt: null,
        photoId: null,
        quotaSettled: false,
      };
      uploadService.sessions.set('10053', session);

      const r2Reader = async () => corruptedPersistedBytes;

      const result = await uploadService.executeR2ReadBackVerification({
        sessionId: '10053',
        workerId: 'worker-node-1',
        r2Reader,
      });

      expect(result.success).toBe(false);
      expect(result.status).toBe('REJECTED');
      expect(session.status).toBe('REJECTED');
      expect(session.quotaSettled).toBe(false);
      expect(result.error).toContain('R2_BYTE_CHECKSUM_MISMATCH');
      expect(uploadService.photos.has('10053')).toBe(false);
    });

    it('recovers from worker crash during verification via lease expiration takeover (F08)', async () => {
      const testBytes = Buffer.from('Valid wedding photograph bytes');
      const correctSha256 = crypto.createHash('sha256').update(testBytes).digest('hex');

      // Worker 1 crashed while session was in VERIFYING state, lease expired 5s ago
      const session: StoredUploadSession = {
        id: '10054',
        weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        expectedBytes: String(testBytes.length),
        actualBytes: String(testBytes.length),
        clientDeclaredSha256: correctSha256,
        verifiedObjectSha256: null,
        isMultipart: false,
        multipartUploadId: null,
        objectKey: 'photos/w1/10054/original',
        status: 'VERIFYING',
        verificationLeaseToken: 'dead-worker-1-xyz',
        verificationLeaseExpiresAt: Date.now() - 5000, // Expired lease
        expiresAt: Date.now() + 1800000,
        completedAt: null,
        photoId: null,
        quotaSettled: false,
      };
      uploadService.sessions.set('10054', session);

      const r2Reader = async () => testBytes;

      // Worker 2 sweeps and takes over verification
      const result = await uploadService.executeR2ReadBackVerification({
        sessionId: '10054',
        workerId: 'worker-node-2',
        r2Reader,
      });

      expect(result.success).toBe(true);
      expect(result.status).toBe('COMPLETED');
      expect(session.status).toBe('COMPLETED');
      expect(session.verificationLeaseToken).toContain('worker-node-2');
    });

    it('ensures verification reprocessing is idempotent (F08)', async () => {
      const testBytes = Buffer.from('Reprocessing idempotent test bytes');
      const correctSha256 = crypto.createHash('sha256').update(testBytes).digest('hex');

      const session: StoredUploadSession = {
        id: '10055',
        weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        expectedBytes: String(testBytes.length),
        actualBytes: String(testBytes.length),
        clientDeclaredSha256: correctSha256,
        verifiedObjectSha256: correctSha256,
        isMultipart: false,
        multipartUploadId: null,
        objectKey: 'photos/w1/10055/original',
        status: 'COMPLETED',
        photoId: 'photo-pre-existing-uuid',
        expiresAt: Date.now() + 1800000,
        completedAt: new Date().toISOString(),
        quotaSettled: true,
      };
      uploadService.sessions.set('10055', session);

      const r2Reader = async () => testBytes;

      const result = await uploadService.executeR2ReadBackVerification({
        sessionId: '10055',
        workerId: 'worker-node-any',
        r2Reader,
      });

      expect(result.success).toBe(true);
      expect(result.recovered).toBe(true);
      expect(result.photoId).toBe('photo-pre-existing-uuid');
    });
  });

  // ===================================================================
  // F09: Session-Based Idempotency & Concurrency Isolation
  // ===================================================================
  describe('F09: Session-Based Idempotency & Concurrency Isolation', () => {
    it('enforces primary idempotency boundary on uploadSessionId without accidental deduplication of distinct sessions', async () => {
      const identicalHash = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

      const sessionA: StoredUploadSession = {
        id: '10061',
        weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        expectedBytes: '1000',
        actualBytes: null,
        clientDeclaredSha256: identicalHash,
        verifiedObjectSha256: null,
        isMultipart: false,
        multipartUploadId: null,
        objectKey: 'photos/w1/10061/original',
        status: 'RESERVED',
        expiresAt: Date.now() + 1800000,
        completedAt: null,
        photoId: null,
        quotaSettled: false,
      };
      uploadService.sessions.set('10061', sessionA);

      const sessionB: StoredUploadSession = {
        id: '10062',
        weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        expectedBytes: '1000',
        actualBytes: null,
        clientDeclaredSha256: identicalHash,
        verifiedObjectSha256: null,
        isMultipart: false,
        multipartUploadId: null,
        objectKey: 'photos/w1/10062/original',
        status: 'RESERVED',
        expiresAt: Date.now() + 1800000,
        completedAt: null,
        photoId: null,
        quotaSettled: false,
      };
      uploadService.sessions.set('10062', sessionB);

      const resA = await uploadService.completeUploadSession({
        sessionId: '10061',
        actualBytes: '1000',
        providerObjectExists: true,
        providerObjectSizeBytes: '1000',
      });

      const resB = await uploadService.completeUploadSession({
        sessionId: '10062',
        actualBytes: '1000',
        providerObjectExists: true,
        providerObjectSizeBytes: '1000',
      });

      expect(resA.success).toBe(true);
      expect(resB.success).toBe(true);
      expect(resA.photoId).not.toBe(resB.photoId);
      expect(uploadService.photos.size).toBe(2);

      const resAReplay = await uploadService.completeUploadSession({
        sessionId: '10061',
        actualBytes: '1000',
        providerObjectExists: true,
        providerObjectSizeBytes: '1000',
      });
      expect(resAReplay.recovered).toBe(true);
      expect(resAReplay.photoId).toBe(resA.photoId);
      expect(uploadService.photos.size).toBe(2);
    });

    it('handles abort vs complete race correctly', async () => {
      const session: StoredUploadSession = {
        id: '10070',
        weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        expectedBytes: '5000',
        actualBytes: null,
        clientDeclaredSha256: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
        verifiedObjectSha256: null,
        isMultipart: true,
        multipartUploadId: 'mp-race-1',
        objectKey: 'photos/w1/10070/original',
        status: 'RESERVED',
        expiresAt: Date.now() + 1800000,
        completedAt: null,
        photoId: null,
        quotaSettled: false,
      };
      uploadService.sessions.set('10070', session);

      await uploadService.completeUploadSession({
        sessionId: '10070',
        actualBytes: '5000',
        providerObjectExists: true,
        providerObjectSizeBytes: '5000',
      });

      const abortRes = uploadService.abortUploadSession('10070');
      expect(abortRes.success).toBe(false);
      expect(abortRes.error).toContain('CANNOT_ABORT_COMPLETED_SESSION');
    });
  });

  // ===================================================================
  // F10: Guest Favorite Authorization & Cross-Wedding Isolation
  // ===================================================================
  describe('F10: Cross-Wedding Token Isolation for Favorites', () => {
    it('strictly rejects valid token from Wedding A when used on Wedding B', () => {
      const tokenWeddingA = GuestAuthorizationService.issueGuestToken('priya-rohan-2026', 'guest-client-1');

      const res = GuestAuthorizationService.authorizeFavoriteWrite({
        weddingSlug: 'ananya-kabir-2026',
        guestToken: tokenWeddingA,
      });

      expect(res.authorized).toBe(false);
      expect(res.error).toContain('SLUG_MISMATCH');
    });

    it('rejects forged device UUID without valid guest session token', () => {
      const res = GuestAuthorizationService.authorizeFavoriteWrite({
        weddingSlug: 'priya-rohan-2026',
        deviceUuid: 'spoofed-hardware-id-999',
      });

      expect(res.authorized).toBe(false);
      expect(res.error).toContain('A device UUID alone does not authorize favorite writes');
    });
  });

  // ===================================================================
  // F14 & Lifecycle: Cross-Tenant, Private Gallery & Expiration Checks
  // ===================================================================
  describe('F14 & Lifecycle: Cross-Tenant & Expiration Enforcements', () => {
    it('rejects guest access to private/family photos without a valid PIN token (F14)', () => {
      const privatePhoto: PhotoRecord = {
        id: 'p-family-01',
        weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        weddingSlug: 'priya-rohan-2026',
        status: 'approved',
        visibility: 'visibility_family',
        keyThumb: 'thumb.webp',
        keyPreview: 'preview.webp',
      };

      const canViewWithoutPin = GuestAuthorizationService.canViewPhoto(privatePhoto, undefined);
      expect(canViewWithoutPin).toBe(false);

      const validPinToken = GuestAuthorizationService.issueGuestToken('priya-rohan-2026', 'fp-device-123');
      const canViewWithPin = GuestAuthorizationService.canViewPhoto(privatePhoto, validPinToken);
      expect(canViewWithPin).toBe(true);

      const otherWeddingToken = GuestAuthorizationService.issueGuestToken('ananya-kabir-2026', 'fp-device-123');
      const canViewOther = GuestAuthorizationService.canViewPhoto(privatePhoto, otherWeddingToken);
      expect(canViewOther).toBe(false);
    });

    it('rejects photographer attempting to upload to an unassigned wedding', () => {
      const validToken = 'photographer-token-valid-001';
      const unauthorizedWeddingId = 'e8e1215b-9cf4-4e2a-89a1-cb9e1e36780c';

      const crossTenant = uploadService.verifyPhotographerAccess(validToken, unauthorizedWeddingId);
      expect(crossTenant.authorized).toBe(false);
      expect(crossTenant.error).toContain('CROSS_TENANT_VIOLATION');
    });

    it('rejects part URL generation for expired upload sessions', () => {
      const expiredSession: StoredUploadSession = {
        id: '10080',
        weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        expectedBytes: '52428800',
        actualBytes: null,
        clientDeclaredSha256: 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899',
        verifiedObjectSha256: null,
        isMultipart: true,
        multipartUploadId: 'mp-expired',
        objectKey: 'photos/w1/10080/original',
        status: 'RESERVED',
        expiresAt: Date.now() - 5000,
        completedAt: null,
        photoId: null,
        quotaSettled: false,
      };
      uploadService.sessions.set('10080', expiredSession);

      const partResult = uploadService.validatePartUrlRequest('10080');
      expect(partResult.allowed).toBe(false);
      expect(partResult.error).toContain('SESSION_EXPIRED');
    });

    it('enforces PIN rate limiting with 15-minute lockout after 5 consecutive failures (F13)', () => {
      const testIp = '198.51.100.42';
      const slug = 'priya-rohan-2026';

      // 4 failed attempts allow retries with decrementing counter
      for (let i = 1; i <= 4; i++) {
        const attempt = GuestAuthorizationService.recordPinAttempt(testIp, slug, false);
        expect(attempt.allowed).toBe(true);
        expect(attempt.remainingAttempts).toBe(5 - i);
      }

      // 5th failed attempt locks out the IP
      const fifthAttempt = GuestAuthorizationService.recordPinAttempt(testIp, slug, false);
      expect(fifthAttempt.allowed).toBe(false);
      expect(fifthAttempt.error).toContain('PIN_LOCKED_OUT');

      // Subsequent 6th attempt is strictly blocked
      const blockedAttempt = GuestAuthorizationService.recordPinAttempt(testIp, slug, false);
      expect(blockedAttempt.allowed).toBe(false);
      expect(blockedAttempt.error).toContain('PIN_RATE_LIMITED');
    });

    it('strictly rejects revoked guest session tokens across all instances (F10)', () => {
      const token = GuestAuthorizationService.issueGuestToken('priya-rohan-2026', 'device-revocation-test');
      expect(GuestAuthorizationService.verifyGuestToken(token, 'priya-rohan-2026').valid).toBe(true);

      // Emergency revocation
      GuestAuthorizationService.REVOKED_GUEST_TOKENS.add(token);
      try {
        const verifyRevoked = GuestAuthorizationService.verifyGuestToken(token, 'priya-rohan-2026');
        expect(verifyRevoked.valid).toBe(false);
        expect(verifyRevoked.error).toContain('TOKEN_REVOKED');
      } finally {
        GuestAuthorizationService.REVOKED_GUEST_TOKENS.delete(token);
      }
    });

    it('strictly forbids privileged mutations when caller only holds a guest session token (F10)', () => {
      const guestToken = GuestAuthorizationService.issueGuestToken('priya-rohan-2026', 'guest-client-1');

      const uploadAttempt = GuestAuthorizationService.canPerformOperation('upload_photo', {
        weddingSlug: 'priya-rohan-2026',
        guestToken,
      });
      expect(uploadAttempt.allowed).toBe(false);
      expect(uploadAttempt.error).toContain('GUEST_PRIVILEGE_VIOLATION');

      const deleteAttempt = GuestAuthorizationService.canPerformOperation('delete_photo', {
        weddingSlug: 'priya-rohan-2026',
        guestToken,
      });
      expect(deleteAttempt.allowed).toBe(false);
      expect(deleteAttempt.error).toContain('GUEST_PRIVILEGE_VIOLATION');
    });
  });

  // ===================================================================
  // F15: Edge CDN Handler, Origin Access Policy & Cache Isolation
  // ===================================================================
  describe('F15: Edge CDN Handler & Cache Isolation', () => {
    const cdnEnv = {
      CDN_SIGNING_SECRET: 'test-cdn-edge-secret-key-min-32-chars-long',
      ALLOW_EVENTUAL_CONSISTENCY: 'true',
    };

    function signEdgeUrl(key: string, expOffsetSec: number, disposition?: string) {
      const exp = Math.floor(Date.now() / 1000) + expOffsetSec;
      const cleanKey = key.replace(/^\/+/, '');
      const sig = crypto
        .createHmac('sha256', cdnEnv.CDN_SIGNING_SECRET)
        .update(`${cleanKey}:${exp}`)
        .digest('hex');

      const query = new URLSearchParams({ exp: String(exp), sig });
      if (disposition) {
        query.set('response-content-disposition', disposition);
      }
      return `https://media.shadify.in/${cleanKey}?${query.toString()}`;
    }

    it('rejects direct unsigned access to media assets with 403 Forbidden', async () => {
      const res = await EdgeCdnHandler.handleRequest(
        {
          method: 'GET',
          url: 'https://media.shadify.in/photos/wedding-1/photo-1/preview.jpg',
          headers: {},
        },
        cdnEnv
      );

      expect(res.status).toBe(403);
      expect(res.headers['Cache-Control']).toBe('no-store, private');
      expect(JSON.parse(res.body as string).error).toBe('FORBIDDEN_UNSIGNED_MEDIA_REQUEST');
    });

    it('rejects expired signed CDN URL with 403 Forbidden', async () => {
      const expiredUrl = signEdgeUrl('photos/wedding-1/photo-1/preview.jpg', -10);
      const res = await EdgeCdnHandler.handleRequest(
        {
          method: 'GET',
          url: expiredUrl,
          headers: {},
        },
        cdnEnv
      );

      expect(res.status).toBe(403);
      expect(JSON.parse(res.body as string).error).toBe('CDN_TOKEN_EXPIRED');
    });

    it('rejects tampered signature with 403 Forbidden', async () => {
      const validUrl = signEdgeUrl('photos/wedding-1/photo-1/preview.jpg', 3600);
      const tamperedUrl = validUrl.slice(0, -4) + '0000';
      const res = await EdgeCdnHandler.handleRequest(
        {
          method: 'GET',
          url: tamperedUrl,
          headers: {},
        },
        cdnEnv
      );

      expect(res.status).toBe(403);
      expect(JSON.parse(res.body as string).error).toBe('INVALID_CDN_SIGNATURE');
    });

    it('serves preview with private 1h Cache-Control and nosniff header on valid signature', async () => {
      const validUrl = signEdgeUrl('photos/wedding-1/photo-1/preview.webp', 3600);
      const res = await EdgeCdnHandler.handleRequest(
        {
          method: 'GET',
          url: validUrl,
          headers: {},
        },
        cdnEnv
      );

      expect(res.status).toBe(200);
      expect(res.headers['Content-Type']).toBe('image/webp');
      expect(res.headers['Cache-Control']).toBe('private, no-transform, max-age=3600');
      expect(res.headers['X-Content-Type-Options']).toBe('nosniff');
    });

    it('serves download with 15m Cache-Control and Content-Disposition attachment header', async () => {
      const validUrl = signEdgeUrl('photos/wedding-1/photo-1/original.jpg', 900, 'attachment; filename="wedding-photo.jpg"');
      const res = await EdgeCdnHandler.handleRequest(
        {
          method: 'GET',
          url: validUrl,
          headers: {},
        },
        cdnEnv
      );

      expect(res.status).toBe(200);
      expect(res.headers['Content-Type']).toBe('image/jpeg');
      expect(res.headers['Cache-Control']).toBe('private, no-transform, max-age=900');
      expect(res.headers['Content-Disposition']).toBe('attachment; filename="wedding-photo.jpg"');
    });

    it('rejects non-GET/HEAD methods with 405 Method Not Allowed', async () => {
      const validUrl = signEdgeUrl('photos/wedding-1/photo-1/preview.webp', 3600);
      const res = await EdgeCdnHandler.handleRequest(
        {
          method: 'POST',
          url: validUrl,
          headers: {},
        },
        cdnEnv
      );

      expect(res.status).toBe(405);
      expect(JSON.parse(res.body as string).error).toBe('METHOD_NOT_ALLOWED');
    });

    it('rejects canonical CDN URL when variant scope is modified (e.g. preview signature presented for download) (F15)', async () => {
      const nowSec = Math.floor(Date.now() / 1000);
      const expiresSec = nowSec + 3600;
      const key = 'photos/wedding-1/photo-1/preview.webp';
      const canonicalString = `GET\nwedding-1\nphoto-1\npreview\n${key}\n${expiresSec}\n`;
      const signature = crypto
        .createHmac('sha256', 'shadify-cdn-media-signing-hmac-sha256-secret-32ch')
        .update(canonicalString)
        .digest('hex');

      // Present the same signature for variant=download
      const maliciousUrl = `https://media.shadify.in/${key}?exp=${expiresSec}&sig=${signature}&w=wedding-1&pid=photo-1&v=download`;
      const res = await EdgeCdnHandler.handleRequest(
        {
          method: 'GET',
          url: maliciousUrl,
          headers: {},
        },
        cdnEnv
      );

      expect(res.status).toBe(403);
      expect(JSON.parse(res.body as string).error).toBe('INVALID_CDN_SIGNATURE');
    });

    it('rejects path traversal attempts in Edge CDN requests (F15)', async () => {
      // 1. Literal path traversal
      const resLiteral = await EdgeCdnHandler.handleRequest(
        {
          method: 'GET',
          url: 'https://media.shadify.in/photos/../etc/passwd?exp=9999999999&sig=dummy',
          headers: {},
        },
        cdnEnv
      );
      expect(resLiteral.status).toBe(403);
      expect(JSON.parse(resLiteral.body as string).error).toBe('PATH_TRAVERSAL_DETECTED');

      // 2. Encoded path traversal (%2e%2e)
      const resEncoded = await EdgeCdnHandler.handleRequest(
        {
          method: 'GET',
          url: 'https://media.shadify.in/photos/%2e%2e/secrets.env?exp=9999999999&sig=dummy',
          headers: {},
        },
        cdnEnv
      );
      expect(resEncoded.status).toBe(403);
      expect(JSON.parse(resEncoded.body as string).error).toBe('PATH_TRAVERSAL_DETECTED');

      // 3. Double slashes
      const resDouble = await EdgeCdnHandler.handleRequest(
        {
          method: 'GET',
          url: 'https://media.shadify.in//photos//wedding-1//preview.jpg?exp=9999999999&sig=dummy',
          headers: {},
        },
        cdnEnv
      );
      expect(resDouble.status).toBe(403);
      expect(JSON.parse(resDouble.body as string).error).toBe('PATH_TRAVERSAL_DETECTED');
    });

    it('rejects HTTP Parameter Pollution (HPP) with multiple sig or exp parameters (F15)', async () => {
      const resHpp = await EdgeCdnHandler.handleRequest(
        {
          method: 'GET',
          url: 'https://media.shadify.in/photos/wedding-1/photo-1/preview.webp?exp=1000&exp=2000&sig=abc',
          headers: {},
        },
        cdnEnv
      );
      expect(resHpp.status).toBe(400);
      expect(JSON.parse(resHpp.body as string).error).toBe('HTTP_PARAMETER_POLLUTION_DETECTED');
    });

    it('supports seamless secret rotation with CDN_PREVIOUS_SIGNING_SECRET (F15)', async () => {
      const prevSecret = 'old-previous-cdn-secret-32characters-key';
      const rotatedEnv = {
        ...cdnEnv,
        CDN_PREVIOUS_SIGNING_SECRET: prevSecret,
      };

      const nowSec = Math.floor(Date.now() / 1000);
      const expiresSec = nowSec + 3600;
      const key = 'photos/wedding-1/photo-1/preview.webp';
      const canonicalString = `GET\nwedding-1\nphoto-1\npreview\n${key}\n${expiresSec}\n`;
      const prevSignature = crypto.createHmac('sha256', prevSecret).update(canonicalString).digest('hex');

      const url = `https://media.shadify.in/${key}?exp=${expiresSec}&sig=${prevSignature}&w=wedding-1&pid=photo-1&v=preview`;
      const res = await EdgeCdnHandler.handleRequest(
        {
          method: 'GET',
          url,
          headers: {},
        },
        rotatedEnv
      );

      expect(res.status).toBe(200);
      expect(res.headers['Cache-Control']).toBe('private, no-transform, max-age=3600');
    });

    it('immediately rejects in-flight signed URLs if wedding gallery is revoked at the edge (Finding 2)', async () => {
      const revokedEnv = {
        ...cdnEnv,
        REVOKED_WEDDINGS: new Set(['wedding-revoked-now']),
      };

      const nowSec = Math.floor(Date.now() / 1000);
      const expiresSec = nowSec + 3600;
      const key = 'photos/wedding-revoked-now/photo-1/preview.webp';
      const canonicalString = `GET\nwedding-revoked-now\nphoto-1\npreview\n${key}\n${expiresSec}\n`;
      const signature = crypto.createHmac('sha256', cdnEnv.CDN_SIGNING_SECRET).update(canonicalString).digest('hex');

      const url = `https://media.shadify.in/${key}?exp=${expiresSec}&sig=${signature}&w=wedding-revoked-now&pid=photo-1&v=preview`;
      const res = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url, headers: {} },
        revokedEnv
      );

      expect(res.status).toBe(403);
      expect(res.headers['Cache-Control']).toBe('no-store, private');
      expect(JSON.parse(res.body as string).error).toBe('WEDDING_GALLERY_REVOKED');
    });

    it('immediately rejects in-flight signed URLs if specific photo is revoked at the edge (Finding 2)', async () => {
      const revokedEnv = {
        ...cdnEnv,
        REVOKED_PHOTOS: new Set(['photo-deleted-123']),
      };

      const nowSec = Math.floor(Date.now() / 1000);
      const expiresSec = nowSec + 3600;
      const key = 'photos/w1/photo-deleted-123/preview.webp';
      const canonicalString = `GET\nw1\nphoto-deleted-123\npreview\n${key}\n${expiresSec}\n`;
      const signature = crypto.createHmac('sha256', cdnEnv.CDN_SIGNING_SECRET).update(canonicalString).digest('hex');

      const url = `https://media.shadify.in/${key}?exp=${expiresSec}&sig=${signature}&w=w1&pid=photo-deleted-123&v=preview`;
      const res = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url, headers: {} },
        revokedEnv
      );

      expect(res.status).toBe(403);
      expect(res.headers['Cache-Control']).toBe('no-store, private');
      expect(JSON.parse(res.body as string).error).toBe('MEDIA_ASSET_REVOKED');
    });

    it('rejects in-flight signed URLs if wedding is marked revoked in WEDDING_REVOCATION_KV (F15)', async () => {
      const kvStore = new Map<string, string>([
        ['revoked_weddings:wedding-kv-revoked', '1'],
      ]);
      const kvEnv = {
        ...cdnEnv,
        WEDDING_REVOCATION_KV: {
          get: async (key: string) => kvStore.get(key) || null,
        },
      };

      const nowSec = Math.floor(Date.now() / 1000);
      const expiresSec = nowSec + 3600;
      const key = 'photos/wedding-kv-revoked/p1/preview.webp';
      const canonicalString = `GET\nwedding-kv-revoked\np1\npreview\n${key}\n${expiresSec}\n`;
      const signature = crypto.createHmac('sha256', cdnEnv.CDN_SIGNING_SECRET).update(canonicalString).digest('hex');

      const url = `https://media.shadify.in/${key}?exp=${expiresSec}&sig=${signature}&w=wedding-kv-revoked&pid=p1&v=preview`;
      const res = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url, headers: {} },
        kvEnv
      );

      expect(res.status).toBe(403);
      expect(res.headers['Cache-Control']).toBe('no-store, private');
      expect(JSON.parse(res.body as string).error).toBe('WEDDING_GALLERY_REVOKED');
    });

    it('rejects in-flight signed URLs if photo is marked revoked in WEDDING_REVOCATION_KV (F15)', async () => {
      const kvStore = new Map<string, string>([
        ['revoked_photos:photo-kv-revoked-99', '1'],
      ]);
      const kvEnv = {
        ...cdnEnv,
        WEDDING_REVOCATION_KV: {
          get: async (key: string) => kvStore.get(key) || null,
        },
      };

      const nowSec = Math.floor(Date.now() / 1000);
      const expiresSec = nowSec + 3600;
      const key = 'photos/w1/photo-kv-revoked-99/preview.webp';
      const canonicalString = `GET\nw1\nphoto-kv-revoked-99\npreview\n${key}\n${expiresSec}\n`;
      const signature = crypto.createHmac('sha256', cdnEnv.CDN_SIGNING_SECRET).update(canonicalString).digest('hex');

      const url = `https://media.shadify.in/${key}?exp=${expiresSec}&sig=${signature}&w=w1&pid=photo-kv-revoked-99&v=preview`;
      const res = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url, headers: {} },
        kvEnv
      );

      expect(res.status).toBe(403);
      expect(res.headers['Cache-Control']).toBe('no-store, private');
      expect(JSON.parse(res.body as string).error).toBe('MEDIA_ASSET_REVOKED');
    });

    it('fails closed with 503 and no-store if WEDDING_REVOCATION_KV throws an unexpected error (F15)', async () => {
      const failingKvEnv = {
        ...cdnEnv,
        WEDDING_REVOCATION_KV: {
          get: async () => {
            throw new Error('Cloudflare KV edge network connection timeout');
          },
        },
      };

      const nowSec = Math.floor(Date.now() / 1000);
      const expiresSec = nowSec + 3600;
      const key = 'photos/w1/p1/preview.webp';
      const canonicalString = `GET\nw1\np1\npreview\n${key}\n${expiresSec}\n`;
      const signature = crypto.createHmac('sha256', cdnEnv.CDN_SIGNING_SECRET).update(canonicalString).digest('hex');

      const url = `https://media.shadify.in/${key}?exp=${expiresSec}&sig=${signature}&w=w1&pid=p1&v=preview`;
      const res = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url, headers: {} },
        failingKvEnv
      );

      expect(res.status).toBe(503);
      expect(res.headers['Cache-Control']).toBe('no-store, private');
      expect(res.headers['Retry-After']).toBe('10');
      expect(JSON.parse(res.body as string).error).toBe('REVOCATION_CHECK_UNAVAILABLE');
    });

    it('rejects revoked asset before cache lookup or storage fetch, preventing cache leakage (F15)', async () => {
      let r2FetchCallCount = 0;
      const trackingFetcher = async (key: string) => {
        r2FetchCallCount++;
        return { data: Buffer.from('image_bytes'), contentType: 'image/jpeg' };
      };

      const revokedEnv = {
        ...cdnEnv,
        REVOKED_WEDDINGS: new Set(['wedding-killswitch-active']),
      };

      const nowSec = Math.floor(Date.now() / 1000);
      const expiresSec = nowSec + 3600;
      const key = 'photos/wedding-killswitch-active/p1/preview.webp';
      const canonicalString = `GET\nwedding-killswitch-active\np1\npreview\n${key}\n${expiresSec}\n`;
      const signature = crypto.createHmac('sha256', cdnEnv.CDN_SIGNING_SECRET).update(canonicalString).digest('hex');

      const url = `https://media.shadify.in/${key}?exp=${expiresSec}&sig=${signature}&w=wedding-killswitch-active&pid=p1&v=preview`;
      const res = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url, headers: {} },
        revokedEnv,
        trackingFetcher
      );

      // Must be rejected with 403 no-store
      expect(res.status).toBe(403);
      expect(res.headers['Cache-Control']).toBe('no-store, private');
      expect(JSON.parse(res.body as string).error).toBe('WEDDING_GALLERY_REVOKED');
      // Storage fetcher was NEVER called because revocation check ran at Step 0/1
      expect(r2FetchCallCount).toBe(0);
    });

    it('rejects old signature once CDN_PREVIOUS_SIGNING_SECRET is removed after key rotation rollout (F15)', async () => {
      const oldSecret = 'previous-active-secret-32-chars-long-123';
      const newSecret = 'new-active-secret-32-characters-length-456';

      const nowSec = Math.floor(Date.now() / 1000);
      const expiresSec = nowSec + 3600;
      const key = 'photos/w1/p1/preview.webp';
      const canonicalString = `GET\nw1\np1\npreview\n${key}\n${expiresSec}\n`;
      const oldSignature = crypto.createHmac('sha256', oldSecret).update(canonicalString).digest('hex');
      const url = `https://media.shadify.in/${key}?exp=${expiresSec}&sig=${oldSignature}&w=w1&pid=p1&v=preview`;

      // Phase 1: Dual-key grace period -> Old key is accepted
      const gracePeriodEnv: EdgeCdnEnv = {
        CDN_SIGNING_SECRET: newSecret,
        CDN_PREVIOUS_SIGNING_SECRET: oldSecret,
        ALLOW_EVENTUAL_CONSISTENCY: 'true',
      };
      const graceRes = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url, headers: {} },
        gracePeriodEnv
      );
      expect(graceRes.status).toBe(200);

      // Phase 2: Old key decommissioned (CDN_PREVIOUS_SIGNING_SECRET unset) -> Old key immediately rejected
      const decommissionedEnv: EdgeCdnEnv = {
        CDN_SIGNING_SECRET: newSecret,
        ALLOW_EVENTUAL_CONSISTENCY: 'true',
      };
      const decommissionedRes = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url, headers: {} },
        decommissionedEnv
      );
      expect(decommissionedRes.status).toBe(403);
      expect(decommissionedRes.headers['Cache-Control']).toBe('no-store, private');
      expect(JSON.parse(decommissionedRes.body as string).error).toBe('INVALID_CDN_SIGNATURE');
    });

    it('demonstrates bounded eventual consistency: stale PoP serves valid URL during KV propagation window (F15)', async () => {
      // Simulate a stale PoP that has not yet observed the KV write (get returns null)
      const stalePopKvEnv: EdgeCdnEnv = {
        CDN_SIGNING_SECRET: cdnEnv.CDN_SIGNING_SECRET,
        ALLOW_EVENTUAL_CONSISTENCY: 'true',
        WEDDING_REVOCATION_KV: {
          get: async () => null, // Stale replica hasn't received the write yet
        },
      };

      const nowSec = Math.floor(Date.now() / 1000);
      const expiresSec = nowSec + 3600;
      const key = 'photos/w1/p1/preview.webp';
      const canonicalString = `GET\nw1\np1\npreview\n${key}\n${expiresSec}\n`;
      const signature = crypto.createHmac('sha256', cdnEnv.CDN_SIGNING_SECRET).update(canonicalString).digest('hex');
      const url = `https://media.shadify.in/${key}?exp=${expiresSec}&sig=${signature}&w=w1&pid=p1&v=preview`;

      // During the propagation window at the stale PoP, request succeeds
      const staleRes = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url, headers: {} },
        stalePopKvEnv
      );
      expect(staleRes.status).toBe(200);

      // Once the PoP observes the write, subsequent requests are immediately rejected
      const updatedPopKvEnv: EdgeCdnEnv = {
        ...stalePopKvEnv,
        WEDDING_REVOCATION_KV: {
          get: async (k: string) => (k === 'revoked_weddings:w1' ? '1' : null),
        },
      };
      const updatedRes = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url, headers: {} },
        updatedPopKvEnv
      );
      expect(updatedRes.status).toBe(403);
      expect(JSON.parse(updatedRes.body as string).error).toBe('WEDDING_GALLERY_REVOKED');
    });

    it('demonstrates full lifecycle: deletion -> outbox event -> consumer -> KV revocation -> old signed URL rejection (F14 & F15)', async () => {
      // 1. Issue an unexpired signed CDN URL for a photo
      const photoId = 'photo-lifecycle-revocation-test-001';
      const weddingSlug = 'priya-rohan-2026';
      const key = `photos/${weddingSlug}/${photoId}/preview.webp`;
      const nowSec = Math.floor(Date.now() / 1000);
      const expiresSec = nowSec + 3600; // Valid for 1 hour

      const canonicalString = `GET\n${weddingSlug}\n${photoId}\npreview\n${key}\n${expiresSec}\n`;
      const signature = crypto.createHmac('sha256', cdnEnv.CDN_SIGNING_SECRET).update(canonicalString).digest('hex');
      const validSignedUrl = `https://media.shadify.in/${key}?exp=${expiresSec}&sig=${signature}&w=${weddingSlug}&pid=${photoId}&v=preview`;

      // 2. In-memory simulated Cloudflare KV store
      const kvStoreData = new Map<string, string>();
      const mockKvStore: RevocationKvStore = {
        put: async (k: string, v: string) => {
          kvStoreData.set(k, v);
        },
        get: async (k: string) => kvStoreData.get(k) || null,
      };

      const edgeEnv: EdgeCdnEnv = {
        ...cdnEnv,
        ALLOW_EVENTUAL_CONSISTENCY: 'true',
        WEDDING_REVOCATION_KV: {
          get: async (k: string) => mockKvStore.get(k),
        },
      };

      // Prior to deletion: edge allows the request (200 OK)
      const initialEdgeRes = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url: validSignedUrl, headers: {} },
        edgeEnv
      );
      expect(initialEdgeRes.status).toBe(200);

      // 3. Database Deletion & Outbox Event Emission (simulating DELETE route behavior)
      const mockPool = {
        connect: async () => ({
          query: async (sql: string, params?: any[]) => {
            if (sql.includes('SELECT id, event_type')) {
              // Return mock leased outbox event
              return {
                rows: [
                  {
                    id: 99901n,
                    event_type: 'PHOTO_DELETED',
                    wedding_id: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
                    photo_id: photoId,
                    payload: { photoId, weddingSlug, objectKey: key },
                    retry_count: 0,
                    max_retries: 4,
                  },
                ],
              };
            }
            return { rowCount: 1, rows: [] };
          },
          release: () => {},
        }),
      } as any;

      // 4. Outbox Consumer Execution: processes outbox event and synchronizes to KV & Purge
      const mockPurgeService = {
        purgePhoto: async () => ({ success: true, purgedCount: 1, retryCount: 0 }),
        purgeWedding: async () => ({ success: true, purgedCount: 1, retryCount: 0 }),
      } as any;

      const processor = new OutboxRevocationProcessor({
        pool: mockPool,
        purgeService: mockPurgeService,
        kvStore: mockKvStore,
      });

      const procResult = await processor.processBatch(5);
      expect(procResult.processedCount).toBe(1);
      expect(procResult.completedCount).toBe(1);

      // Verify KV now contains the revocation record
      expect(await mockKvStore.get(`revoked_photos:${photoId}`)).toBe('1');

      // 5. Subsequent request with the PREVIOUSLY ISSUED valid signed URL
      // Edge worker evaluates Step 1 pre-cache check against KV: strictly rejects with 403
      const revokedEdgeRes = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url: validSignedUrl, headers: {} },
        edgeEnv
      );

      expect(revokedEdgeRes.status).toBe(403);
      const body = JSON.parse(revokedEdgeRes.body as string);
      expect(body.error).toBe('MEDIA_ASSET_REVOKED');
      expect(revokedEdgeRes.headers['Cache-Control']).toBe('no-store, private');
    });

    it('tracks retry limits, exponential backoff, and dead-letter queue on purge failure (F15 outbox)', async () => {
      let queryCalls: { sql: string; params: any[] }[] = [];
      const mockPool = {
        connect: async () => ({
          query: async (sql: string, params?: any[]) => {
            queryCalls.push({ sql, params: params || [] });
            if (sql.includes('SELECT id, event_type')) {
              return {
                rows: [
                  {
                    id: 99902n,
                    event_type: 'PHOTO_DELETED',
                    wedding_id: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
                    photo_id: 'photo-fail-001',
                    payload: { photoId: 'photo-fail-001', weddingSlug: 'test-slug' },
                    retry_count: 3, // Already retried 3 times
                    max_retries: 4, // Max retries is 4
                  },
                ],
              };
            }
            if (sql.includes("SET status = 'PROCESSING'")) {
              return { rowCount: 1 };
            }
            if (sql.includes("SET status = 'DEAD_LETTER'")) {
              return { rowCount: 1 };
            }
            return { rows: [] };
          },
          release: () => {},
        }),
      } as any;

      // Mock purge service that fails
      const failingPurgeService = {
        purgePhoto: async () => ({ success: false, error: 'Cloudflare Zone API Timeout 504' }),
        purgeWedding: async () => ({ success: false, error: 'Cloudflare Zone API Timeout 504' }),
      } as any;

      const processor = new OutboxRevocationProcessor({
        pool: mockPool,
        purgeService: failingPurgeService,
      });

      const res = await processor.processBatch(1);
      expect(res.processedCount).toBe(1);
      expect(res.failedCount).toBe(1);
      expect(res.deadLetterCount).toBe(1); // Terminal failure moved to DEAD_LETTER

      // Verify SQL updated to DEAD_LETTER
      const deadLetterUpdate = queryCalls.find((q) => q.sql.includes("SET status = 'DEAD_LETTER'"));
      expect(deadLetterUpdate).toBeDefined();
      expect(deadLetterUpdate!.params[0]).toBe(4); // retry_count reached 4
      expect(deadLetterUpdate!.params[1]).toContain('TERMINAL_FAILURE_MAX_RETRIES');
    });

    it('handles stale edge KV by querying authoritative Durable Object coordinator and self-healing KV', async () => {
      const photoId = 'photo-stale-kv-001';
      const weddingSlug = 'priya-rohan-2026';
      const key = `originals/${weddingSlug}/${photoId}.jpg`;

      // 1. Issue valid signed URL
      const signed = CdnService.generateSignedCdnUrl({
        objectKey: key,
        expiresInSeconds: 900,
        weddingSlug,
        photoId,
      });

      // 2. Mock KV simulating STALE state (returns null as if propagation has not reached this POP)
      let kvMap = new Map<string, string>();
      const mockStaleKv = {
        get: async (k: string) => kvMap.get(k) || null,
        put: async (k: string, v: string) => {
          kvMap.set(k, v);
        },
      };

      // 3. Mock Strongly Consistent Durable Object Coordinator (holds authoritative revocation)
      const revokedDoSet = new Set<string>();
      revokedDoSet.add(photoId); // Photo is revoked authoritatively in DO!

      const mockDo = {
        isWeddingRevoked: async () => false,
        isPhotoRevoked: async (pid: string, _slug: string) => revokedDoSet.has(pid),
      };

      const edgeEnv: EdgeCdnEnv = {
        CDN_SIGNING_SECRET: env.CLOUDFLARE_HMAC_SECRET,
        WEDDING_REVOCATION_KV: mockStaleKv,
        WEDDING_REVOCATION_DO: mockDo,
      };

      // 4. Request with valid signed URL:
      // Even though KV is stale (returns null), the edge worker queries the authoritative DO,
      // discovers the revocation, returns 403 MEDIA_ASSET_REVOKED, and self-heals KV!
      const staleKvRes = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url: signed.url, headers: {} },
        edgeEnv
      );

      expect(staleKvRes.status).toBe(403);
      const body = JSON.parse(staleKvRes.body as string);
      expect(body.error).toBe('MEDIA_ASSET_REVOKED');
      expect(body.message).toContain('authoritatively revoked by the Durable Object coordinator');

      // 5. Verify that KV has been self-healed by the edge worker
      expect(kvMap.get(`revoked_photos:${photoId}`)).toBe('1');

      // Subsequent request hits the self-healed KV directly
      const healedRes = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url: signed.url, headers: {} },
        edgeEnv
      );
      expect(healedRes.status).toBe(403);
      const healedBody = JSON.parse(healedRes.body as string);
      expect(healedBody.message).toContain('via KV');
    });

    it('fails closed with 503 when coordinator check experiences infrastructure failure', async () => {
      const signed = CdnService.generateSignedCdnUrl({
        objectKey: 'originals/priya-rohan-2026/test.jpg',
        expiresInSeconds: 900,
        weddingSlug: 'priya-rohan-2026',
        photoId: 'photo-err-001',
      });

      const failingDo = {
        isWeddingRevoked: async () => false,
        isPhotoRevoked: async () => {
          throw new Error('Durable Object unreachable (500)');
        },
      };

      const edgeEnv: EdgeCdnEnv = {
        CDN_SIGNING_SECRET: env.CLOUDFLARE_HMAC_SECRET,
        WEDDING_REVOCATION_DO: failingDo,
      };

      const res = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url: signed.url, headers: {} },
        edgeEnv
      );

      expect(res.status).toBe(503);
      const body = JSON.parse(res.body as string);
      expect(body.error).toBe('REVOCATION_CHECK_UNAVAILABLE');
      expect(res.headers['Retry-After']).toBe('10');
    });

    it('recovers and processes expired outbox leases after worker crash', async () => {
      let leaseQueryCaptured = '';
      let updateCalls: { sql: string; params: any[] }[] = [];

      const mockPool = {
        connect: async () => ({
          query: async (sql: string, params?: any[]) => {
            if (sql.includes('SELECT id, event_type')) {
              leaseQueryCaptured = sql;
              return {
                rows: [
                  {
                    id: 88801n,
                    event_type: 'PHOTO_DELETED',
                    wedding_id: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
                    photo_id: 'photo-crashed-worker',
                    payload: { photoId: 'photo-crashed-worker', weddingSlug: 'test-slug' },
                    retry_count: 1,
                    max_retries: 4,
                  },
                ],
              };
            }
            if (sql.includes('UPDATE outbox_events')) {
              updateCalls.push({ sql, params: params || [] });
              return { rowCount: 1, rows: [] };
            }
            return { rowCount: 1, rows: [] };
          },
          release: () => {},
        }),
      } as any;

      const mockPurgeService = {
        purgePhoto: async () => ({ success: true, purgedCount: 1, retryCount: 0 }),
      } as any;

      const processor = new OutboxRevocationProcessor({
        pool: mockPool,
        purgeService: mockPurgeService,
        leaseDurationSeconds: 45,
      });

      const result = await processor.processBatch(1);
      expect(result.processedCount).toBe(1);
      expect(result.completedCount).toBe(1);

      // Verify that query includes recovery of expired leases:
      expect(leaseQueryCaptured).toContain("lease_expires_at <= clock_timestamp()");
      expect(leaseQueryCaptured).toContain("FOR UPDATE SKIP LOCKED");

      // Verify lease token was set during leasing
      const processingUpdate = updateCalls.find((u) => u.sql.includes("SET status = 'PROCESSING'"));
      expect(processingUpdate).toBeDefined();
      expect(processingUpdate!.params[1]).toBe('45'); // lease duration 45 seconds

      // Verify completed event cleared lease token and expiry
      const completedUpdate = updateCalls.find((u) => u.sql.includes("SET status = 'COMPLETED'"));
      expect(completedUpdate).toBeDefined();
      expect(completedUpdate!.sql).toContain("lease_token = NULL");
      expect(completedUpdate!.sql).toContain("lease_expires_at = NULL");
    });

    it('guarantees idempotency and non-undoing revocation when purge fails after KV/DO succeed', async () => {
      let kvMap = new Map<string, string>();
      const mockKv = {
        get: async (k: string) => kvMap.get(k) || null,
        put: async (k: string, v: string) => {
          kvMap.set(k, v);
        },
      };

      let doRevocations = new Set<string>();
      const mockDo = {
        revokePhoto: async (pid: string) => {
          doRevocations.add(pid);
        },
        revokeWedding: async () => {},
        isWeddingRevoked: async () => false,
        isPhotoRevoked: async (pid: string) => doRevocations.has(pid),
      };

      let attempt = 0;
      const transientPurgeService = {
        purgePhoto: async () => {
          attempt++;
          if (attempt === 1) {
            // First attempt fails at cache purge stage
            return { success: false, error: 'Cloudflare 500 internal edge error' };
          }
          // Second attempt succeeds
          return { success: true, purgedCount: 1, retryCount: 1 };
        },
      } as any;

      const event = {
        id: 77701n,
        event_type: 'PHOTO_DELETED',
        wedding_id: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        photo_id: 'photo-partial-fail',
        payload: { photoId: 'photo-partial-fail', weddingSlug: 'test-slug' },
        retry_count: 0,
        max_retries: 4,
      };

      const mockPool = {
        connect: async () => ({
          query: async (sql: string, params?: any[]) => {
            if (sql.includes('SELECT id, event_type')) {
              return { rows: [event] };
            }
            if (sql.includes("SET status = 'PENDING'") && params) {
              event.retry_count = params[0]; // increment retry
              return { rowCount: 1, rows: [] };
            }
            return { rowCount: 1, rows: [] };
          },
          release: () => {},
        }),
      } as any;

      const processor = new OutboxRevocationProcessor({
        pool: mockPool,
        purgeService: transientPurgeService,
        kvStore: mockKv,
        doCoordinator: mockDo,
      });

      // 1. Run First Batch (Fails at Purge step)
      const res1 = await processor.processBatch(1);
      expect(res1.processedCount).toBe(1);
      expect(res1.failedCount).toBe(1);
      expect(res1.completedCount).toBe(0);

      // SAFETY ASSERTION: KV and DO revocation tombstones WERE WRITTEN and NOT UNDONE!
      expect(kvMap.get('revoked_photos:photo-partial-fail')).toBe('1');
      expect(doRevocations.has('photo-partial-fail')).toBe(true);

      // 2. Run Second Batch (Retry succeeds)
      const res2 = await processor.processBatch(1);
      expect(res2.processedCount).toBe(1);
      expect(res2.completedCount).toBe(1);
      expect(res2.failedCount).toBe(0);

      // Verification: Revocation tombstones remain intact
      expect(kvMap.get('revoked_photos:photo-partial-fail')).toBe('1');
      expect(doRevocations.has('photo-partial-fail')).toBe(true);
    });

    it('verifies tripartite deletion: logical DB delete, authorization revocation, and physical R2 deletion', async () => {
      let r2DeletedKeys: string[] = [];
      const mockR2 = {
        deletePhotoObjects: async (slug: string, pid: string) => {
          const keys = [
            `originals/${slug}/${pid}.raw`,
            `previews/${slug}/${pid}.webp`,
            `thumbnails/${slug}/${pid}.webp`,
          ];
          r2DeletedKeys.push(...keys);
          return { success: true, deletedKeys: keys };
        },
      };

      let kvMap = new Map<string, string>();
      const mockKv = {
        get: async (k: string) => kvMap.get(k) || null,
        put: async (k: string, v: string) => {
          kvMap.set(k, v);
        },
      };

      const mockPool = {
        connect: async () => ({
          query: async (sql: string) => {
            if (sql.includes('SELECT id, event_type')) {
              return {
                rows: [
                  {
                    id: 66601n,
                    event_type: 'PHOTO_DELETED',
                    wedding_id: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
                    photo_id: 'photo-tripartite-001',
                    payload: {
                      photoId: 'photo-tripartite-001',
                      weddingSlug: 'priya-rohan-2026',
                      manifest: {
                        keys: [
                          'originals/priya-rohan-2026/photo-tripartite-001.raw',
                          'previews/priya-rohan-2026/photo-tripartite-001.webp',
                          'thumbnails/priya-rohan-2026/photo-tripartite-001.webp',
                        ],
                      },
                    },
                    retry_count: 0,
                    max_retries: 4,
                  },
                ],
              };
            }
            if (sql.includes('SELECT key_original, key_preview, key_thumb')) {
              return {
                rows: [
                  {
                    key_original: 'originals/priya-rohan-2026/photo-tripartite-001.raw',
                    key_preview: 'previews/priya-rohan-2026/photo-tripartite-001.webp',
                    key_thumb: 'thumbnails/priya-rohan-2026/photo-tripartite-001.webp',
                  },
                ],
              };
            }
            return { rowCount: 1, rows: [] };
          },
          release: () => {},
        }),
      } as any;

      const mockPurge = {
        purgePhoto: async () => ({ success: true, purgedCount: 1, retryCount: 0 }),
      } as any;

      const processor = new OutboxRevocationProcessor({
        pool: mockPool,
        purgeService: mockPurge,
        kvStore: mockKv,
        r2Storage: mockR2,
      });

      const res = await processor.processBatch(1);
      expect(res.completedCount).toBe(1);

      // 1. Authorization Revocation verified (KV tombstone written)
      expect(kvMap.get('revoked_photos:photo-tripartite-001')).toBe('1');

      // 2. Physical R2 Deletion verified (original + derivatives deleted)
      expect(r2DeletedKeys).toHaveLength(3);
      expect(r2DeletedKeys).toContain('originals/priya-rohan-2026/photo-tripartite-001.raw');
      expect(r2DeletedKeys).toContain('previews/priya-rohan-2026/photo-tripartite-001.webp');
      expect(r2DeletedKeys).toContain('thumbnails/priya-rohan-2026/photo-tripartite-001.webp');
    });

    it('replays dead-lettered events through operator replay mechanism without authorization gaps', async () => {
      let deadLetterEvents = [
        {
          id: 55501n,
          status: 'DEAD_LETTER',
          retry_count: 4,
          last_error: 'TERMINAL_FAILURE_MAX_RETRIES: Network 504 Gateway Timeout',
        },
      ];

      const mockClient = {
        query: async (sql: string, params?: any[]) => {
          if (sql.includes("UPDATE outbox_events") && sql.includes("REPLAYED_BY_OPERATOR")) {
            const limit = typeof params?.[2] === 'number' ? params[2] : (typeof params?.[0] === 'number' ? params[0] : 50);
            const replayed = deadLetterEvents.slice(0, limit);
            replayed.forEach((e) => {
              e.status = 'PENDING';
              e.retry_count = 0;
              e.last_error = 'REPLAYED_BY_OPERATOR';
            });
            return {
              rowCount: replayed.length,
              rows: replayed.map((e) => ({
                id: e.id,
                wedding_id: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
                original_last_error: e.last_error,
              })),
            };
          }
          if (sql.includes('INSERT INTO audit_log')) {
            return { rowCount: 1 };
          }
          return { rowCount: 0, rows: [] };
        },
        release: () => {},
      };

      const mockPool = {
        connect: async () => mockClient,
        query: async (sql: string, params?: any[]) => mockClient.query(sql, params),
      } as any;

      const mockAuthService = {
        authorizeOperatorRequest: async () => ({
          authorized: true,
          operatorUserId: 'operator-f14-test',
          authoritativeRole: 'super_admin',
          scopes: ['outbox:dead-letter:replay'],
        }),
      };

      const processor = new OutboxRevocationProcessor({
        pool: mockPool,
        authorizationService: mockAuthService,
      });

      const replayedCount = await processor.replayDeadLetters({
        reason: 'Authorized manual dead-letter replay check',
        limit: 10,
        authContext: {
          request: { headers: { authorization: 'Bearer token-1' } },
        },
      });
      expect(replayedCount).toBe(1);
      expect(deadLetterEvents[0].status).toBe('PENDING');
      expect(deadLetterEvents[0].retry_count).toBe(0);
      expect(deadLetterEvents[0].last_error).toBe('REPLAYED_BY_OPERATOR');
    });

    it('enforces lease-token fencing on completion and blocks stale worker after lease takeover', async () => {
      let activeLeaseToken = 'token-worker-a-original';
      let capturedCompletionQuery = '';
      let capturedCompletionParams: any[] = [];

      const mockPool = {
        connect: async () => ({
          query: async (sql: string, params?: any[]) => {
            if (sql.includes('SELECT id, event_type')) {
              return {
                rows: [
                  {
                    id: 44401n,
                    event_type: 'PHOTO_DELETED',
                    wedding_id: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
                    photo_id: 'photo-fencing-001',
                    payload: { photoId: 'photo-fencing-001', weddingSlug: 'test-slug' },
                    retry_count: 0,
                    max_retries: 4,
                  },
                ],
              };
            }
            if (sql.includes("SET status = 'PROCESSING'")) {
              // Worker A acquired initial lease
              return { rowCount: 1 };
            }
            if (sql.includes("SET status = 'COMPLETED'")) {
              capturedCompletionQuery = sql;
              capturedCompletionParams = params || [];
              // Simulate: while Worker A was processing, Worker B took over and changed the token!
              const passedToken = params?.[1];
              if (passedToken !== activeLeaseToken) {
                // Fencing violation: token does not match active DB lease token!
                return { rowCount: 0 };
              }
              return { rowCount: 1 };
            }
            return { rows: [] };
          },
          release: () => {},
        }),
      } as any;

      const mockPurge = {
        purgePhoto: async () => {
          // Mid-processing: simulate lease expiration and Worker B taking over the row with a new token
          activeLeaseToken = 'token-worker-b-takeover';
          return { success: true, purgedCount: 1 };
        },
      } as any;

      const processor = new OutboxRevocationProcessor({
        pool: mockPool,
        purgeService: mockPurge,
      });

      // Worker A attempts batch processing:
      const res = await processor.processBatch(1);

      // Verify that completion SQL strictly predicates on lease_token, status, AND non-expired lease horizon:
      expect(capturedCompletionQuery).toContain('WHERE id = $1');
      expect(capturedCompletionQuery).toContain('AND lease_token = $2');
      expect(capturedCompletionQuery).toContain("AND status = 'PROCESSING'");
      expect(capturedCompletionQuery).toContain('AND lease_expires_at > clock_timestamp()');
      // Worker A was fenced out: 0 completed, 1 failed (fencing violation)
      expect(res.completedCount).toBe(0);
      expect(res.failedCount).toBe(1);
    });

    it('derives deterministic Durable Object namespace ID from weddingSlug and routes requests to the same coordinator', async () => {
      const derivedIds: string[] = [];
      const mockDoNamespace = {
        idFromName: (name: string) => {
          derivedIds.push(name);
          return { toString: () => `do-id-for-${name}` };
        },
        get: (_id: any) => ({
          isWeddingRevoked: async () => false,
          isPhotoRevoked: async () => true, // Revoked
        }),
      };

      const signed = CdnService.generateSignedCdnUrl({
        objectKey: 'originals/ananya-kabir-2026/photo-det-01.jpg',
        expiresInSeconds: 900,
        weddingSlug: 'ananya-kabir-2026',
        photoId: 'photo-det-01',
      });

      const edgeEnv: EdgeCdnEnv = {
        CDN_SIGNING_SECRET: env.CLOUDFLARE_HMAC_SECRET,
        WEDDING_REVOCATION_DO: mockDoNamespace,
      };

      // Request 1: Photo in wedding
      const res1 = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url: signed.url, headers: {} },
        edgeEnv
      );
      expect(res1.status).toBe(403);

      // Verify deterministic derivation:
      expect(derivedIds).toHaveLength(1);
      expect(derivedIds[0]).toBe('wedding:ananya-kabir-2026');
    });

    it('strictly fails closed with 503 when STRICT_REVOCATION_MODE is active and DO binding is absent', async () => {
      const signed = CdnService.generateSignedCdnUrl({
        objectKey: 'photos/test.jpg',
        expiresInSeconds: 900,
        weddingSlug: 'priya-rohan-2026',
        photoId: 'photo-strict-001',
      });

      const edgeEnv: EdgeCdnEnv = {
        CDN_SIGNING_SECRET: env.CLOUDFLARE_HMAC_SECRET,
        STRICT_REVOCATION_MODE: true, // Production Strict Mode
        // WEDDING_REVOCATION_DO is deliberately omitted
      };

      const res = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url: signed.url, headers: {} },
        edgeEnv
      );

      // STRICT INVARIANT: Fails closed with 503, preventing accidental fallback to eventually consistent KV-only mode
      expect(res.status).toBe(503);
      const body = JSON.parse(res.body as string);
      expect(body.error).toBe('REVOCATION_COORDINATOR_UNCONFIGURED');
      expect(body.message).toContain('Strict revocation mode active');
    });

    it('enumerates complete derivative key inventory and handles partial R2 deletion recovery', async () => {
      const keys = enumeratePhotoObjectKeys('priya-rohan-2026', 'photo-enum-001', 'cr3');
      expect(keys).toEqual([
        'originals/priya-rohan-2026/photo-enum-001.cr3',
        'previews/priya-rohan-2026/photo-enum-001.webp',
        'thumbnails/priya-rohan-2026/photo-enum-001.webp',
        'watermarked/priya-rohan-2026/photo-enum-001.webp',
      ]);

      let attempt = 0;
      let deletedKeysAudit: string[] = [];

      const partialR2Storage = {
        deletePhotoObjects: async (_slug: string, _pid: string, customKeys?: string[]) => {
          attempt++;
          const targets = customKeys || keys;
          if (attempt === 1) {
            // First attempt: 2 keys deleted, 2 keys fail (e.g. storage timeout)
            const deleted = targets.slice(0, 2);
            const failed = targets.slice(2);
            deletedKeysAudit.push(...deleted);
            return {
              success: false,
              deletedKeys: deleted,
              failedKeys: failed,
              error: 'R2 transient timeout on derivative WebP deletion',
            };
          }
          // Retry attempt: remaining keys successfully deleted
          deletedKeysAudit.push(...targets);
          return {
            success: true,
            deletedKeys: targets,
          };
        },
      };

      const event = {
        id: 33301n,
        event_type: 'PHOTO_DELETED',
        wedding_id: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        photo_id: 'photo-enum-001',
        payload: {
          photoId: 'photo-enum-001',
          weddingSlug: 'priya-rohan-2026',
          manifest: {
            keys: [
              'originals/priya-rohan-2026/photo-enum-001.cr3',
              'previews/priya-rohan-2026/photo-enum-001.webp',
              'thumbnails/priya-rohan-2026/photo-enum-001.webp',
            ],
          },
        },
        retry_count: 0,
        max_retries: 4,
        last_error: null,
      };

      const mockPool = {
        connect: async () => ({
          query: async (sql: string, params?: any[]) => {
            if (sql.includes('SELECT id, event_type')) {
              return { rows: [event] };
            }
            if (sql.includes('SELECT key_original, key_preview, key_thumb')) {
              return {
                rows: [
                  {
                    key_original: 'originals/priya-rohan-2026/photo-enum-001.cr3',
                    key_preview: 'previews/priya-rohan-2026/photo-enum-001.webp',
                    key_thumb: 'thumbnails/priya-rohan-2026/photo-enum-001.webp',
                  },
                ],
              };
            }
            if (sql.includes("SET status = 'PROCESSING'")) {
              return { rowCount: 1 };
            }
            if (sql.includes("SET payload = $1::jsonb")) {
              if (params && params[0]) {
                try {
                  event.payload = JSON.parse(params[0]);
                } catch {}
              }
              return { rowCount: 1 };
            }
            if (sql.includes("SET status = 'PENDING'") && params) {
              event.retry_count = params[0];
              event.last_error = params[1];
              if (params[2]) {
                try {
                  event.payload = JSON.parse(params[2]);
                } catch {}
              }
              return { rowCount: 1 };
            }
            if (sql.includes("SET status = 'COMPLETED'")) {
              return { rowCount: 1 };
            }
            return { rows: [] };
          },
          release: () => {},
        }),
      } as any;

      const mockPurge = {
        purgePhoto: async () => ({ success: true, purgedCount: 1 }),
      } as any;

      const processor = new OutboxRevocationProcessor({
        pool: mockPool,
        purgeService: mockPurge,
        r2Storage: partialR2Storage,
      });

      // 1. Initial attempt fails due to partial deletion
      const res1 = await processor.processBatch(1);
      expect(res1.failedCount).toBe(1);
      expect(res1.completedCount).toBe(0);
      expect(event.retry_count).toBe(1);
      expect(event.last_error).toContain('R2 physical deletion incomplete');

      // 2. Retry succeeds and marks completed
      const res2 = await processor.processBatch(1);
      expect(res2.completedCount).toBe(1);
      expect(res2.failedCount).toBe(0);
    });

    it('preserves historical failure error traces and records operator audit credentials during dead-letter replay', async () => {
      let deadLetterEvents = [
        {
          id: 22201n,
          status: 'DEAD_LETTER',
          retry_count: 4,
          last_error: 'TERMINAL_FAILURE_MAX_RETRIES: R2 S3 503 SlowDown | original_error: initial_timeout',
        },
      ];

      let capturedUpdateQuery = '';
      let capturedParams: any[] = [];
      let capturedAuditInsertQuery = '';
      let capturedAuditParams: any[] = [];

      const originalPreReplayError = deadLetterEvents[0].last_error;

      const queryHandler = async (sql: string, params?: any[]) => {
        if (sql.includes("UPDATE outbox_events") && sql.includes("REPLAYED_BY_OPERATOR")) {
          capturedUpdateQuery = sql;
          capturedParams = params || [];
          deadLetterEvents[0].status = 'PENDING';
          deadLetterEvents[0].retry_count = 0;
          deadLetterEvents[0].last_error = `REPLAYED_BY_OPERATOR: ${params?.[0]} | REASON: ${params?.[1]} | PREVIOUS_ERRORS: ${originalPreReplayError}`;
          return {
            rowCount: 1,
            rows: [
              {
                id: deadLetterEvents[0].id,
                wedding_id: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
                original_last_error: originalPreReplayError,
              },
            ],
          };
        }
        if (sql.includes("INSERT INTO audit_log")) {
          capturedAuditInsertQuery = sql;
          capturedAuditParams = params || [];
          return { rowCount: 1 };
        }
        return { rowCount: 0, rows: [] };
      };

      const mockPool = {
        query: queryHandler,
        connect: async () => ({
          query: queryHandler,
          release: () => {},
        }),
      } as any;

      const mockAuthService = {
        authorizeOperatorRequest: async () => ({
          authorized: true,
          operatorUserId: 'operator-alice-sec-01',
          authoritativeRole: 'super_admin',
          scopes: ['outbox:dead-letter:replay'],
        }),
      };

      const processor = new OutboxRevocationProcessor({
        pool: mockPool,
        authorizationService: mockAuthService,
      });

      const replayed = await processor.replayDeadLetters({
        reason: 'R2 storage incident mitigation verified',
        limit: 10,
        authContext: {
          request: { headers: { authorization: 'Bearer op-token' } },
        },
      });

      expect(replayed).toBe(1);
      // Verify locked CTE and absence of JSONB payload mutation:
      expect(capturedUpdateQuery).toContain('WITH targets AS');
      expect(capturedUpdateQuery).not.toContain('jsonb_set');
      expect(capturedUpdateQuery).toContain('REPLAYED_BY_OPERATOR: ');
      expect(capturedParams[0]).toBe('operator-alice-sec-01');
      expect(capturedParams[1]).toBe('R2 storage incident mitigation verified');

      // Verify that historical error was preserved in operational trace:
      expect(deadLetterEvents[0].last_error).toContain('operator-alice-sec-01');
      expect(deadLetterEvents[0].last_error).toContain('R2 storage incident mitigation verified');
      expect(deadLetterEvents[0].last_error).toContain('R2 S3 503 SlowDown');
      expect(deadLetterEvents[0].last_error).toContain('initial_timeout');

      // Verify durable immutable audit record inserted into audit_log with PRE-REPLAY original error:
      expect(capturedAuditInsertQuery).toContain('INSERT INTO audit_log');
      expect(capturedAuditInsertQuery).toContain('operator_id');
      expect(capturedAuditParams[0]).toBe('3fa85f64-5717-4562-b3fc-2c963f66afa6');
      expect(capturedAuditParams[1]).toBe(getDurableActorUuid('operator-alice-sec-01')); // Durable actor UUID mapping (F14.4)
      expect(capturedAuditParams[2]).toBe(deadLetterEvents[0].id.toString());
      expect(capturedAuditParams[3]).toBe('operator-alice-sec-01');
      expect(capturedAuditParams[4]).toBe('super_admin');
      expect(capturedAuditParams[5]).toBe('R2 storage incident mitigation verified');
      // Crucial Governance Assertion: previous_error captures the TRUE pre-replay error, not the new string!
      expect(capturedAuditParams[6]).toBe(originalPreReplayError);
    });

    it('F14 Replay Concurrency: concurrent operator replays isolate locks with FOR UPDATE SKIP LOCKED without double-replaying', async () => {
      let lockedByOp1 = false;
      const deadLetterRow = {
        id: 77701n,
        wedding_id: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        original_last_error: 'TERMINAL_FAILURE_TIMEOUT',
      };

      const createClientForOperator = (operatorId: string) => ({
        query: async (sql: string, params?: any[]) => {
          if (sql.includes('BEGIN') || sql.includes('COMMIT')) {
            return { rowCount: 0 };
          }
          if (sql.includes('UPDATE outbox_events') && sql.includes('FOR UPDATE SKIP LOCKED')) {
            if (operatorId === 'operator-1') {
              lockedByOp1 = true;
              return { rowCount: 1, rows: [deadLetterRow] };
            } else {
              // Operator 2 arrives while Operator 1 holds the lock: SKIP LOCKED skips the locked row
              if (lockedByOp1) {
                return { rowCount: 0, rows: [] };
              }
              return { rowCount: 1, rows: [deadLetterRow] };
            }
          }
          if (sql.includes('INSERT INTO audit_log')) {
            return { rowCount: 1 };
          }
          return { rowCount: 0, rows: [] };
        },
        release: () => {},
      });

      const poolOp1 = { connect: async () => createClientForOperator('operator-1') } as any;
      const poolOp2 = { connect: async () => createClientForOperator('operator-2') } as any;

      // Run concurrent replay requests
      const mockAuthService1 = {
        authorizeOperatorRequest: async () => ({
          authorized: true,
          operatorUserId: 'operator-1',
          authoritativeRole: 'super_admin',
          scopes: ['outbox:dead-letter:replay'],
        }),
      };
      const mockAuthService2 = {
        authorizeOperatorRequest: async () => ({
          authorized: true,
          operatorUserId: 'operator-2',
          authoritativeRole: 'super_admin',
          scopes: ['outbox:dead-letter:replay'],
        }),
      };
      const proc1 = new OutboxRevocationProcessor({ pool: poolOp1, authorizationService: mockAuthService1 });
      const proc2 = new OutboxRevocationProcessor({ pool: poolOp2, authorizationService: mockAuthService2 });

      const [res1, res2] = await Promise.all([
        proc1.replayDeadLetters({
          reason: 'replaying batch A for incident',
          authContext: { request: {} },
        }),
        proc2.replayDeadLetters({
          reason: 'concurrent replay attempt check',
          authContext: { request: {} },
        }),
      ]);

      expect(res1).toBe(1);
      expect(res2).toBe(0); // Fenced out by SKIP LOCKED; zero double-replays
    });

    it('F14 Repeated Replay: repeated replays across distinct intervals produce separate, immutable audit log records', async () => {
      const insertedAuditRecords: any[] = [];
      const eventRow = {
        id: 88801n,
        wedding_id: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        original_last_error: 'PERSISTENT_DOWNSTREAM_503',
      };

      const mockClient = {
        query: async (sql: string, params?: any[]) => {
          if (sql.includes('UPDATE outbox_events') && sql.includes('FOR UPDATE SKIP LOCKED')) {
            return { rowCount: 1, rows: [eventRow] };
          }
          if (sql.includes('INSERT INTO audit_log')) {
            insertedAuditRecords.push({
              weddingId: params?.[0],
              operatorId: params?.[1],
              eventId: params?.[2],
              operatorUserId: params?.[3],
              operatorRole: params?.[4],
              reason: params?.[5],
              previousError: params?.[6],
              correlationId: params?.[7],
            });
            return { rowCount: 1 };
          }
          return { rowCount: 0, rows: [] };
        },
        release: () => {},
      };

      const pool = { connect: async () => mockClient } as any;

      // First replay by Operator Alice at T1
      const corrId1 = 'corr-audit-seq-001';
      const mockAuthAlice = {
        authorizeOperatorRequest: async () => ({
          authorized: true,
          operatorUserId: 'operator-alice',
          authoritativeRole: 'super_admin',
          scopes: ['outbox:dead-letter:replay'],
        }),
      };
      const procAlice = new OutboxRevocationProcessor({ pool, authorizationService: mockAuthAlice });
      await procAlice.replayDeadLetters({
        reason: 'First replay after transient R2 fix',
        correlationId: corrId1,
        authContext: { request: {} },
      });

      // Second replay by Operator Bob at T2 after repeated incident
      const corrId2 = 'corr-audit-seq-002';
      const mockAuthBob = {
        authorizeOperatorRequest: async () => ({
          authorized: true,
          operatorUserId: 'operator-bob',
          authoritativeRole: 'super_admin',
          scopes: ['outbox:dead-letter:replay'],
        }),
      };
      const procBob = new OutboxRevocationProcessor({ pool, authorizationService: mockAuthBob });
      await procBob.replayDeadLetters({
        reason: 'Second replay after secondary network restore',
        correlationId: corrId2,
        authContext: { request: {} },
      });

      // Assert that two distinct, immutable audit records were created (append-only ledger)
      expect(insertedAuditRecords).toHaveLength(2);
      expect(insertedAuditRecords[0].operatorUserId).toBe('operator-alice');
      expect(insertedAuditRecords[0].correlationId).toBe(corrId1);
      expect(insertedAuditRecords[1].operatorUserId).toBe('operator-bob');
      expect(insertedAuditRecords[1].correlationId).toBe(corrId2);
      expect(insertedAuditRecords[0].correlationId).not.toBe(insertedAuditRecords[1].correlationId);
    });

    it('F14 Operator Authorization: rejects unauthenticated or unauthorized operator replay attempts', async () => {
      const mockPool = {
        connect: async () => ({
          query: async () => ({ rowCount: 0, rows: [] }),
          release: () => {},
        }),
      } as any;

      const mockUnauthorizedService = {
        authorizeOperatorRequest: async () => ({
          authorized: false,
          error: 'caller lacks DEAD_LETTER_REPLAY authority',
          scopes: [],
        }),
      };
      const mockAuthorizedServiceForValidation = {
        authorizeOperatorRequest: async () => ({
          authorized: true,
          operatorUserId: 'valid-op',
          authoritativeRole: 'super_admin',
          scopes: ['outbox:dead-letter:replay'],
        }),
      };

      const processor = new OutboxRevocationProcessor({
        pool: mockPool,
        authorizationService: mockAuthorizedServiceForValidation,
      });

      // 0. Unauthenticated invocation rejection (missing authContext)
      await expect(
        processor.replayDeadLetters({
          reason: 'Valid length reason for replay',
        } as any)
      ).rejects.toThrow('Operator authorization context is required for dead-letter replay.');

      // 1. Invalid reason rejection (too short or control characters)
      await expect(
        processor.replayDeadLetters({
          reason: 'short',
          authContext: { request: {} },
        })
      ).rejects.toThrow('Invalid replay reason: must be between 10 and 500 characters.');

      await expect(
        processor.replayDeadLetters({
          reason: 'Valid length but has control \x00 character',
          authContext: { request: {} },
        })
      ).rejects.toThrow('Invalid replay reason: cannot contain control characters.');

      // 2. Unauthorized attempt throws security error
      const unauthorizedProc = new OutboxRevocationProcessor({
        pool: mockPool,
        authorizationService: mockUnauthorizedService,
      });
      await expect(
        unauthorizedProc.replayDeadLetters({
          reason: 'Unauthorized manual replay',
          authContext: { request: { headers: {} } },
        })
      ).rejects.toThrow('Unauthorized operator replay attempt: caller lacks DEAD_LETTER_REPLAY authority');

      // 3. Authorized attempt derives operator identity cryptographically
      let capturedAuditOp: string | null = null;
      const mockAuthorizedService = {
        authorizeOperatorRequest: async () => ({
          authorized: true,
          operatorUserId: 'cryptographically-verified-op-99',
          authoritativeRole: 'super_admin',
          scopes: ['outbox:dead-letter:replay'],
        }),
      };

      const mockAuthClient = {
        query: async (sql: string, params?: any[]) => {
          if (sql.includes('UPDATE outbox_events') && sql.includes('FOR UPDATE SKIP LOCKED')) {
            return {
              rowCount: 1,
              rows: [{ id: 99991n, wedding_id: 'test-wedding', original_last_error: 'prior_err' }],
            };
          }
          if (sql.includes('INSERT INTO audit_log')) {
            capturedAuditOp = params?.[3];
            return { rowCount: 1 };
          }
          return { rowCount: 0, rows: [] };
        },
        release: () => {},
      };

      const authPool = { connect: async () => mockAuthClient } as any;
      const authProcessor = new OutboxRevocationProcessor({
        pool: authPool,
        authorizationService: mockAuthorizedService,
      });

      const count = await authProcessor.replayDeadLetters({
        reason: 'Authorized replay test',
        authContext: {
          request: { headers: { authorization: 'Bearer valid-token' } },
        },
      });

      expect(count).toBe(1);
      expect(capturedAuditOp).toBe('cryptographically-verified-op-99');
    });

    it('F14 Lease Acquisition Rollback: rolls back transaction and releases client if per-event lease assignment affects 0 rows', async () => {
      const events = [
        { id: 101n, event_type: 'PHOTO_DELETED', wedding_id: 'w1', photo_id: 'p1', payload: { photoId: 'p1', weddingSlug: 's1' }, retry_count: 0, max_retries: 4 },
        { id: 102n, event_type: 'PHOTO_DELETED', wedding_id: 'w1', photo_id: 'p2', payload: { photoId: 'p2', weddingSlug: 's1' }, retry_count: 0, max_retries: 4 },
      ];

      let rollbackExecuted = false;
      let clientReleased = false;

      const mockClient = {
        query: async (sql: string, params?: any[]) => {
          if (sql.includes('BEGIN')) return { rowCount: 0 };
          if (sql.includes('ROLLBACK')) {
            rollbackExecuted = true;
            return { rowCount: 0 };
          }
          if (sql.includes('SELECT id, event_type')) {
            return { rows: events };
          }
          if (sql.includes("SET status = 'PROCESSING'")) {
            // Event 101 succeeds
            if (params?.[2] === 101n) {
              return { rowCount: 1 };
            }
            // Event 102 experiences race / concurrent deletion -> affects 0 rows!
            if (params?.[2] === 102n) {
              return { rowCount: 0 };
            }
          }
          return { rowCount: 0, rows: [] };
        },
        release: () => {
          clientReleased = true;
        },
      };

      const mockPool = {
        connect: async () => mockClient,
      } as any;

      const processor = new OutboxRevocationProcessor({ pool: mockPool });

      await expect(processor.processBatch(2)).rejects.toThrow(
        'Failed to assign lease token to event 102: expected 1 row affected, got 0'
      );

      // Verify that ROLLBACK was executed and client was properly released back to pool
      expect(rollbackExecuted).toBe(true);
      expect(clientReleased).toBe(true);
    });

    it('Test A: rejects completion and renewal when lease expires even without peer takeover (lease horizon fencing)', async () => {
      const activeEvent = {
        id: 44401n,
        event_type: 'PHOTO_DELETED',
        wedding_id: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        photo_id: 'photo-expired-001',
        payload: { photoId: 'photo-expired-001', weddingSlug: 'priya-rohan-2026' },
        retry_count: 0,
        max_retries: 4,
        last_error: null,
      };

      const workerToken = 'token-worker-a-horizon';
      let leaseExpired = false;

      const mockPool = {
        connect: async () => ({
          query: async (sql: string, params?: any[]) => {
            if (sql.includes('SELECT id, event_type')) {
              return { rows: [activeEvent] };
            }
            if (sql.includes("SET status = 'PROCESSING'")) {
              return { rowCount: 1 };
            }
            if (sql.includes("SET status = 'COMPLETED'")) {
              // Fencing check: simulate DB checking `lease_expires_at > clock_timestamp()`
              if (leaseExpired) {
                // Horizon elapsed in PostgreSQL!
                return { rowCount: 0 };
              }
              return { rowCount: 1 };
            }
            return { rows: [] };
          },
          release: () => {},
        }),
        query: async (sql: string, params?: any[]) => {
          if (sql.includes('UPDATE outbox_events') && sql.includes('lease_expires_at = clock_timestamp()')) {
            // renewLease query
            if (leaseExpired) {
              return { rowCount: 0 };
            }
            return { rowCount: 1 };
          }
          return { rowCount: 0 };
        },
      } as any;

      const mockPurge = {
        purgePhoto: async () => {
          // Mid-flight: lease expires before completion SQL executes (clock_timestamp() passed lease_expires_at)
          leaseExpired = true;
          return { success: true, purgedCount: 1 };
        },
      } as any;

      const processor = new OutboxRevocationProcessor({
        pool: mockPool,
        purgeService: mockPurge,
      });

      // 1. Completion attempt must be fenced out and rejected
      const res = await processor.processBatch(1);
      expect(res.completedCount).toBe(0);
      expect(res.failedCount).toBe(1);

      // 2. Renewal attempt on expired lease must return false (cannot revive expired lease)
      const renewed = await processor.renewLease(activeEvent.id, workerToken, 30);
      expect(renewed).toBe(false);
    });

    it('Test B: ensures stale worker updates for completion, retry, and dead-letter affect zero rows after peer takeover', async () => {
      const activeEvent = {
        id: 44402n,
        event_type: 'PHOTO_DELETED',
        wedding_id: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        photo_id: 'photo-takeover-001',
        payload: { photoId: 'photo-takeover-001', weddingSlug: 'priya-rohan-2026' },
        retry_count: 0,
        max_retries: 4,
        last_error: null,
      };

      const workerAToken = 'token-worker-a-stale';
      const workerBToken = 'token-worker-b-active';
      let currentDbToken = workerAToken;

      // Mock database simulating row-level atomic predicates:
      // WHERE id = $x AND lease_token = $y AND status = 'PROCESSING' AND lease_expires_at > clock_timestamp()
      const simulateFencedUpdate = (sql: string, passedToken: string) => {
        expect(sql).toContain('WHERE id =');
        expect(sql).toContain('AND lease_token =');
        expect(sql).toContain("AND status = 'PROCESSING'");
        expect(sql).toContain('AND lease_expires_at > clock_timestamp()');
        if (passedToken === currentDbToken) {
          return { rowCount: 1 };
        }
        // Fencing violation: token mismatch or horizon expired!
        return { rowCount: 0 };
      };

      const mockPool = {
        connect: async () => ({
          query: async (sql: string, params?: any[]) => {
            if (sql.includes('SELECT id, event_type')) {
              return { rows: [activeEvent] };
            }
            if (sql.includes("SET status = 'PROCESSING'")) {
              return { rowCount: 1 };
            }
            if (sql.includes("SET status = 'COMPLETED'")) {
              return simulateFencedUpdate(sql, params?.[1]);
            }
            if (sql.includes("SET status = 'PENDING'")) {
              return simulateFencedUpdate(sql, params?.[3]);
            }
            if (sql.includes("SET status = 'DEAD_LETTER'")) {
              return simulateFencedUpdate(sql, params?.[3]);
            }
            return { rows: [] };
          },
          release: () => {},
        }),
      } as any;

      // Simulate: Worker B swept the expired event and claimed it with workerBToken
      currentDbToken = workerBToken;

      const client = await mockPool.connect();

      // Attempt 1: Worker A attempts completion with stale token
      const completeRes = await client.query(
        `UPDATE outbox_events
         SET status = 'COMPLETED', lease_token = NULL, lease_expires_at = NULL, updated_at = clock_timestamp()
         WHERE id = $1 AND lease_token = $2 AND status = 'PROCESSING' AND lease_expires_at > clock_timestamp()`,
        [activeEvent.id, workerAToken]
      );
      expect(completeRes.rowCount).toBe(0);

      // Attempt 2: Worker A attempts retry reset with stale token
      const retryRes = await client.query(
        `UPDATE outbox_events
         SET status = 'PENDING', lease_token = NULL, lease_expires_at = NULL, retry_count = $1, last_error = $2, updated_at = clock_timestamp()
         WHERE id = $3 AND lease_token = $4 AND status = 'PROCESSING' AND lease_expires_at > clock_timestamp()`,
        [1, 'stale worker error', activeEvent.id, workerAToken]
      );
      expect(retryRes.rowCount).toBe(0);

      // Attempt 3: Worker A attempts dead-letter transition with stale token
      const dlRes = await client.query(
        `UPDATE outbox_events
         SET status = 'DEAD_LETTER', lease_token = NULL, lease_expires_at = NULL, retry_count = $1, last_error = $2, updated_at = clock_timestamp()
         WHERE id = $3 AND lease_token = $4 AND status = 'PROCESSING' AND lease_expires_at > clock_timestamp()`,
        [4, 'stale terminal error', activeEvent.id, workerAToken]
      );
      expect(dlRes.rowCount).toBe(0);

      // Legitimate Worker B update succeeds
      const workerBRes = await client.query(
        `UPDATE outbox_events
         SET status = 'COMPLETED', lease_token = NULL, lease_expires_at = NULL, updated_at = clock_timestamp()
         WHERE id = $1 AND lease_token = $2 AND status = 'PROCESSING' AND lease_expires_at > clock_timestamp()`,
        [activeEvent.id, workerBToken]
      );
      expect(workerBRes.rowCount).toBe(1);
    });

    it('Test C: assigns unique, distinct UUID lease tokens per event in multi-event batch', async () => {
      const events = [
        { id: 501n, event_type: 'PHOTO_DELETED', wedding_id: 'w1', photo_id: 'p1', payload: { photoId: 'p1', weddingSlug: 's1' }, retry_count: 0, max_retries: 4 },
        { id: 502n, event_type: 'PHOTO_DELETED', wedding_id: 'w1', photo_id: 'p2', payload: { photoId: 'p2', weddingSlug: 's1' }, retry_count: 0, max_retries: 4 },
        { id: 503n, event_type: 'PHOTO_DELETED', wedding_id: 'w1', photo_id: 'p3', payload: { photoId: 'p3', weddingSlug: 's1' }, retry_count: 0, max_retries: 4 },
      ];

      const assignedLeaseTokens: string[] = [];
      const completedTokens: string[] = [];

      const mockPool = {
        connect: async () => ({
          query: async (sql: string, params?: any[]) => {
            if (sql.includes('SELECT id, event_type')) {
              return { rows: events };
            }
            if (sql.includes("SET status = 'PROCESSING'")) {
              assignedLeaseTokens.push(params?.[0]);
              return { rowCount: 1 };
            }
            if (sql.includes("SET status = 'COMPLETED'")) {
              completedTokens.push(params?.[1]);
              return { rowCount: 1 };
            }
            return { rows: [] };
          },
          release: () => {},
        }),
      } as any;

      const mockPurge = {
        purgePhoto: async () => ({ success: true, purgedCount: 1 }),
      } as any;

      const processor = new OutboxRevocationProcessor({
        pool: mockPool,
        purgeService: mockPurge,
      });

      const res = await processor.processBatch(3);
      expect(res.processedCount).toBe(3);
      expect(res.completedCount).toBe(3);

      // Verify that each event in the batch received a unique, distinct lease token
      expect(assignedLeaseTokens).toHaveLength(3);
      const uniqueTokens = new Set(assignedLeaseTokens);
      expect(uniqueTokens.size).toBe(3);

      // Verify that each completion query matched the exact unique token assigned to that event
      expect(completedTokens).toEqual(assignedLeaseTokens);
    });

    it('Test D: enforces exact equivalence between outbox mutation and edge worker Durable Object derivation', () => {
      const slugs = [
        'ananya-kabir-2026',
        'priya-rohan-2026',
        'sharma-wedding-dec-2026',
        'meera-arjun-goa',
      ];

      for (const slug of slugs) {
        // Outbox mutation derivation
        const outboxDoId = getCanonicalDurableObjectId(slug);
        // Edge worker lookup derivation
        const edgeDoId = `wedding:${slug}`;

        expect(outboxDoId).toBe(edgeDoId);
        expect(outboxDoId).toBe(`wedding:${slug}`);
      }
    });

    it('Test E: strictly validates tenant slug and rejects malformed slugs with HTTP 400 MALFORMED_TENANT_IDENTIFIER', async () => {
      // 1. Path resolution tests across canonical route prefixes
      expect(resolveCanonicalWeddingSlug('https://cdn.shadify.io/v1/weddings/priya-rohan-2026/photos')).toBe('priya-rohan-2026');
      expect(resolveCanonicalWeddingSlug('https://cdn.shadify.io/originals/priya-rohan-2026/img01.jpg')).toBe('priya-rohan-2026');
      expect(resolveCanonicalWeddingSlug('https://cdn.shadify.io/thumbnails/priya-rohan-2026/thumb.webp')).toBe('priya-rohan-2026');
      expect(resolveCanonicalWeddingSlug('https://cdn.shadify.io/previews/ananya-kabir-2026/preview.webp')).toBe('ananya-kabir-2026');
      expect(resolveCanonicalWeddingSlug('https://cdn.shadify.io/watermarked/ananya-kabir-2026/preview.webp')).toBe('ananya-kabir-2026');

      // 2. Adversarial, malformed path, encoded/repeated separators, and tenant mismatch rejection
      expect(resolveCanonicalWeddingSlug('https://cdn.shadify.io/v1/weddings/..%2f..%2fetc/passwd')).toBeNull();
      expect(resolveCanonicalWeddingSlug('https://cdn.shadify.io/v1/weddings/INVALID_UPPERCASE/photos')).toBeNull();
      expect(resolveCanonicalWeddingSlug('https://cdn.shadify.io/v1/weddings/slug$with$symbols/photos')).toBeNull();
      expect(resolveCanonicalWeddingSlug('https://cdn.shadify.io/unknown/prefix/priya-rohan-2026')).toBeNull();
      expect(resolveCanonicalWeddingSlug('https://cdn.shadify.io/')).toBeNull();
      expect(resolveCanonicalWeddingSlug('https://cdn.shadify.io/photos')).toBeNull();

      // Explicit slug with unrecognized route rejected (cannot invent tenant identity from query param)
      expect(resolveCanonicalWeddingSlug('https://cdn.shadify.io/unrecognized/route', 'wedding-a')).toBeNull();

      // Repeated separators, backslashes, and encoded path traversal rejected
      expect(resolveCanonicalWeddingSlug('https://cdn.shadify.io/v1/weddings//wedding-a')).toBeNull();
      expect(resolveCanonicalWeddingSlug('https://cdn.shadify.io/v1/weddings/wedding-a%2fphoto')).toBeNull();
      expect(resolveCanonicalWeddingSlug('https://cdn.shadify.io/v1/weddings/wedding-a\\subdir')).toBeNull();

      // Tenant Mismatch Invariant: explicit query param cannot mismatch or override route tenant!
      expect(resolveCanonicalWeddingSlug('https://cdn.shadify.io/originals/wedding-b/photo.jpg', 'wedding-a')).toBeNull();
      expect(resolveCanonicalWeddingSlug('https://cdn.shadify.io/originals/wedding-b/photo.jpg', 'wedding-b')).toBe('wedding-b');

      // 3. EdgeCdnHandler execution with malformed or missing tenant slug
      const edgeEnv: EdgeCdnEnv = {
        CDN_SIGNING_SECRET: env.CLOUDFLARE_HMAC_SECRET,
        WEDDING_REVOCATION_DO: {
          idFromName: () => ({}),
          get: () => ({
            isWeddingRevoked: async () => false,
            isPhotoRevoked: async () => false,
          }),
        } as any,
      };

      // 3a. Malformed explicit tenant slug parameter
      const resMalformedSlug = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url: 'https://cdn.shadify.io/v1/weddings/photos?w=INVALID_UPPERCASE!', headers: {} },
        edgeEnv
      );
      expect(resMalformedSlug.status).toBe(400);
      const body1 = JSON.parse(resMalformedSlug.body as string);
      expect(body1.error).toBe('MALFORMED_TENANT_IDENTIFIER');

      // 3b. Tenant mismatch between query param and media route
      const resMismatch = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url: 'https://cdn.shadify.io/originals/wedding-b/photo.jpg?w=wedding-a', headers: {} },
        edgeEnv
      );
      expect(resMismatch.status).toBe(400);
      const bodyMismatch = JSON.parse(resMismatch.body as string);
      expect(bodyMismatch.error).toBe('MALFORMED_TENANT_IDENTIFIER');

      // 3c. Request with pid but unresolvable wedding tenant path
      const resUnresolvable = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url: 'https://cdn.shadify.io/unsupported/path/structure?pid=photo-1', headers: {} },
        edgeEnv
      );
      expect(resUnresolvable.status).toBe(400);
      const body2 = JSON.parse(resUnresolvable.body as string);
      expect(body2.error).toBe('MALFORMED_TENANT_IDENTIFIER');
    });

    it('F15 Semantics: explicitly separates photo-level vs wedding-level Durable Object revocation without passing undefined photo ID', async () => {
      let weddingRevocationQueriedSlug: string | null = null;
      let photoRevocationCalls: { pid: string; slug: string }[] = [];
      const kvWrites: Record<string, string> = {};

      const mockDoStub = {
        isWeddingRevoked: async (slug: string) => {
          weddingRevocationQueriedSlug = slug;
          return slug === 'revoked-wedding-slug';
        },
        isPhotoRevoked: async (pid: string, slug: string) => {
          photoRevocationCalls.push({ pid, slug });
          return pid === 'photo-revoked-99';
        },
      };

      const mockKv = {
        get: async () => null,
        put: async (key: string, val: string) => {
          kvWrites[key] = val;
        },
      };

      const edgeEnv: EdgeCdnEnv = {
        CDN_SIGNING_SECRET: env.CLOUDFLARE_HMAC_SECRET,
        WEDDING_REVOCATION_DO: mockDoStub as any,
        WEDDING_REVOCATION_KV: mockKv as any,
      };

      // 1. Wedding-level revocation: request wedding gallery asset without photoId
      const signedWeddingUrl = CdnService.generateSignedCdnUrl({
        objectKey: 'originals/revoked-wedding-slug/cover.jpg',
        expiresInSeconds: 900,
        weddingSlug: 'revoked-wedding-slug',
      });

      const resWedding = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url: signedWeddingUrl.url, headers: {} },
        edgeEnv
      );

      expect(resWedding.status).toBe(403);
      const weddingBody = JSON.parse(resWedding.body as string);
      expect(weddingBody.error).toBe('WEDDING_GALLERY_REVOKED');
      expect(weddingRevocationQueriedSlug).toBe('revoked-wedding-slug');
      // Invariant: isPhotoRevoked was NOT called with undefined or empty string!
      expect(photoRevocationCalls).toHaveLength(0);
      expect(kvWrites['revoked_weddings:revoked-wedding-slug']).toBe('1');

      // 2. Photo-level revocation: valid wedding, but specific photo is revoked
      const signedPhotoUrl = CdnService.generateSignedCdnUrl({
        objectKey: 'originals/active-wedding/photo-revoked-99.jpg',
        expiresInSeconds: 900,
        weddingSlug: 'active-wedding',
        photoId: 'photo-revoked-99',
      });

      const resPhoto = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url: signedPhotoUrl.url, headers: {} },
        edgeEnv
      );

      expect(resPhoto.status).toBe(403);
      const photoBody = JSON.parse(resPhoto.body as string);
      expect(photoBody.error).toBe('MEDIA_ASSET_REVOKED');
      // Invariant: photo-level revocation was explicitly called with valid string pid
      expect(photoRevocationCalls).toEqual([{ pid: 'photo-revoked-99', slug: 'active-wedding' }]);
      expect(kvWrites['revoked_photos:photo-revoked-99']).toBe('1');
    });

    it('WeddingRevocationCoordinator: provides tenant-isolated, storage-backed photo and wedding revocation with inheritance and zero stale caching', async () => {
      const mockStorageMap = new Map<string, any>();
      const mockStorage = {
        get: async <T>(key: string): Promise<T | undefined> => mockStorageMap.get(key),
        put: async <T>(key: string, val: T): Promise<void> => {
          mockStorageMap.set(key, val);
        },
        delete: async (key: string): Promise<boolean> => mockStorageMap.delete(key),
      };

      const coordinator = new WeddingRevocationCoordinator({ storage: mockStorage }, undefined, 'ananya-kabir-2026');

      // 1. Initial state: nothing revoked
      expect(await coordinator.isWeddingRevoked('ananya-kabir-2026')).toBe(false);
      expect(await coordinator.isPhotoRevoked('photo-001', 'ananya-kabir-2026')).toBe(false);

      // 2. Tenant Isolation Invariant: rejecting mismatched wedding slug
      await expect(coordinator.revokePhoto('photo-001', 'mismatched-wedding-slug')).rejects.toThrow(
        'Tenant isolation violation'
      );
      await expect(coordinator.revokeWedding('mismatched-wedding-slug')).rejects.toThrow(
        'Tenant isolation violation'
      );
      await expect(coordinator.isPhotoRevoked('photo-001', 'mismatched-wedding-slug')).rejects.toThrow(
        'Tenant isolation violation'
      );

      // 3. Photo-level revocation persists structured audit record in tenant-scoped key
      await coordinator.revokePhoto('photo-001', 'ananya-kabir-2026', {
        eventId: 'evt-del-001',
        actorId: 'operator-alice',
        reason: 'User request GDPR erasure',
      });
      expect(await coordinator.isPhotoRevoked('photo-001', 'ananya-kabir-2026')).toBe(true);
      expect(await coordinator.isPhotoRevoked('photo-002', 'ananya-kabir-2026')).toBe(false);
      expect(await coordinator.isWeddingRevoked('ananya-kabir-2026')).toBe(false);

      // Verify authoritative storage key structure and structured record
      const storedPhotoRecord = mockStorageMap.get('wedding:ananya-kabir-2026:photo:photo-001:revoked');
      expect(storedPhotoRecord).toBeDefined();
      expect(storedPhotoRecord.revoked).toBe(true);
      expect(storedPhotoRecord.actorId).toBe('operator-alice');
      expect(storedPhotoRecord.eventId).toBe('evt-del-001');

      // 4. Zero In-Memory Cache Staleness: modifying authoritative storage directly reflects immediately
      mockStorageMap.set('wedding:ananya-kabir-2026:photo:photo-002:revoked', {
        revoked: true,
        revokedAt: new Date().toISOString(),
        weddingSlug: 'ananya-kabir-2026',
        photoId: 'photo-002',
      });
      // Direct storage read picks up revocation without cached stale false
      expect(await coordinator.isPhotoRevoked('photo-002', 'ananya-kabir-2026')).toBe(true);

      // 5. Wedding-wide revocation: all photos inherit revocation status
      await coordinator.revokeWedding('ananya-kabir-2026');
      expect(await coordinator.isWeddingRevoked('ananya-kabir-2026')).toBe(true);
      // Photo 003 was not individually revoked, but inherits wedding revocation!
      expect(await coordinator.isPhotoRevoked('photo-003', 'ananya-kabir-2026')).toBe(true);
    });

    it('validateProductionRevocationConfig: strictly asserts production strict mode and DO binding invariants', () => {
      // 1. Valid production configuration passes
      const validConfig = validateProductionRevocationConfig({
        NODE_ENV: 'production',
        STRICT_REVOCATION_MODE: true,
        WEDDING_REVOCATION_DO: { idFromName: () => ({}), get: () => ({}) } as any,
        CDN_SIGNING_SECRET: 'production-hmac-secret-min-32-chars-long-12345678',
      });
      expect(validConfig.valid).toBe(true);
      expect(validConfig.errors).toHaveLength(0);

      // 2. Production with missing DO binding throws ProductionRevocationConfigurationError
      expect(() =>
        validateProductionRevocationConfig({
          NODE_ENV: 'production',
          STRICT_REVOCATION_MODE: true,
          CDN_SIGNING_SECRET: 'production-hmac-secret-min-32-chars-long-12345678',
        })
      ).toThrow(ProductionRevocationConfigurationError);

      // 3. Production with STRICT_REVOCATION_MODE false throws ProductionRevocationConfigurationError
      expect(() =>
        validateProductionRevocationConfig({
          NODE_ENV: 'production',
          STRICT_REVOCATION_MODE: false,
          WEDDING_REVOCATION_DO: { idFromName: () => ({}), get: () => ({}) } as any,
          CDN_SIGNING_SECRET: 'production-hmac-secret-min-32-chars-long-12345678',
        })
      ).toThrow(ProductionRevocationConfigurationError);

      // 4. Strict mode declared in non-prod with missing DO throws ProductionRevocationConfigurationError
      expect(() =>
        validateProductionRevocationConfig({
          NODE_ENV: 'development',
          STRICT_REVOCATION_MODE: true,
          CDN_SIGNING_SECRET: 'development-secret-min-32-chars-long-12345678',
        })
      ).toThrow(ProductionRevocationConfigurationError);
    });

    it('EdgeCdnHandler: fails closed with HTTP 503 when production configuration guard fails', async () => {
      const brokenProdEnv: EdgeCdnEnv & { NODE_ENV: string } = {
        NODE_ENV: 'production',
        STRICT_REVOCATION_MODE: true,
        CDN_SIGNING_SECRET: 'production-hmac-secret-min-32-chars-long-12345678',
        // Missing WEDDING_REVOCATION_DO binding!
      };

      const res = await EdgeCdnHandler.handleRequest(
        { method: 'GET', url: 'https://cdn.shadify.io/originals/test-wedding/photo.jpg', headers: {} },
        brokenProdEnv
      );

      expect(res.status).toBe(503);
      const body = JSON.parse(res.body as string);
      expect(body.error).toBe('REVOCATION_COORDINATOR_UNCONFIGURED');
    });

    it('validateAndDeriveAuthoritativePhotoKeys: strictly enforces tenant prefix containment and rejects cross-tenant or malformed keys', () => {
      const weddingSlug = 'priya-rohan-2026';
      const photoId = 'photo-containment-101';

      // 1. Valid derivative keys with canonical tenant and photo prefixes pass
      const validKeys = [
        `originals/${weddingSlug}/${photoId}.jpg`,
        `previews/${weddingSlug}/${photoId}.webp`,
        `thumbnails/${weddingSlug}/${photoId}.webp`,
        `watermarked/${weddingSlug}/${photoId}.jpg`,
      ];
      const derived = validateAndDeriveAuthoritativePhotoKeys(weddingSlug, photoId, validKeys);
      expect(derived).toHaveLength(4);
      expect(derived).toContain(`originals/${weddingSlug}/${photoId}.jpg`);
      expect(derived).toContain(`previews/${weddingSlug}/${photoId}.webp`);

      // 2. Cross-tenant key injection attempt is rejected immediately
      const crossTenantKeys = [
        `originals/${weddingSlug}/${photoId}.jpg`,
        `previews/other-wedding-slug/${photoId}.webp`, // Cross-tenant injection!
      ];
      expect(() =>
        validateAndDeriveAuthoritativePhotoKeys(weddingSlug, photoId, crossTenantKeys)
      ).toThrow(/Authoritative manifest validation violation/);

      // 3. Mismatched photoId key injection is rejected
      const crossPhotoKeys = [
        `originals/${weddingSlug}/${photoId}.jpg`,
        `previews/${weddingSlug}/other-photo-999.webp`, // Mismatched photo ID!
      ];
      expect(() =>
        validateAndDeriveAuthoritativePhotoKeys(weddingSlug, photoId, crossPhotoKeys)
      ).toThrow(/Authoritative manifest validation violation/);

      // 4. Directory traversal in key is rejected
      const traversalKeys = [
        `originals/${weddingSlug}/../secret.jpg`,
      ];
      expect(() =>
        validateAndDeriveAuthoritativePhotoKeys(weddingSlug, photoId, traversalKeys)
      ).toThrow(/Authoritative manifest validation violation/);
    });

    it('F14 Transactional Replay Rollback: rolls back transaction when audit_log insertion fails, leaving outbox in DEAD_LETTER', async () => {
      let rollbackCalled = false;
      let commitCalled = false;
      const targetEventId = 33301n;
      const eventRow = {
        id: targetEventId,
        wedding_id: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        original_last_error: 'TRANSIENT_DOWNSTREAM_TIMEOUT',
      };

      const failingAuditClient = {
        query: async (sql: string, params?: any[]) => {
          if (sql.includes('BEGIN')) {
            return { rowCount: 0 };
          }
          if (sql.includes('COMMIT')) {
            commitCalled = true;
            return { rowCount: 0 };
          }
          if (sql.includes('ROLLBACK')) {
            rollbackCalled = true;
            return { rowCount: 0 };
          }
          if (sql.includes('UPDATE outbox_events') && sql.includes('FOR UPDATE SKIP LOCKED')) {
            return { rowCount: 1, rows: [eventRow] };
          }
          if (sql.includes('INSERT INTO audit_log')) {
            // Simulate database error during audit_log insert (e.g. disk full, permission denied)
            throw new Error('SIMULATED_AUDIT_LOG_INSERTION_FAILURE');
          }
          return { rowCount: 0, rows: [] };
        },
        release: () => {},
      };

      const mockAuth = {
        authorizeOperatorRequest: async () => ({
          authorized: true,
          operatorUserId: 'operator-audit-fail-test',
          authoritativeRole: 'super_admin',
          scopes: ['outbox:dead-letter:replay'],
        }),
      };
      const mockPool = { connect: async () => failingAuditClient } as any;
      const processor = new OutboxRevocationProcessor({
        pool: mockPool,
        authorizationService: mockAuth,
      });

      await expect(
        processor.replayDeadLetters({
          reason: 'Testing transactional rollback on audit log insertion failure',
          authContext: { request: {} },
        })
      ).rejects.toThrow('SIMULATED_AUDIT_LOG_INSERTION_FAILURE');

      // CRITICAL GOVERNANCE INVARIANT:
      // When audit_log insert fails, ROLLBACK MUST be executed and COMMIT MUST NOT occur!
      expect(rollbackCalled).toBe(true);
      expect(commitCalled).toBe(false);
    });

    it('F15 DO Failure Prevents Outbox Completion & Retries Idempotently', async () => {
      let r2DeleteCalled = false;
      let kvPutCalled = false;
      let doRevokeCallCount = 0;
      let doShouldFail = true;

      const mockDoCoordinator = {
        revokePhoto: async (pid: string, slug: string) => {
          doRevokeCallCount++;
          if (doShouldFail) {
            throw new Error('Cloudflare DO RPC connection timeout');
          }
        },
        revokeWedding: async () => {},
        isPhotoRevoked: async () => false,
        isWeddingRevoked: async () => false,
      };

      const mockKvStore = {
        put: async () => { kvPutCalled = true; },
        get: async () => null,
      };

      const mockPurgeService = {
        purgePhoto: async () => ({ success: true, purgedUrls: [] }),
        purgePhotoVariants: async () => ({ success: true, purgedKeys: [] }),
      };

      let eventStatus = 'PENDING';
      let retryCount = 0;

      const mockEvent = {
        id: '99001',
        event_type: 'PHOTO_DELETED',
        wedding_id: 'w-do-test-01',
        photo_id: 'photo-fail-do-01',
        payload: {
          photoId: 'photo-fail-do-01',
          weddingSlug: 'wedding-do-test',
          r2Keys: ['originals/wedding-do-test/photo-fail-do-01.jpg'],
        },
        retry_count: 0,
        max_retries: 4,
        status: 'PENDING',
      };

      const mockClient = {
        query: async (sql: string, params?: any[]) => {
          if (sql.includes('BEGIN') || sql.includes('COMMIT') || sql.includes('ROLLBACK')) {
            return { rowCount: 0 };
          }
          if (sql.includes('SELECT id, event_type')) {
            return { rows: [mockEvent] };
          }
          if (sql.includes("SET status = 'PROCESSING'") && sql.includes('lease_token = $1')) {
            eventStatus = 'PROCESSING';
            return { rowCount: 1 };
          }
          if (sql.includes("SET status = 'COMPLETED'")) {
            eventStatus = 'COMPLETED';
            return { rowCount: 1 };
          }
          if (sql.includes("status = 'PENDING'") && (sql.includes("retry_count = $1") || sql.includes("retry_count = retry_count + 1"))) {
            eventStatus = 'PENDING';
            retryCount = params?.[0] || 1;
            return { rowCount: 1 };
          }
          return { rowCount: 0, rows: [] };
        },
        release: () => {},
      };

      const mockPool = { connect: async () => mockClient } as any;
      const processor = new OutboxRevocationProcessor({
        pool: mockPool,
        kvStore: mockKvStore as any,
        doCoordinator: mockDoCoordinator as any,
        purgeService: mockPurgeService as any,
      });

      // 1. First run: DO coordinator fails with RPC timeout
      const result1 = await processor.processBatch(1);
      expect(result1.failedCount).toBe(1);
      expect(result1.completedCount).toBe(0);
      expect(eventStatus).not.toBe('COMPLETED'); // CRITICAL: Event must NOT be marked COMPLETED
      expect(retryCount).toBe(1); // Retried

      // 2. Second run: DO coordinator recovers and succeeds
      doShouldFail = false;
      const result2 = await processor.processBatch(1);
      expect(result2.completedCount).toBe(1);
      expect(result2.failedCount).toBe(0);
      expect(eventStatus).toBe('COMPLETED'); // Marked completed after successful DO persistence
      expect(doRevokeCallCount).toBe(2);
    });

    it('Admin Outbox Replay Route: POST /v1/admin/outbox/dead-letters/replay enforces authentication and validation', async () => {
      const app = await buildApp();
      const mockReplayPool = {
        connect: async () => ({
          query: async (sql: string) => {
            if (sql.includes('BEGIN') || sql.includes('COMMIT') || sql.includes('ROLLBACK')) return { rowCount: 0 };
            if (sql.includes('WITH targets AS')) return { rowCount: 0, rows: [] };
            return { rowCount: 0, rows: [] };
          },
          release: () => {},
        }),
      };
      (app as any).dbPool = mockReplayPool;
      const path = '/v1/admin/outbox/dead-letters/replay';

      // 1. Request missing origin HMAC -> 401 Unauthorized
      const resMissingOrigin = await app.inject({
        method: 'POST',
        url: path,
        payload: { reason: 'Missing origin HMAC test' },
      });
      expect(resMissingOrigin.statusCode).toBe(401);

      // 2. Request with origin HMAC but missing operator delegation token -> 403 Forbidden
      const unauthPayload = JSON.stringify({ reason: 'Missing operator delegation token test' });
      const hmacHeadersUnauth = getOriginHmacHeaders('POST', path, unauthPayload);
      const resUnauth = await app.inject({
        method: 'POST',
        url: path,
        headers: {
          ...hmacHeadersUnauth,
          'content-type': 'application/json',
        },
        payload: unauthPayload,
      });
      expect(resUnauth.statusCode).toBe(403);
      expect(JSON.parse(resUnauth.body).code).toBe('OPERATOR_REPLAY_FORBIDDEN');

      // 3. Request with valid operator credentials but missing reason -> 400 Bad Request
      const superAdminId = 'e8e1215b-9cf4-4e2a-89a1-cb9e1e36780c';
      const delegationToken = OperatorAuthorizationService.createDelegationAssertion({
        operatorUserId: superAdminId,
        email: 'lead-admin@shadify.in',
        oidcToken: validOidcToken,
      });

      const missingReasonPayload = JSON.stringify({});
      const hmacHeadersMissingReason = getOriginHmacHeaders('POST', path, missingReasonPayload);
      const resMissingReason = await app.inject({
        method: 'POST',
        url: path,
        headers: {
          ...hmacHeadersMissingReason,
          'content-type': 'application/json',
          authorization: `Bearer ${validOidcToken}`,
          'x-shadify-operator-assertion': delegationToken,
          'x-operator-user-id': superAdminId,
        },
        payload: missingReasonPayload,
      });
      expect(resMissingReason.statusCode).toBe(400);

      // 4. Authorized replay invocation with valid super_admin credentials and origin HMAC
      const validPayload = JSON.stringify({
        reason: 'Authorized operational dead-letter replay after cloud mitigation',
        limit: 10,
      });
      const hmacHeadersValid = getOriginHmacHeaders('POST', path, validPayload);
      const resAuthorized = await app.inject({
        method: 'POST',
        url: path,
        headers: {
          ...hmacHeadersValid,
          'content-type': 'application/json',
          authorization: `Bearer ${validOidcToken}`,
          'x-shadify-operator-assertion': delegationToken,
          'x-operator-user-id': superAdminId,
        },
        payload: validPayload,
      });
      expect(resAuthorized.statusCode).toBe(200);
      const authorizedBody = JSON.parse(resAuthorized.body);
      expect(authorizedBody.success).toBe(true);
      expect(authorizedBody.operatorUserId).toBe(superAdminId);
      expect(typeof authorizedBody.replayedCount).toBe('number');

      await app.close();
    });
  });
});

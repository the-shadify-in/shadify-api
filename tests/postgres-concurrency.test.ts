import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import pg from 'pg';
import crypto from 'node:crypto';
import {
  OperatorAuthorizationService,
  PostgresJtiStore,
  PostgresRevocationStore,
} from '../src/services/admin-auth.js';
import {
  GuestAuthorizationService,
  PostgresGuestRateLimiter,
  PostgresGuestRevocationStore,
} from '../src/services/guest-auth.js';
import {
  OutboxRevocationProcessor,
  StaleLeaseFencingError,
} from '../src/services/outbox-processor.js';

describe('Real PostgreSQL Integration: Concurrency & Transaction Boundaries (F09)', () => {
  let pool: pg.Pool;
  let testWeddingId: string;

  beforeAll(async () => {
    // Connect to the isolated disposable PostgreSQL cluster on port 5433
    pool = new pg.Pool({
      host: '127.0.0.1',
      port: 5433,
      user: 'cvs',
      database: process.env.PGDATABASE || 'shadify_migrated_test',
      max: 10,
    });

    // Seed test wedding and entitlement
    const uniqueSlug = 'rohan-priya-concurrency-' + Date.now();
    let client: pg.PoolClient | undefined;
    try {
      client = await pool.connect();
      const weddingRes = await client.query(
        `INSERT INTO weddings (slug, bride_name, groom_name, wedding_date, status) 
         VALUES ($1, 'Priya', 'Rohan', '2026-12-15', 'published') 
         RETURNING id`,
        [uniqueSlug]
      );
      testWeddingId = weddingRes.rows[0].id;

      await client.query(
        `INSERT INTO entitlements (wedding_id, storage_allocated_bytes, storage_used_bytes, photo_count_used, hosting_until)
         VALUES ($1, 53687091200, 0, 0, NOW() + INTERVAL '1 year')`,
        [testWeddingId]
      );
    } catch (err: any) {
      if (err.code === 'EPERM' || err.message?.includes('EPERM')) {
        console.warn('Skipping PostgreSQL concurrency suite: loopback port 5433 blocked by sandbox network isolation');
        return;
      }
      throw err;
    } finally {
      if (client) client.release();
    }
  });

  beforeEach((ctx) => {
    if (!testWeddingId) {
      ctx.skip();
    }
  });

  afterAll(async () => {
    await pool.end();
  });

  it('handles two simultaneous completion requests across separate database connections with exact 1 Photo & 1 Quota settlement', async () => {
    // 1. Create a reserved upload session
    const clientInit = await pool.connect();
    let sessionId: string;
    try {
      const sessionRes = await clientInit.query(
        `INSERT INTO upload_sessions (wedding_id, expected_bytes, object_key, status, expires_at)
         VALUES ($1, 20971520, 'raw-uploads/test/original', 'RESERVED', NOW() + INTERVAL '30 minutes')
         RETURNING id`,
        [testWeddingId]
      );
      sessionId = sessionRes.rows[0].id;
    } finally {
      clientInit.release();
    }

    // 2. Open two distinct physical database connections
    const conn1 = await pool.connect();
    const conn2 = await pool.connect();

    const photoHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    try {
      // 3. Fire concurrent complete_upload_session transactions simultaneously
      const [res1, res2] = await Promise.all([
        conn1.query(
          `SELECT out_photo_id, out_wedding_id, out_actual_bytes, out_recovered 
           FROM public.complete_upload_session($1::bigint, $2::bigint, $3::text)`,
          [sessionId, 20971520, photoHash]
        ),
        conn2.query(
          `SELECT out_photo_id, out_wedding_id, out_actual_bytes, out_recovered 
           FROM public.complete_upload_session($1::bigint, $2::bigint, $3::text)`,
          [sessionId, 20971520, photoHash]
        ),
      ]);

      const row1 = res1.rows[0];
      const row2 = res2.rows[0];

      // Both connections must receive the exact same photo_id
      expect(row1.out_photo_id).toBe(row2.out_photo_id);

      // Exactly one must be the primary creator (out_recovered = false), and the other must be recovered (true)
      const recoveredFlags = [row1.out_recovered, row2.out_recovered].sort();
      expect(recoveredFlags).toEqual([false, true]);

      // 4. Verify in PostgreSQL that exactly ONE photo record exists
      const photoCheck = await pool.query(
        `SELECT count(*)::int as count FROM photos WHERE upload_session_id = $1`,
        [sessionId]
      );
      expect(photoCheck.rows[0].count).toBe(1);

      // 5. Verify that quota was settled exactly ONCE
      const entitlementCheck = await pool.query(
        `SELECT storage_used_bytes, photo_count_used FROM entitlements WHERE wedding_id = $1`,
        [testWeddingId]
      );
      expect(entitlementCheck.rows[0].storage_used_bytes).toBe('20971520');
      expect(entitlementCheck.rows[0].photo_count_used).toBe(1);
    } finally {
      conn1.release();
      conn2.release();
    }
  });

  it('rejects completion on a cancelled session', async () => {
    const client = await pool.connect();
    try {
      const sessionRes = await client.query(
        `INSERT INTO upload_sessions (wedding_id, expected_bytes, object_key, status, expires_at)
         VALUES ($1, 10485760, 'raw-uploads/test/abort-race', 'CANCELLED', NOW() + INTERVAL '30 minutes')
         RETURNING id`,
        [testWeddingId]
      );
      const sessionId = sessionRes.rows[0].id;

      await expect(
        client.query(
          `SELECT * FROM public.complete_upload_session($1::bigint, $2::bigint, $3::text)`,
          [sessionId, 10485760, 'hash1234567890123456789012345678901234567890123456789012345678901234']
        )
      ).rejects.toThrow(/CANCELLED/);
    } finally {
      client.release();
    }
  });

  it('fails explicitly with error if session is marked COMPLETED but corresponding photo row is missing (F09 regression)', async () => {
    const client = await pool.connect();
    try {
      const sessionRes = await client.query(
        `INSERT INTO upload_sessions (wedding_id, expected_bytes, object_key, status, expires_at)
         VALUES ($1, 5242880, 'raw-uploads/test/orphan-completed', 'COMPLETED', NOW() + INTERVAL '30 minutes')
         RETURNING id`,
        [testWeddingId]
      );
      const orphanSessionId = sessionRes.rows[0].id;

      // Invoking complete_upload_session must throw CORRUPT_STATE rather than returning a null photo ID
      await expect(
        client.query(
          `SELECT * FROM public.complete_upload_session($1::bigint, $2::bigint, $3::text)`,
          [orphanSessionId, 5242880, 'hashorphansession123456789012345678901234567890123456789012345678']
        )
      ).rejects.toThrow(/CORRUPT_STATE: Completed upload session \d+ has no associated photo record/);
    } finally {
      client.release();
    }
  });

  it('allows distinct upload sessions with identical content to create distinct photos without colliding', async () => {
    const identicalHash = crypto
      .createHash('sha256')
      .update('identical-content-' + Date.now() + Math.random())
      .digest('hex');

    const client = await pool.connect();
    try {
      // Create a second wedding to test cross-tenant identical content isolation
      const w2Res = await client.query(
        `INSERT INTO weddings (slug, bride_name, groom_name, wedding_date, status) 
         VALUES ($1, 'Aarti', 'Vikram', '2026-12-20', 'published') 
         RETURNING id`,
        ['aarti-vikram-' + Date.now()]
      );
      const testWeddingId2 = w2Res.rows[0].id;
      await client.query(
        `INSERT INTO entitlements (wedding_id, storage_allocated_bytes, storage_used_bytes, photo_count_used, hosting_until)
         VALUES ($1, 53687091200, 0, 0, NOW() + INTERVAL '1 year')`,
        [testWeddingId2]
      );

      // Create Session 1 in Wedding 1
      const s1 = (
        await client.query(
          `INSERT INTO upload_sessions (wedding_id, expected_bytes, object_key, status, expires_at)
           VALUES ($1, 5000, 'photos/w1/s1/orig', 'RESERVED', NOW() + INTERVAL '30m') RETURNING id`,
          [testWeddingId]
        )
      ).rows[0].id;

      // Create Session 2 in Wedding 2
      const s2 = (
        await client.query(
          `INSERT INTO upload_sessions (wedding_id, expected_bytes, object_key, status, expires_at)
           VALUES ($1, 5000, 'photos/w2/s2/orig', 'RESERVED', NOW() + INTERVAL '30m') RETURNING id`,
          [testWeddingId2]
        )
      ).rows[0].id;

      // Complete Session 1
      const res1 = await client.query(
        `SELECT out_photo_id FROM public.complete_upload_session($1::bigint, $2::bigint, $3::text)`,
        [s1, 5000, identicalHash]
      );

      // Complete Session 2 with identical content in Wedding 2
      const res2 = await client.query(
        `SELECT out_photo_id FROM public.complete_upload_session($1::bigint, $2::bigint, $3::text)`,
        [s2, 5000, identicalHash]
      );

      // Both complete successfully with distinct photo IDs bound to their uploadSessionId
      expect(res1.rows[0].out_photo_id).not.toBe(res2.rows[0].out_photo_id);

      const totalPhotos = await client.query(
        `SELECT count(*)::int as count FROM photos WHERE sha256 = $1`,
        [identicalHash]
      );
      expect(totalPhotos.rows[0].count).toBe(2);

      // Verify that within the SAME wedding, duplicate sha256 is strictly rejected by photos_wedding_id_sha256_key
      const sDup = (
        await client.query(
          `INSERT INTO upload_sessions (wedding_id, expected_bytes, object_key, status, expires_at)
           VALUES ($1, 5000, 'photos/w1/sdup/orig', 'RESERVED', NOW() + INTERVAL '30m') RETURNING id`,
          [testWeddingId]
        )
      ).rows[0].id;

      await expect(
        client.query(
          `SELECT out_photo_id FROM public.complete_upload_session($1::bigint, $2::bigint, $3::text)`,
          [sDup, 5000, identicalHash]
        )
      ).rejects.toThrow(/violates unique constraint "photos_wedding_id_sha256_key"/);
    } finally {
      client.release();
    }
  });

  it('enforces distributed JTI replay prevention across independent instances backed by PostgreSQL table (F06)', async () => {
    // Two independent service instances sharing the PostgreSQL JTI store
    const store1 = new PostgresJtiStore(pool);
    const store2 = new PostgresJtiStore(pool);
    const service1 = new OperatorAuthorizationService(store1);
    const service2 = new OperatorAuthorizationService(store2);

    const superAdminId = 'e8e1215b-9cf4-4e2a-89a1-cb9e1e36780c';
    const oidcToken = 'valid-gcp-oidc-service-account-token';
    const delegationToken = OperatorAuthorizationService.createDelegationAssertion({
      operatorUserId: superAdminId,
      email: 'lead-admin@shadify.in',
      oidcToken,
      ttlSeconds: 300,
    });

    // 1. First presentation to Instance 1 succeeds
    const res1 = await service1.authorizeOperatorRequest({
      oidcToken,
      delegationToken,
      headerOperatorUserId: superAdminId,
      requiredRole: 'super_admin',
    });
    expect(res1.authorized).toBe(true);
    expect(res1.operator?.authoritativeRole).toBe('super_admin');

    // 2. Replay presentation of the EXACT same token to Instance 2 is strictly blocked by the PostgreSQL table
    const res2 = await service2.authorizeOperatorRequest({
      oidcToken,
      delegationToken,
      headerOperatorUserId: superAdminId,
      requiredRole: 'super_admin',
    });
    expect(res2.authorized).toBe(false);
    expect(res2.error).toContain('REPLAY_ATTACK_DETECTED');

    // 3. Verify exactly 1 entry exists in the PostgreSQL delegation_jti_registry table
    const claims = JSON.parse(Buffer.from(delegationToken.split('.')[1], 'base64url').toString('utf8'));
    const jtiRow = await pool.query(
      `SELECT count(*)::int as count FROM delegation_jti_registry WHERE jti = $1`,
      [claims.jti]
    );
    expect(jtiRow.rows[0].count).toBe(1);
  });

  it('guarantees atomic JTI consumption during simultaneous concurrent presentations (F06)', async () => {
    const store1 = new PostgresJtiStore(pool);
    const store2 = new PostgresJtiStore(pool);
    const service1 = new OperatorAuthorizationService(store1);
    const service2 = new OperatorAuthorizationService(store2);

    const superAdminId = 'e8e1215b-9cf4-4e2a-89a1-cb9e1e36780c';
    const oidcToken = 'valid-gcp-oidc-service-account-token';
    const delegationToken = OperatorAuthorizationService.createDelegationAssertion({
      operatorUserId: superAdminId,
      email: 'lead-admin@shadify.in',
      oidcToken,
      ttlSeconds: 300,
    });

    // Two simultaneous presentations racing against PostgreSQL's UNIQUE constraint on jti
    const [authRes1, authRes2] = await Promise.all([
      service1.authorizeOperatorRequest({
        oidcToken,
        delegationToken,
        headerOperatorUserId: superAdminId,
      }),
      service2.authorizeOperatorRequest({
        oidcToken,
        delegationToken,
        headerOperatorUserId: superAdminId,
      }),
    ]);

    const results = [authRes1.authorized, authRes2.authorized].sort();
    // Exactly one must succeed (true), exactly one must fail with replay attack (false)
    expect(results).toEqual([false, true]);

    const error = authRes1.authorized ? authRes2.error : authRes1.error;
    expect(error).toContain('REPLAY_ATTACK_DETECTED');
  });

  it('rolls back entire transaction on quota limit violation without inserting orphan photo records (F09)', async () => {
    const client = await pool.connect();
    try {
      // 1. Create a session expecting 100GB (exceeds 50GB entitlement)
      const sessionRes = await client.query(
        `INSERT INTO upload_sessions (wedding_id, expected_bytes, object_key, status, expires_at)
         VALUES ($1, 60000000000, 'photos/overflow/original', 'RESERVED', NOW() + INTERVAL '30m')
         RETURNING id`,
        [testWeddingId]
      );
      const sessionId = sessionRes.rows[0].id;

      // 2. Complete session attempting to settle 60GB
      let errorThrown = false;
      try {
        await client.query(
          `SELECT * FROM public.complete_upload_session($1::bigint, $2::bigint, $3::text)`,
          [sessionId, 60000000000, '1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff']
        );
      } catch (err: any) {
        errorThrown = true;
        expect(err.code).toBe('54000'); // Quota exceeded SQLSTATE
      }
      expect(errorThrown).toBe(true);

      // 3. Verify that zero photos were inserted
      const photoCheck = await pool.query(
        `SELECT count(*)::int as count FROM photos WHERE upload_session_id = $1`,
        [sessionId]
      );
      expect(photoCheck.rows[0].count).toBe(0);

      // 4. Verify that session remains RESERVED (not settled)
      const sessionCheck = await pool.query(
        `SELECT status FROM upload_sessions WHERE id = $1`,
        [sessionId]
      );
      expect(sessionCheck.rows[0].status).toBe('RESERVED');
    } finally {
      client.release();
    }
  });

  it('handles abort vs complete race correctly between simultaneous transactions (F09)', async () => {
    const clientInit = await pool.connect();
    let sessionId: string;
    try {
      const s = await clientInit.query(
        `INSERT INTO upload_sessions (wedding_id, expected_bytes, object_key, status, expires_at)
         VALUES ($1, 1048576, 'photos/race/original', 'RESERVED', NOW() + INTERVAL '30m')
         RETURNING id`,
        [testWeddingId]
      );
      sessionId = s.rows[0].id;
    } finally {
      clientInit.release();
    }

    const conn1 = await pool.connect();
    const conn2 = await pool.connect();

    try {
      const [completeRes, cancelRes] = await Promise.allSettled([
        conn1.query(`SELECT * FROM public.complete_upload_session($1::bigint, $2::bigint, $3::text)`, [
          sessionId,
          1048576,
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        ]),
        conn2.query(`SELECT public.cancel_upload_session($1::bigint)`, [sessionId]),
      ]);

      // Exactly one must succeed and the other must be rejected
      const statuses = [completeRes.status, cancelRes.status].sort();
      expect(statuses).toEqual(['fulfilled', 'rejected']);

      // Final session status must be either COMPLETED or CANCELLED, never in an intermediate/inconsistent state
      const finalSession = await pool.query(`SELECT status FROM upload_sessions WHERE id = $1`, [sessionId]);
      expect(['COMPLETED', 'CANCELLED']).toContain(finalSession.rows[0].status);
    } finally {
      conn1.release();
      conn2.release();
    }
  });

  it('strictly enforces unique constraint uq_photos_session on upload_session_id (F09)', async () => {
    const client = await pool.connect();
    try {
      const s = (
        await client.query(
          `INSERT INTO upload_sessions (wedding_id, expected_bytes, object_key, status, expires_at)
           VALUES ($1, 5000, 'photos/uq/orig', 'COMPLETED', NOW() + INTERVAL '30m') RETURNING id`,
          [testWeddingId]
        )
      ).rows[0].id;

      // First photo insert
      await client.query(
        `INSERT INTO photos (wedding_id, upload_session_id, sha256, bytes_original, key_original, key_preview, key_thumb, width, height, status)
         VALUES ($1, $2, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 5000, 'k1', 'k1_prev', 'k1_thumb', 800, 600, 'approved')`,
        [testWeddingId, s]
      );

      // Duplicate insert with same upload_session_id must violate unique constraint uq_photos_session
      await expect(
        client.query(
          `INSERT INTO photos (wedding_id, upload_session_id, sha256, bytes_original, key_original, key_preview, key_thumb, width, height, status)
           VALUES ($1, $2, 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', 5000, 'k2', 'k2_prev', 'k2_thumb', 800, 600, 'approved')`,
          [testWeddingId, s]
        )
      ).rejects.toThrow(/violates unique constraint "uq_photos_session"/);
    } finally {
      client.release();
    }
  });

  it('enforces monotonic worker fencing generation, rejecting stale worker completion with SQLSTATE 55001 (F08)', async () => {
    const client = await pool.connect();
    try {
      // 1. Create a reserved upload session
      const s = (
        await client.query(
          `INSERT INTO upload_sessions (wedding_id, expected_bytes, object_key, status, expires_at)
           VALUES ($1, 4096, 'photos/fence/test', 'RESERVED', NOW() + INTERVAL '30m') RETURNING id`,
          [testWeddingId]
        )
      ).rows[0].id;

      // 2. Worker A claims lease with a 1-second timeout (Generation 1)
      const claimA = await client.query(
        `SELECT out_claimed, out_generation, out_lease_token, out_session_status 
         FROM public.claim_verification_lease($1::bigint, $2::text, $3::int)`,
        [s, 'worker-alpha', 1]
      );
      expect(claimA.rows[0].out_claimed).toBe(true);
      expect(claimA.rows[0].out_generation).toBe(1);
      const tokenA = claimA.rows[0].out_lease_token;
      expect(tokenA).toContain('worker-alpha');

      // 3. Worker A experiences an unexpected network partition or GC pause.
      // Wait 1.1s for Worker A's lease to expire
      await new Promise((r) => setTimeout(r, 1100));

      // 4. Worker B observes the expired lease and takes over the job (Generation 2)
      const claimB = await client.query(
        `SELECT out_claimed, out_generation, out_lease_token, out_session_status 
         FROM public.claim_verification_lease($1::bigint, $2::text, $3::int)`,
        [s, 'worker-beta', 30]
      );
      expect(claimB.rows[0].out_claimed).toBe(true);
      expect(claimB.rows[0].out_generation).toBe(2);
      const tokenB = claimB.rows[0].out_lease_token;
      expect(tokenB).toContain('worker-beta');

      // 5. Stale Worker A resumes and attempts to complete the session with its stale generation (1)
      let staleError: any = null;
      try {
        await client.query(
          `SELECT * FROM public.complete_upload_session($1::bigint, $2::bigint, $3::text, $4::int, $5::text)`,
          [s, 4096, 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 1, tokenA]
        );
      } catch (err) {
        staleError = err;
      }
      expect(staleError).toBeTruthy();
      expect(staleError.code).toBe('55001'); // STALE_WORKER_FENCING SQLSTATE
      expect(staleError.message).toContain('STALE_WORKER_FENCING');

      // 6. Active Worker B completes with active generation (2) and succeeds
      const completeB = await client.query(
        `SELECT out_photo_id, out_recovered 
         FROM public.complete_upload_session($1::bigint, $2::bigint, $3::text, $4::int, $5::text)`,
        [s, 4096, 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 2, tokenB]
      );
      expect(completeB.rows[0].out_photo_id).toBeTruthy();
      expect(completeB.rows[0].out_recovered).toBe(false);
    } finally {
      client.release();
    }
  });

  it('enforces durable operator signing key and identity revocation across independent service instances (F06)', async () => {
    const revocationStore = new PostgresRevocationStore(pool);
    const instanceA = new OperatorAuthorizationService(new PostgresJtiStore(pool), revocationStore);
    const instanceB = new OperatorAuthorizationService(new PostgresJtiStore(pool), revocationStore);

    const superAdminId = 'e8e1215b-9cf4-4e2a-89a1-cb9e1e36780c';
    const oidcToken = 'oidc-test-durable-revocation';

    // 1. Fresh assertion validates on Instance A
    const token = OperatorAuthorizationService.createDelegationAssertion({
      operatorUserId: superAdminId,
      email: 'lead-admin@shadify.in',
      oidcToken,
    });

    const resA = await instanceA.authorizeOperatorRequest({
      oidcToken,
      delegationToken: token,
      headerOperatorUserId: superAdminId,
    });
    expect(resA.authorized).toBe(true);

    // 2. Durably revoke signing key in PostgreSQL
    await revocationStore.revokeKey('key-2026-current', 'Emergency compromised key test');

    const token2 = OperatorAuthorizationService.createDelegationAssertion({
      operatorUserId: superAdminId,
      email: 'lead-admin@shadify.in',
      oidcToken,
    });

    // 3. Independent Instance B must reject assertion due to durable database revocation check
    const resB = await instanceB.authorizeOperatorRequest({
      oidcToken,
      delegationToken: token2,
      headerOperatorUserId: superAdminId,
    });
    expect(resB.authorized).toBe(false);
    expect(resB.error).toContain('REVOKED_KEY');

    // 4. Durably revoke operator ID in PostgreSQL
    const otherOperatorId = 'b2c3d4e5-f6a7-4890-bcde-1234567890ab';
    await revocationStore.revokeOperator(otherOperatorId, 'Suspicious off-hours export activity');

    // Re-enable key temporarily for operator test with an isolated key
    const client = await pool.connect();
    try {
      await client.query(`DELETE FROM revoked_delegation_keys WHERE key_id = 'key-2026-current'`);
    } finally {
      client.release();
    }

    const token3 = OperatorAuthorizationService.createDelegationAssertion({
      operatorUserId: otherOperatorId,
      email: 'studio-vikram@shadify.in',
      oidcToken,
    });

    const resC = await instanceA.authorizeOperatorRequest({
      oidcToken,
      delegationToken: token3,
      headerOperatorUserId: otherOperatorId,
    });
    expect(resC.authorized).toBe(false);
    expect(resC.error).toContain('REVOKED_OPERATOR');
  });

  it('enforces durable guest PIN rate limiting, lockout, and wedding-wide brute force detection in PostgreSQL (F13)', async () => {
    const rateLimiter = new PostgresGuestRateLimiter(pool);
    const weddingSlug = 'priya-rohan-durable-' + Date.now();
    const attackerIp = '203.0.113.88';

    // 1. First 4 failed attempts decrease remaining attempts
    for (let i = 1; i <= 4; i++) {
      const res = await rateLimiter.recordAttempt(attackerIp, weddingSlug, false);
      expect(res.allowed).toBe(true);
      expect(res.remainingAttempts).toBe(5 - i);
    }

    // 2. 5th failed attempt triggers 15-minute lockout
    const res5 = await rateLimiter.recordAttempt(attackerIp, weddingSlug, false);
    expect(res5.allowed).toBe(false);
    expect(res5.remainingAttempts).toBe(0);
    expect(res5.error).toContain('PIN_LOCKED_OUT');

    // 3. 6th attempt from a separate physical connection is immediately locked out
    const res6 = await rateLimiter.recordAttempt(attackerIp, weddingSlug, false);
    expect(res6.allowed).toBe(false);
    expect(res6.error).toContain('PIN_RATE_LIMITED');

    // 4. Benign IP is still allowed
    const benignIp = '203.0.113.89';
    const benignRes = await rateLimiter.recordAttempt(benignIp, weddingSlug, false);
    expect(benignRes.allowed).toBe(true);

    // 5. Distributed attack simulation (distributed IPs targeting same wedding)
    // 4 failed attempts from 4 additional IPs pushes cumulative failures to >= 20
    for (let ipNum = 1; ipNum <= 4; ipNum++) {
      for (let attempt = 1; attempt <= 4; attempt++) {
        await rateLimiter.recordAttempt(`203.0.113.10${ipNum}`, weddingSlug, false);
      }
    }
    // Now wedding cumulative failures = 5 (attackerIp) + 1 (benignIp) + 16 (4*4) = 22 >= 20
    const attackRes = await rateLimiter.recordAttempt('203.0.113.200', weddingSlug, false);
    expect(attackRes.allowed).toBe(false);
    expect(attackRes.error).toContain('WEDDING_PIN_LOCKED_OUT');
  });

  it('enforces durable guest token revocation across physical database connections (F13)', async () => {
    const revocationStore = new PostgresGuestRevocationStore(pool);
    GuestAuthorizationService.setDefaultPool(pool);

    const weddingSlug = 'priya-rohan-guest-revocation';
    const guestToken = GuestAuthorizationService.issueGuestToken(weddingSlug, 'fingerprint-device-abc');

    // 1. Token valid before revocation
    const verifyBefore = await GuestAuthorizationService.verifyGuestTokenDurable(guestToken, weddingSlug);
    expect(verifyBefore.valid).toBe(true);

    // 2. Durably revoke token in PostgreSQL table revoked_guest_tokens
    const expiresAt = new Date(Date.now() + 24 * 3600 * 1000);
    await revocationStore.revokeToken(guestToken, expiresAt);

    // 3. Token rejected across independent connections
    const verifyAfter = await GuestAuthorizationService.verifyGuestTokenDurable(guestToken, weddingSlug);
    expect(verifyAfter.valid).toBe(false);
    expect(verifyAfter.error).toContain('TOKEN_REVOKED');
  });

  it('enforces upload session referential integrity: blocks deletion of completed sessions, allows uncompleted session pruning, and supports wedding cascade erasure (Finding 1)', async () => {
    const client = await pool.connect();
    try {
      const uniqueSlug = 'retention-test-' + Date.now();
      const weddingRes = await client.query(
        `INSERT INTO weddings (slug, bride_name, groom_name, wedding_date, status) 
         VALUES ($1, 'Divya', 'Siddharth', '2026-11-20', 'published') 
         RETURNING id`,
        [uniqueSlug]
      );
      const wid = weddingRes.rows[0].id;

      await client.query(
        `INSERT INTO entitlements (wedding_id, storage_allocated_bytes, storage_used_bytes, photo_count_used, hosting_until)
         VALUES ($1, 53687091200, 0, 0, NOW() + INTERVAL '1 year')`,
        [wid]
      );

      // 1. Create completed session S_comp and photo P1
      const sComp = (
        await client.query(
          `INSERT INTO upload_sessions (wedding_id, expected_bytes, object_key, status, expires_at)
           VALUES ($1, 4000, 'photos/ret/scomp/orig', 'COMPLETED', NOW() + INTERVAL '1h') RETURNING id`,
          [wid]
        )
      ).rows[0].id;

      await client.query(
        `INSERT INTO photos (wedding_id, upload_session_id, sha256, bytes_original, key_original, key_preview, key_thumb, width, height, status)
         VALUES ($1, $2, '9999999999999999999999999999999999999999999999999999999999999999', 4000, 'k_comp', 'k_prev', 'k_thumb', 800, 600, 'approved')`,
        [wid, sComp]
      );

      // 2a. Direct autocommit deletion of completed session S_comp MUST fail with FK violation
      await expect(
        client.query(`DELETE FROM upload_sessions WHERE id = $1`, [sComp])
      ).rejects.toThrow(/violates foreign key constraint/);

      // 2b. Explicit transaction block: Statement succeeds with deferred check; fails at COMMIT boundary
      await client.query('BEGIN');
      const delRes = await client.query(`DELETE FROM upload_sessions WHERE id = $1`, [sComp]);
      expect(delRes.rowCount).toBe(1);
      await expect(client.query('COMMIT')).rejects.toThrow(/violates foreign key constraint/);
      await client.query('ROLLBACK');

      // Verify photo and session are both intact
      const photoCheck = await client.query(`SELECT id FROM photos WHERE upload_session_id = $1`, [sComp]);
      expect(photoCheck.rowCount).toBe(1);

      // 3. Create uncompleted expired session S_exp (no photo attached)
      const sExp = (
        await client.query(
          `INSERT INTO upload_sessions (wedding_id, expected_bytes, object_key, status, expires_at)
           VALUES ($1, 4000, 'photos/ret/sexp/orig', 'EXPIRED', NOW() - INTERVAL '1h') RETURNING id`,
          [wid]
        )
      ).rows[0].id;

      // Deleting uncompleted expired session MUST succeed cleanly
      const delExpRes = await client.query(`DELETE FROM upload_sessions WHERE id = $1`, [sExp]);
      expect(delExpRes.rowCount).toBe(1);

      // 4. Wedding-level erasure in explicit transaction MUST succeed at COMMIT
      await client.query('BEGIN');
      const delWeddingRes = await client.query(`DELETE FROM weddings WHERE id = $1`, [wid]);
      expect(delWeddingRes.rowCount).toBe(1);
      await client.query('COMMIT');

      // Verify both photo and session were erased cleanly by cascade
      const sessionAfter = await client.query(`SELECT id FROM upload_sessions WHERE id = $1`, [sComp]);
      expect(sessionAfter.rowCount).toBe(0);
      const photoAfter = await client.query(`SELECT id FROM photos WHERE upload_session_id = $1`, [sComp]);
      expect(photoAfter.rowCount).toBe(0);
    } finally {
      client.release();
    }
  });

  it('proves wedding-wide PIN lockout concurrency across simultaneous requests from distinct IP addresses (Finding 3)', async () => {
    const rateLimiter = new PostgresGuestRateLimiter(pool);
    const resetWeddingSlug = 'reset-semantics-' + Date.now();

    // Part A: Test distinct-IP reset semantics (one IP resets without clearing other locked IPs)
    // IP 1 has 3 failures; IP 2 has 5 failures (locked out for 15m)
    for (let i = 1; i <= 3; i++) {
      await rateLimiter.recordAttempt('198.51.100.1', resetWeddingSlug, false);
    }
    for (let i = 1; i <= 5; i++) {
      await rateLimiter.recordAttempt('198.51.100.2', resetWeddingSlug, false);
    }

    // Verify IP 2 is locked out
    const ip2Locked = await rateLimiter.recordAttempt('198.51.100.2', resetWeddingSlug, false);
    expect(ip2Locked.allowed).toBe(false);
    expect(ip2Locked.error).toContain('PIN_RATE_LIMITED');

    // IP 1 successfully enters the correct PIN: resets IP 1's failures cleanly
    const resetRes = await rateLimiter.recordAttempt('198.51.100.1', resetWeddingSlug, true);
    expect(resetRes.allowed).toBe(true);

    const clientReset = await pool.connect();
    try {
      const ip1Check = await clientReset.query(
        `SELECT * FROM guest_pin_attempts WHERE wedding_slug = $1 AND ip_address = '198.51.100.1'`,
        [resetWeddingSlug]
      );
      expect(ip1Check.rowCount).toBe(0); // IP 1 reset

      const ip2Check = await clientReset.query(
        `SELECT * FROM guest_pin_attempts WHERE wedding_slug = $1 AND ip_address = '198.51.100.2'`,
        [resetWeddingSlug]
      );
      expect(ip2Check.rowCount).toBe(1); // IP 2 still preserved and locked!
      expect(ip2Check.rows[0].failed_attempts).toBe(5);
    } finally {
      clientReset.release();
    }

    // Part B: Test concurrent race-condition elimination at the 19-to-20 threshold
    const attackWeddingSlug = 'concurrent-attack-' + Date.now();

    // 1. Seed wedding to exactly 19 failed attempts across multiple distinct IPs (just below 20-failure lockout threshold)
    // 3 failed attempts per IP from 6 distinct IPs = 18, plus 1 attempt from IP 7 = 19
    for (let i = 1; i <= 6; i++) {
      for (let attempt = 1; attempt <= 3; attempt++) {
        await rateLimiter.recordAttempt(`198.51.100.${i}`, attackWeddingSlug, false);
      }
    }
    await rateLimiter.recordAttempt(`198.51.100.7`, attackWeddingSlug, false);

    // Verify current state is at exactly 19 failures and still allowed
    const client = await pool.connect();
    try {
      const sumRes = await client.query(
        `SELECT COALESCE(SUM(failed_attempts), 0)::int as sum FROM guest_pin_attempts WHERE wedding_slug = $1`,
        [attackWeddingSlug]
      );
      expect(sumRes.rows[0].sum).toBe(19);
    } finally {
      client.release();
    }

    // 2. Launch 8 SIMULTANEOUS concurrent requests from 8 DISTINCT IP addresses (IPs .50 to .57)
    // Because of transaction-scoped advisory serialization (Finding 3), exactly 1 request may enter as attempt #20,
    // and ALL remaining concurrent requests MUST observe the wedding-wide threshold and be locked out!
    const distinctIps = Array.from({ length: 8 }, (_, i) => `198.51.100.${50 + i}`);
    const results = await Promise.all(
      distinctIps.map((ip) => rateLimiter.recordAttempt(ip, attackWeddingSlug, false))
    );

    // Every request that was evaluated at or after the 20th attempt must be rejected
    const lockedOutResults = results.filter((r) => r.allowed === false && r.error?.includes('WEDDING_PIN_LOCKED_OUT'));
    // At least 7 out of 8 (or all 8) must be WEDDING_PIN_LOCKED_OUT
    expect(lockedOutResults.length).toBeGreaterThanOrEqual(7);

    // Subsequent attempt from yet another fresh IP must be unconditionally rejected
    const freshRes = await rateLimiter.recordAttempt('198.51.100.99', attackWeddingSlug, false);
    expect(freshRes.allowed).toBe(false);
    expect(freshRes.error).toContain('WEDDING_PIN_LOCKED_OUT');

    // 3. Universal Admin Reset: unlocks gallery using identical advisory namespace (Finding 3)
    await rateLimiter.adminResetWedding(attackWeddingSlug);
    const postResetRes = await rateLimiter.recordAttempt('198.51.100.99', attackWeddingSlug, false);
    expect(postResetRes.allowed).toBe(true);
    expect(postResetRes.remainingAttempts).toBe(4);
  });
});

// ---------------------------------------------------------------------------
// F15.5 — Real PostgreSQL Lease-Fencing Integration under In-Flight Interruption (F15.5)
// ---------------------------------------------------------------------------
// This suite tests the ACTUAL OutboxRevocationProcessor.processBatch() against
// a live PostgreSQL instance (port 5433) with real FOR UPDATE SKIP LOCKED
// lease acquisition, concurrent worker overlap, and lease expiration fencing.
//
// Architectural Scope:
//   Simulates an in-flight worker interruption (e.g. GC pause, network partition,
//   or suspended coroutine) where lease expiry allows a secondary worker to take
//   over, and verifies that the stale worker's in-flight mutation is fenced out.
//
// Concurrency & Fencing Mechanism:
//   1. Worker A acquires an active lease on a PHOTO_DELETED event.
//   2. During physical deletion, Worker A is suspended via a controllable promise.
//   3. While Worker A is in-flight and suspended, its lease is artificially expired
//      in PostgreSQL (simulating lease timeout during interruption).
//   4. Worker B starts processBatch(1) concurrently with targetWeddingId scoping.
//      Worker B acquires the expired event via FOR UPDATE SKIP LOCKED and enters
//      its own deletion operation (also held open via a controllable promise).
//   5. With BOTH workers concurrently in-flight:
//      - The database confirms Worker B holds the active lease token.
//      - A stale Worker A update targeting its old lease token is executed.
//      - Real PostgreSQL confirms rowCount === 0; Worker B's lease is NOT overwritten.
//   6. Worker A is resumed: its attempt to mark the event COMPLETED is fenced out
//      (0 rows affected -> StaleLeaseFencingError), resulting in completedCount = 0.
//   7. Worker B is resumed: it completes successfully, resulting in completedCount = 1.
//   8. Final DB verification: status = 'COMPLETED', lease_token = NULL.
//
// Isolation & Safety:
//   - All test data is strictly scoped via targetWeddingId and eventId.
//   - Zero global deletes on outbox_events.
//   - try/finally barrier guarantees worker resolution and connection cleanup on failure.
//   - Database unavailability explicitly skips via ctx.skip().
// ---------------------------------------------------------------------------
describe('Real PostgreSQL lease-fencing integration under simulated in-flight interruption (F15.5)', () => {
  const localDbConfig: pg.PoolConfig = {
    host: '127.0.0.1',
    port: 5433,
    user: 'cvs',
    database: process.env.PGDATABASE || 'shadify_migrated_test',
    max: 5,
  };

  let pool: pg.Pool;
  let testWeddingId: string;
  let dbAvailable = false;

  beforeAll(async () => {
    pool = new pg.Pool(localDbConfig);
    let client: pg.PoolClient | undefined;
    try {
      client = await pool.connect();
      // Seed an isolated test wedding row (scoped foreign key anchor)
      const slug = 'f155-fencing-concurrent-' + Date.now();
      const wRes = await client.query(
        `INSERT INTO weddings (slug, bride_name, groom_name, wedding_date, status)
         VALUES ($1, 'Meera', 'Arjun', '2027-01-01', 'published') RETURNING id`,
        [slug]
      );
      testWeddingId = wRes.rows[0].id;
      await client.query(
        `INSERT INTO entitlements (wedding_id, storage_allocated_bytes, storage_used_bytes, photo_count_used, hosting_until)
         VALUES ($1, 53687091200, 0, 0, NOW() + INTERVAL '1 year')`,
        [testWeddingId]
      );
      dbAvailable = true;
    } catch (err: any) {
      if (err.code === 'ECONNREFUSED' || err.code === 'EPERM' || err.message?.includes('EPERM')) {
        console.warn('[F15.5] PostgreSQL unavailable at port 5433; suite will be skipped explicitly');
        dbAvailable = false;
        return;
      }
      throw err;
    } finally {
      if (client) client.release();
    }
  });

  beforeEach((ctx) => {
    if (!dbAvailable) {
      ctx.skip();
    }
  });

  afterAll(async () => {
    try {
      if (pool && testWeddingId) {
        // Scoped cleanup: delete only this test wedding and cascading children
        await pool.query(`DELETE FROM weddings WHERE id = $1`, [testWeddingId]);
      }
    } finally {
      if (pool) {
        await pool.end();
      }
    }
  });

  class AuthoritativeClientWrapper {
    private inTransaction: boolean = false;
    private transactionDepth: number = 0;
    private transactionCommitted: boolean = false;
    private transactionRolledBack: boolean = false;
    private isReleased: boolean = false;
    private isDestroyed: boolean = false;
    private rollbackError: Error | null = null;
    private lifecycleHistory: Array<{ op: string; timestamp: number; success: boolean }> = [];
    private currentTxOps: Array<{ op: string; timestamp: number; success: boolean }> = [];
    private lastTxOps: Array<{ op: string; timestamp: number; success: boolean }> = [];

    constructor(private readonly rawClient: any) {}

    isIdle(): boolean {
      return !this.isReleased && !this.isDestroyed && !this.inTransaction && this.transactionDepth === 0;
    }

    isInTransaction(): boolean {
      return this.inTransaction;
    }

    isReleasedWrapper(): boolean {
      return this.isReleased;
    }

    isDiscarded(): boolean {
      return this.isDestroyed;
    }

    getRollbackError(): Error | null {
      return this.rollbackError;
    }

    getLifecycleHistory() {
      return [...this.lifecycleHistory];
    }

    getLastTransactionOperations() {
      return [...this.lastTxOps];
    }

    wasCommittedSuccessfully(): boolean {
      return this.transactionCommitted;
    }

    wasRolledBack(): boolean {
      return this.transactionRolledBack;
    }

    async beginTransaction(): Promise<void> {
      if (this.isReleased || this.isDestroyed) {
        throw new Error('ILLEGAL_STATE: Cannot begin transaction on released or destroyed connection wrapper');
      }
      if (this.inTransaction) {
        throw new Error('ILLEGAL_TRANSACTION_STATE: Cannot BEGIN when already in transaction');
      }
      await this.rawClient.query('BEGIN');
      this.inTransaction = true;
      this.transactionDepth = 1;
      this.transactionCommitted = false;
      this.transactionRolledBack = false;
      const op = { op: 'BEGIN', timestamp: Date.now(), success: true };
      this.lifecycleHistory.push(op);
      this.currentTxOps = [op];
    }

    async commitTransaction(): Promise<void> {
      if (this.isReleased || this.isDestroyed) {
        throw new Error('ILLEGAL_STATE: Cannot commit on released or destroyed connection wrapper');
      }
      if (!this.inTransaction) {
        throw new Error('ILLEGAL_TRANSACTION_STATE: Cannot COMMIT when not in transaction');
      }
      await this.rawClient.query('COMMIT');
      this.inTransaction = false;
      this.transactionDepth = 0;
      this.transactionCommitted = true;
      const op = { op: 'COMMIT', timestamp: Date.now(), success: true };
      this.lifecycleHistory.push(op);
      this.currentTxOps.push(op);
      this.lastTxOps = [...this.currentTxOps];
    }

    async rollbackTransaction(): Promise<void> {
      if (this.isReleased || this.isDestroyed) {
        throw new Error('ILLEGAL_STATE: Cannot rollback on released or destroyed connection wrapper');
      }
      if (!this.inTransaction) {
        throw new Error('ILLEGAL_TRANSACTION_STATE: Cannot ROLLBACK when not in transaction');
      }
      await this.rawClient.query('ROLLBACK');
      this.inTransaction = false;
      this.transactionDepth = 0;
      this.transactionRolledBack = true;
      const op = { op: 'ROLLBACK', timestamp: Date.now(), success: true };
      this.lifecycleHistory.push(op);
      this.currentTxOps.push(op);
      this.lastTxOps = [...this.currentTxOps];
    }

    async query(queryText: any, values?: any): Promise<any> {
      if (this.isReleased || this.isDestroyed) {
        throw new Error('ILLEGAL_STATE: Cannot query on released or destroyed connection wrapper');
      }
      const trimmed = typeof queryText === 'string' ? queryText.trim().toUpperCase() : '';
      if (trimmed.startsWith('BEGIN') || trimmed.startsWith('START TRANSACTION')) {
        await this.beginTransaction();
        return { rows: [], rowCount: 0 };
      }
      if (trimmed.startsWith('COMMIT') || trimmed.startsWith('END')) {
        await this.commitTransaction();
        return { rows: [], rowCount: 0 };
      }
      if (trimmed.startsWith('ROLLBACK') || trimmed.startsWith('ABORT')) {
        await this.rollbackTransaction();
        return { rows: [], rowCount: 0 };
      }

      try {
        const res = await this.rawClient.query(queryText, values);
        const op = { op: 'QUERY', timestamp: Date.now(), success: true };
        this.lifecycleHistory.push(op);
        if (this.inTransaction) {
          this.currentTxOps.push(op);
        }
        return res;
      } catch (err) {
        const op = { op: 'QUERY_FAILED', timestamp: Date.now(), success: false };
        this.lifecycleHistory.push(op);
        if (this.inTransaction) {
          this.currentTxOps.push(op);
        }
        throw err;
      }
    }

    async release(): Promise<void> {
      if (this.isReleased) {
        throw new Error('ILLEGAL_STATE: Connection wrapper has already been released');
      }
      this.isReleased = true;

      if (this.inTransaction) {
        try {
          // Strictly await rollback completion on PostgreSQL before releasing the client
          await this.rawClient.query('ROLLBACK');
          this.transactionRolledBack = true;
          this.inTransaction = false;
          this.transactionDepth = 0;
          this.lifecycleHistory.push({ op: 'ROLLBACK_ON_RELEASE', timestamp: Date.now(), success: true });
          if (typeof this.rawClient.release === 'function') {
            this.rawClient.release();
          }
        } catch (err: any) {
          // On rollback failure, the connection state is uncertain:
          // Mark wrapper as destroyed (NOT idle), pass error to client.release(err) to destroy the connection in pg-pool!
          this.isDestroyed = true;
          this.inTransaction = false;
          this.transactionDepth = 0;
          this.rollbackError = err;
          this.lifecycleHistory.push({ op: 'ROLLBACK_ON_RELEASE_FAILED', timestamp: Date.now(), success: false });
          if (typeof this.rawClient.release === 'function') {
            this.rawClient.release(err);
          } else if (typeof this.rawClient.destroy === 'function') {
            this.rawClient.destroy();
          }
          throw new Error(`CRITICAL_CLEANUP_FAILURE: Database rollback failed during release, connection destroyed: ${err?.message || err}`);
        }
      } else {
        if (typeof this.rawClient.release === 'function') {
          this.rawClient.release();
        }
      }
    }
  }

  it('F15.5 Concurrent Two-Worker Lease Fencing: Worker B claims expired lease while Worker A is suspended; stale Worker A write fails rowCount=0 without corrupting Worker B', async () => {
    // ------------------------------------------------------------------ //
    // Phase 0 — Seed a fresh, isolated outbox_events row
    // ------------------------------------------------------------------ //
    const ts = Date.now();
    const photoId = `f155-concurrent-${ts}`;
    const weddingSlug = 'meera-arjun-2027';
    const manifestKeys = [
      `originals/${weddingSlug}/${photoId}-orig.jpg`,
      `previews/${weddingSlug}/${photoId}-prev.webp`,
      `thumbnails/${weddingSlug}/${photoId}-thumb.webp`,
    ];

    const setupClient = await pool.connect();
    let eventId: number;
    try {
      // Normal created_at timestamp; targetWeddingId ensures deterministic selection
      const evRes = await setupClient.query(
        `INSERT INTO outbox_events (event_type, wedding_id, payload, status, max_retries, created_at)
         VALUES ('PHOTO_DELETED', $1, $2::jsonb, 'PENDING', 4, clock_timestamp())
         RETURNING id`,
        [
          testWeddingId,
          JSON.stringify({
            photoId,
            weddingSlug,
            manifest: { keys: manifestKeys },
            deletedKeys: [],
            failedKeys: [],
          }),
        ]
      );
      eventId = Number(evRes.rows[0].id);
    } finally {
      setupClient.release();
    }

    const r2DeleteLog: { worker: string; keys: string[] }[] = [];

    // Controllable synchronization barriers for Worker A
    let workerADeleteStartedResolve!: () => void;
    const workerADeleteStarted = new Promise<void>((r) => { workerADeleteStartedResolve = r; });
    let workerAResumeResolve!: () => void;
    const workerAResume = new Promise<void>((r) => { workerAResumeResolve = r; });

    // Controllable synchronization barriers for Worker B
    let workerBDeleteStartedResolve!: () => void;
    const workerBDeleteStarted = new Promise<void>((r) => { workerBDeleteStartedResolve = r; });
    let workerBResumeResolve!: () => void;
    const workerBResume = new Promise<void>((r) => { workerBResumeResolve = r; });

    const mockPurge = {
      purgePhoto: async () => ({ success: true }),
      purgeWedding: async () => ({ success: true }),
    };
    const mockDo = {
      revokePhoto: async () => {},
      revokeWedding: async () => {},
      isWeddingRevoked: async () => false,
      isPhotoRevoked: async () => false,
    };

    const poolA = new pg.Pool({ ...localDbConfig, max: 2 });
    const poolB = new pg.Pool({ ...localDbConfig, max: 2 });

    let workerAPromise: Promise<any> | undefined;
    let workerBPromise: Promise<any> | undefined;

    try {
      // ------------------------------------------------------------------ //
      // Phase 1 — Start Worker A with controllable R2 deletion & exact event scoping
      // ------------------------------------------------------------------ //
      const r2WorkerA = {
        deletePhotoObjects: async (_slug: string, pId: string, keys: string[]) => {
          if (pId !== photoId) {
            throw new Error(`UNEXPECTED_PHOTO_ID_IN_WORKER_A: Expected ${photoId}, got ${pId}`);
          }
          r2DeleteLog.push({ worker: 'Worker A', keys: [...keys] });
          workerADeleteStartedResolve(); // Signal: Worker A has acquired lease and started R2 deletion
          await workerAResume;          // Suspend Worker A in-flight
          return { success: true, deletedKeys: keys, failedKeys: [] };
        },
      };

      const workerA = new OutboxRevocationProcessor({
        pool: poolA as any,
        r2Storage: r2WorkerA as any,
        purgeService: mockPurge as any,
        doCoordinator: mockDo as any,
        leaseDurationSeconds: 60,
        strictRevocationMode: false,
        targetWeddingId: testWeddingId,
        targetEventId: eventId,
      });

      // Launch Worker A asynchronously
      workerAPromise = workerA.processBatch(1);

      // Wait until Worker A has claimed the lease and entered R2 deletion
      await workerADeleteStarted;

      // Verify Worker A claimed the event in PostgreSQL
      const stateA = await pool.query(
        `SELECT status, lease_token, lease_expires_at FROM outbox_events WHERE id = $1`,
        [eventId]
      );
      expect(stateA.rows[0].status).toBe('PROCESSING');
      const workerALeaseToken: string = stateA.rows[0].lease_token;
      expect(workerALeaseToken).toBeTruthy();

      // ------------------------------------------------------------------ //
      // Phase 2 — Expire Worker A's lease in PostgreSQL while Worker A is STILL suspended
      // ------------------------------------------------------------------ //
      await pool.query(
        `UPDATE outbox_events
         SET lease_expires_at = clock_timestamp() - INTERVAL '1 second'
         WHERE id = $1`,
        [eventId]
      );

      // ------------------------------------------------------------------ //
      // Phase 3 — Start Worker B concurrently while Worker A is STILL suspended
      // ------------------------------------------------------------------ //
      const r2WorkerB = {
        deletePhotoObjects: async (_slug: string, pId: string, keys: string[]) => {
          if (pId !== photoId) {
            throw new Error(`UNEXPECTED_PHOTO_ID_IN_WORKER_B: Expected ${photoId}, got ${pId}`);
          }
          r2DeleteLog.push({ worker: 'Worker B', keys: [...keys] });
          workerBDeleteStartedResolve(); // Signal: Worker B has claimed expired lease
          await workerBResume;          // Suspend Worker B in-flight
          return { success: true, deletedKeys: keys, failedKeys: [] };
        },
      };

      const workerB = new OutboxRevocationProcessor({
        pool: poolB as any,
        r2Storage: r2WorkerB as any,
        purgeService: mockPurge as any,
        doCoordinator: mockDo as any,
        leaseDurationSeconds: 60,
        strictRevocationMode: false,
        targetWeddingId: testWeddingId,
        targetEventId: eventId,
      });

      // Launch Worker B asynchronously — claims expired lease via FOR UPDATE SKIP LOCKED
      workerBPromise = workerB.processBatch(1);

      // Wait until Worker B has claimed the event and entered R2 deletion
      await workerBDeleteStarted;

      // ------------------------------------------------------------------ //
      // Phase 4 — Genuine Concurrent Overlap Verification
      // Both Worker A and Worker B are suspended in deletePhotoObjects concurrently
      // ------------------------------------------------------------------ //
      const stateDuringOverlap = await pool.query(
        `SELECT status, lease_token, lease_expires_at FROM outbox_events WHERE id = $1`,
        [eventId]
      );
      expect(stateDuringOverlap.rows[0].status).toBe('PROCESSING');
      const workerBLeaseToken: string = stateDuringOverlap.rows[0].lease_token;
      expect(workerBLeaseToken).toBeTruthy();
      expect(workerBLeaseToken).not.toBe(workerALeaseToken);

      // Verify lease horizon is active for Worker B
      const expiryB = new Date(stateDuringOverlap.rows[0].lease_expires_at);
      expect(expiryB.getTime()).toBeGreaterThan(Date.now());

      // ------------------------------------------------------------------ //
      // Phase 5 — Attempt Stale Worker A Conditional Mutation while Worker B is ACTIVE
      // ------------------------------------------------------------------ //
      const staleAttempt = await pool.query(
        `UPDATE outbox_events
         SET status = 'PROCESSING',
             last_error = 'stale-worker-a-attempted-overwrite',
             updated_at = clock_timestamp()
         WHERE id = $1
           AND lease_token = $2
           AND status = 'PROCESSING'
           AND lease_expires_at > clock_timestamp()`,
        [eventId, workerALeaseToken]
      );

      // Core Invariant: Worker A's update touches ZERO rows because lease_token no longer matches
      expect(staleAttempt.rowCount).toBe(0);

      // Verify Worker B's active lease and state were completely protected from corruption
      const stateAfterStaleAttempt = await pool.query(
        `SELECT status, lease_token, last_error FROM outbox_events WHERE id = $1`,
        [eventId]
      );
      expect(stateAfterStaleAttempt.rows[0].status).toBe('PROCESSING');
      expect(stateAfterStaleAttempt.rows[0].lease_token).toBe(workerBLeaseToken);
      expect(stateAfterStaleAttempt.rows[0].last_error).toBeNull();

      // ------------------------------------------------------------------ //
      // Phase 6 — Resume Worker A: it must be fenced out on completion attempt
      // ------------------------------------------------------------------ //
      workerAResumeResolve();
      const resA = await workerAPromise;

      // Worker A was fenced out on completion -> completedCount must be 0
      expect(resA.completedCount).toBe(0);

      // ------------------------------------------------------------------ //
      // Phase 7 — Resume Worker B: it must complete successfully
      // ------------------------------------------------------------------ //
      workerBResumeResolve();
      const resB = await workerBPromise;

      // Worker B owned the active lease and completed the event -> completedCount must be 1
      expect(resB.completedCount).toBe(1);

      // ------------------------------------------------------------------ //
      // Phase 8 — Final State & Invariants
      // ------------------------------------------------------------------ //
      const finalRow = await pool.query(
        `SELECT status, lease_token, lease_expires_at FROM outbox_events WHERE id = $1`,
        [eventId]
      );
      expect(finalRow.rows[0].status).toBe('COMPLETED');
      expect(finalRow.rows[0].lease_token).toBeNull();
      expect(finalRow.rows[0].lease_expires_at).toBeNull();

      // Ordering invariant: Worker A attempted R2 first, Worker B entered R2 second
      expect(r2DeleteLog).toHaveLength(2);
      expect(r2DeleteLog[0].worker).toBe('Worker A');
      expect(r2DeleteLog[1].worker).toBe('Worker B');

      // Exact event isolation invariant: only the seeded event existed and was operated upon
      const totalEventsInWedding = await pool.query(
        `SELECT id, status FROM outbox_events WHERE wedding_id = $1`,
        [testWeddingId]
      );
      expect(totalEventsInWedding.rows).toHaveLength(1);
      expect(Number(totalEventsInWedding.rows[0].id)).toBe(eventId);
      expect(totalEventsInWedding.rows[0].status).toBe('COMPLETED');
    } finally {
      // Ensure all barriers are unblocked so in-flight promises settle
      try { workerAResumeResolve?.(); } catch {}
      try { workerBResumeResolve?.(); } catch {}
      if (workerAPromise || workerBPromise) {
        await Promise.allSettled([workerAPromise, workerBPromise].filter(Boolean));
      }
      await poolA.end().catch(() => {});
      await poolB.end().catch(() => {});
      try {
        await pool.query(`DELETE FROM outbox_events WHERE id = $1`, [eventId!]);
      } catch {}
    }
  }, 15000);

  it('F15.5 Expiry Fencing on Failure Retry: Worker A whose lease expired cannot escalate retries even when no other worker has claimed the event', async () => {
    // ------------------------------------------------------------------ //
    // Sequence (Auditor P0 Requirement):
    // 1. Worker A acquires an event.
    // 2. Worker A's lease expires in PostgreSQL.
    // 3. No Worker B reclaim is required (Worker A still has matching token).
    // 4. Worker A attempts retry escalation.
    // 5. The update affects zero rows because lease_expires_at <= clock_timestamp().
    // 6. The event's retry_count and status remain unchanged.
    // ------------------------------------------------------------------ //
    const ts = Date.now();
    const photoId = `f155-retry-fencing-${ts}`;
    const weddingSlug = 'meera-arjun-2027';
    const manifestKeys = [
      `originals/${weddingSlug}/${photoId}-orig.jpg`,
      `previews/${weddingSlug}/${photoId}-prev.webp`,
      `thumbnails/${weddingSlug}/${photoId}-thumb.webp`,
    ];

    const setupClient = await pool.connect();
    let eventId: number;
    try {
      const evRes = await setupClient.query(
        `INSERT INTO outbox_events (event_type, wedding_id, payload, status, retry_count, max_retries, created_at)
         VALUES ('PHOTO_DELETED', $1, $2::jsonb, 'PENDING', 0, 4, clock_timestamp())
         RETURNING id`,
        [
          testWeddingId,
          JSON.stringify({
            photoId,
            weddingSlug,
            manifest: { keys: manifestKeys },
            deletedKeys: [],
            failedKeys: [],
          }),
        ]
      );
      eventId = Number(evRes.rows[0].id);
    } finally {
      setupClient.release();
    }

    let workerStartedResolve!: () => void;
    const workerStarted = new Promise<void>((r) => { workerStartedResolve = r; });
    let workerResumeResolve!: () => void;
    const workerResume = new Promise<void>((r) => { workerResumeResolve = r; });

    // Mock R2 storage that signals started, waits for resume, and then FAILS with a transient error
    const r2FailingWorker = {
      deletePhotoObjects: async (_slug: string, pId: string) => {
        if (pId !== photoId) {
          throw new Error(`UNEXPECTED_PHOTO_ID: Expected ${photoId}, got ${pId}`);
        }
        workerStartedResolve();
        await workerResume;
        throw new Error('Simulated transient R2 500 error triggering failure retry');
      },
    };

    const poolWorker = new pg.Pool({ ...localDbConfig, max: 2 });
    let workerPromise: Promise<any> | undefined;

    // Direct Query Instrumentation: captures every UPDATE query, full values, raw execution rowCount result,
    // transaction state ownership, and an exact same-time pre-mutation diagnostic executed under exclusive row lock
    const capturedUpdateRowCounts: {
      sql: string;
      values?: any[];
      rowCount: number | null;
      sameTimeDiagnostic?: { id_match: boolean; token_match: boolean; status_match: boolean; lease_active: boolean } | null;
      lockResultRows?: any[];
      wasIdleBefore?: boolean;
      transactionOwnedByWrapper?: boolean;
      transactionCommitted?: boolean;
      lifecycleHistory?: any[];
      lastTransactionOperations?: any[];
    }[] = [];
    const origConnect = poolWorker.connect.bind(poolWorker);
    poolWorker.connect = async () => {
      const rawClient = await origConnect();
      const wrapper = new AuthoritativeClientWrapper(rawClient);
      const client = {
        ...rawClient,
        query: async (queryText: any, values?: any) => {
          let sameTimeDiag: any = null;
          let lockResRows: any = null;
          let wasIdle = false;
          if (
            typeof queryText === 'string' &&
            queryText.includes('UPDATE outbox_events') &&
            (queryText.includes("status = 'PENDING'") || queryText.includes("status = 'DEAD_LETTER'"))
          ) {
            const targetId = values ? (queryText.includes("status = 'PENDING'") ? values[3] : values[2]) : null;
            const targetToken = values ? (queryText.includes("status = 'PENDING'") ? values[4] : values[3]) : null;
            if (targetId && targetToken) {
              wasIdle = wrapper.isIdle();
              if (!wasIdle) {
                throw new Error('PRECONDITION_FAILED: Client was not idle before initiating guarded mutation');
              }
              await wrapper.beginTransaction();
              try {
                const diagRes = await wrapper.query(
                  `SELECT id,
                          (id = $1) AS id_match,
                          (lease_token = $2) AS token_match,
                          (status = 'PROCESSING') AS status_match,
                          (lease_expires_at > clock_timestamp()) AS lease_active
                   FROM public.outbox_events
                   WHERE id = $1
                   FOR UPDATE`,
                  [targetId, targetToken]
                );
                lockResRows = diagRes?.rows || [];
                sameTimeDiag = lockResRows[0] || null;
                const res = await wrapper.query(queryText, values);
                await wrapper.commitTransaction();
                capturedUpdateRowCounts.push({
                  sql: queryText,
                  values,
                  rowCount: res?.rowCount ?? null,
                  sameTimeDiagnostic: sameTimeDiag,
                  lockResultRows: lockResRows,
                  wasIdleBefore: wasIdle,
                  transactionOwnedByWrapper: true,
                  transactionCommitted: wrapper.wasCommittedSuccessfully(),
                  lifecycleHistory: wrapper.getLifecycleHistory(),
                  lastTransactionOperations: wrapper.getLastTransactionOperations(),
                });
                return res;
              } catch (err) {
                await wrapper.rollbackTransaction();
                throw err;
              }
            }
          }
          const res = await wrapper.query(queryText, values);
          if (typeof queryText === 'string' && queryText.includes('UPDATE outbox_events')) {
            capturedUpdateRowCounts.push({
              sql: queryText,
              values,
              rowCount: res?.rowCount ?? null,
              sameTimeDiagnostic: sameTimeDiag,
              lockResultRows: lockResRows,
              wasIdleBefore: wasIdle,
              transactionOwnedByWrapper: wasIdle,
              transactionCommitted: wrapper.wasCommittedSuccessfully(),
              lifecycleHistory: wrapper.getLifecycleHistory(),
              lastTransactionOperations: wrapper.getLastTransactionOperations(),
            });
          }
          return res;
        },
        release: async () => await wrapper.release(),
      };
      return client as any;
    };

    try {
      const worker = new OutboxRevocationProcessor({
        pool: poolWorker as any,
        r2Storage: r2FailingWorker as any,
        purgeService: { purgePhoto: async () => ({ success: true }), purgeWedding: async () => ({ success: true }) } as any,
        doCoordinator: { revokePhoto: async () => {}, revokeWedding: async () => {}, isWeddingRevoked: async () => false, isPhotoRevoked: async () => false } as any,
        leaseDurationSeconds: 60,
        strictRevocationMode: false,
        targetWeddingId: testWeddingId,
        targetEventId: eventId,
      });

      // 1. Worker A acquires the event
      workerPromise = worker.processBatch(1);
      await workerStarted;

      // Verify Worker A claimed event: status is PROCESSING, retry_count is 0, lease_token assigned
      const activeState = await pool.query(
        `SELECT status, retry_count, lease_token, lease_expires_at FROM outbox_events WHERE id = $1`,
        [eventId]
      );
      expect(activeState.rows[0].status).toBe('PROCESSING');
      expect(activeState.rows[0].retry_count).toBe(0);
      const originalToken = activeState.rows[0].lease_token;
      expect(originalToken).toBeTruthy();

      // 2. Expire Worker A's lease in PostgreSQL (simulating timeout during R2 operation)
      await pool.query(
        `UPDATE outbox_events
         SET lease_expires_at = clock_timestamp() - INTERVAL '1 second'
         WHERE id = $1`,
        [eventId]
      );

      // 3. NO Worker B reclaim is executed! The row in PostgreSQL still has lease_token = originalToken!
      const expiredState = await pool.query(
        `SELECT status, retry_count, lease_token, lease_expires_at FROM outbox_events WHERE id = $1`,
        [eventId]
      );
      expect(expiredState.rows[0].lease_token).toBe(originalToken); // Token still matches!
      expect(new Date(expiredState.rows[0].lease_expires_at).getTime()).toBeLessThan(Date.now());

      // 4. Resume Worker A: R2 throws, Worker A enters catch block and attempts retry escalation
      workerResumeResolve();
      await workerPromise;

      // Direct RowCount Assertion & Full Predicate / Value Proof (F15.5):
      // Directly assert that retryRes.rowCount was exactly 0 when Worker A executed the retry update
      const retryMutation = capturedUpdateRowCounts.find(
        (m) => m.sql.includes("status = 'PENDING'") && m.sql.includes('retry_count = $1')
      );
      expect(retryMutation).toBeDefined();
      expect(retryMutation!.rowCount).toBe(0); // DIRECT AFFECTED-ROW ASSERTION: exactly 0 rows affected!

      // Full captured retry SQL assertion:
      const expectedRetrySqlNormalized = `UPDATE outbox_events SET status = 'PENDING', lease_token = NULL, lease_expires_at = NULL, retry_count = $1, last_error = $2, payload = $3::jsonb, updated_at = clock_timestamp() WHERE id = $4 AND lease_token = $5 AND status = 'PROCESSING' AND lease_expires_at > clock_timestamp()`;
      expect(retryMutation!.sql.replace(/\s+/g, ' ').trim()).toBe(expectedRetrySqlNormalized);

      // Full captured parameter array assertion with exact equality (F15.5 Revision 16):
      const expectedErrorMessage = 'Simulated transient R2 500 error triggering failure retry | previous: none';
      // In PostgreSQL jsonb storage, keys are canonically returned and serialized as:
      // photoId, manifest, failedKeys, deletedKeys, weddingSlug
      const expectedPayload = JSON.stringify({
        photoId,
        manifest: { keys: manifestKeys },
        failedKeys: [],
        deletedKeys: [],
        weddingSlug,
      });
      const expectedRetryParams = [
        1, // newRetryCount: incremented from 0 to 1
        expectedErrorMessage, // exact deterministically constructed last_error
        expectedPayload, // independently constructed serialized payload string (F15.5 Revision 16)
        String(eventId), // target event ID
        originalToken, // target Worker A lease token
      ];
      expect(retryMutation!.values).toEqual(expectedRetryParams);
      expect(JSON.parse(retryMutation!.values![2])).toEqual({
        photoId,
        weddingSlug,
        manifest: { keys: manifestKeys },
        deletedKeys: [],
        failedKeys: [],
      });

      // Immediately Pre-Mutation Diagnostic Observation (captured on exact client connection immediately prior to update):
      // Under controlled concurrency, this observation proves that id_match, token_match, and status_match were all true,
      // and lease expiry (lease_active: false) was the sole disqualifying condition.
      expect(retryMutation!.lockResultRows).toBeDefined();
      expect(retryMutation!.lockResultRows).toHaveLength(1);
      expect(retryMutation!.lockResultRows![0].id).toBe(String(eventId));
      expect(retryMutation!.lockResultRows![0].id_match).toBe(true);
      expect(retryMutation!.lockResultRows![0].token_match).toBe(true);
      expect(retryMutation!.lockResultRows![0].status_match).toBe(true);
      expect(retryMutation!.lockResultRows![0].lease_active).toBe(false); // Sole failed predicate immediately prior to mutation!
      expect(retryMutation!.wasIdleBefore).toBe(true); // Demonstrates client was transaction-idle
      expect(retryMutation!.transactionOwnedByWrapper).toBe(true); // Proves wrapper owned the row-lock transaction
      expect(retryMutation!.transactionCommitted).toBe(true); // Proves transaction completed and committed successfully
      const lifecycleOps = retryMutation!.lastTransactionOperations!.map((h: any) => h.op);
      expect(lifecycleOps).toEqual(['BEGIN', 'QUERY', 'QUERY', 'COMMIT']);

      // 5 & 6. Verify core fencing invariant:
      // The retry update query touched ZERO rows because lease_expires_at was in the past.
      // Therefore, retry_count was NOT incremented (remains 0) and status was NOT modified.
      // Furthermore, every mutable field (last_error, payload, lease_token, lease_expires_at)
      // remains completely unmodified from the expired state.
      const postRetryState = await pool.query(
        `SELECT status, retry_count, lease_token, last_error, payload, lease_expires_at FROM outbox_events WHERE id = $1`,
        [eventId]
      );
      expect(postRetryState.rows[0].status).toBe('PROCESSING');
      expect(postRetryState.rows[0].retry_count).toBe(0); // UNCHANGED! Not incremented to 1!
      expect(postRetryState.rows[0].lease_token).toBe(originalToken); // Lease token untouched!
      expect(postRetryState.rows[0].last_error).toBeNull(); // Error message not written!
      expect(postRetryState.rows[0].payload.deletedKeys).toEqual([]); // Payload not modified!
      expect(new Date(postRetryState.rows[0].lease_expires_at).getTime()).toBeLessThan(Date.now());
    } finally {
      try { workerResumeResolve?.(); } catch {}
      if (workerPromise) {
        await Promise.allSettled([workerPromise]);
      }
      await poolWorker.end().catch(() => {});
      try {
        await pool.query(`DELETE FROM outbox_events WHERE id = $1`, [eventId!]);
      } catch {}
    }
  }, 15000);

  it('F15.5 Expiry Fencing on Dead-Letter Escalation: Worker A whose lease expired cannot dead-letter event (dlRes.rowCount === 0) even when max retries exceeded', async () => {
    // ------------------------------------------------------------------ //
    // Fencing invariant across ALL catch mutations (Auditor P0 Requirement):
    // 1. Worker A acquires event at retry_count = 3 (max_retries = 4, so failure hits DEAD_LETTER path).
    // 2. Worker A's lease expires in PostgreSQL.
    // 3. Worker A fails in R2 and attempts dead-letter transition:
    //    UPDATE outbox_events SET status = 'DEAD_LETTER' ... WHERE ... AND lease_expires_at > clock_timestamp()
    // 4. Directly assert dlRes.rowCount === 0.
    // 5. In PostgreSQL: status remains 'PROCESSING', retry_count remains 3 (NOT moved to DEAD_LETTER).
    // ------------------------------------------------------------------ //
    const ts = Date.now();
    const photoId = `f155-deadletter-fencing-${ts}`;
    const weddingSlug = 'meera-arjun-2027';
    const manifestKeys = [`originals/${weddingSlug}/${photoId}-orig.jpg`];

    const setupClient = await pool.connect();
    let eventId: number;
    try {
      const evRes = await setupClient.query(
        `INSERT INTO outbox_events (event_type, wedding_id, payload, status, retry_count, max_retries, created_at)
         VALUES ('PHOTO_DELETED', $1, $2::jsonb, 'PENDING', 3, 4, clock_timestamp())
         RETURNING id`,
        [
          testWeddingId,
          JSON.stringify({
            photoId,
            weddingSlug,
            manifest: { keys: manifestKeys },
            deletedKeys: [],
            failedKeys: [],
          }),
        ]
      );
      eventId = Number(evRes.rows[0].id);
    } finally {
      setupClient.release();
    }

    let workerStartedResolve!: () => void;
    const workerStarted = new Promise<void>((r) => { workerStartedResolve = r; });
    let workerResumeResolve!: () => void;
    const workerResume = new Promise<void>((r) => { workerResumeResolve = r; });

    const r2FailingWorker = {
      deletePhotoObjects: async (_slug: string, pId: string) => {
        if (pId !== photoId) throw new Error(`UNEXPECTED_PHOTO_ID: Expected ${photoId}, got ${pId}`);
        workerStartedResolve();
        await workerResume;
        throw new Error('Terminal R2 500 error exceeding max retries');
      },
    };

    const poolWorker = new pg.Pool({ ...localDbConfig, max: 2 });
    let workerPromise: Promise<any> | undefined;

    // Direct Query Instrumentation: captures every UPDATE query, full values, raw execution rowCount result,
    // transaction state ownership, and an exact same-time pre-mutation diagnostic executed under exclusive row lock
    const capturedUpdateRowCounts: {
      sql: string;
      values?: any[];
      rowCount: number | null;
      sameTimeDiagnostic?: { id_match: boolean; token_match: boolean; status_match: boolean; lease_active: boolean } | null;
      lockResultRows?: any[];
      wasIdleBefore?: boolean;
      transactionOwnedByWrapper?: boolean;
      transactionCommitted?: boolean;
      lifecycleHistory?: any[];
      lastTransactionOperations?: any[];
    }[] = [];
    const origConnect = poolWorker.connect.bind(poolWorker);
    poolWorker.connect = async () => {
      const rawClient = await origConnect();
      const wrapper = new AuthoritativeClientWrapper(rawClient);
      const client = {
        ...rawClient,
        query: async (queryText: any, values?: any) => {
          let sameTimeDiag: any = null;
          let lockResRows: any = null;
          let wasIdle = false;
          if (
            typeof queryText === 'string' &&
            queryText.includes('UPDATE outbox_events') &&
            (queryText.includes("status = 'PENDING'") || queryText.includes("status = 'DEAD_LETTER'"))
          ) {
            const targetId = values ? (queryText.includes("status = 'PENDING'") ? values[3] : values[2]) : null;
            const targetToken = values ? (queryText.includes("status = 'PENDING'") ? values[4] : values[3]) : null;
            if (targetId && targetToken) {
              wasIdle = wrapper.isIdle();
              if (!wasIdle) {
                throw new Error('PRECONDITION_FAILED: Client was not idle before initiating guarded mutation');
              }
              await wrapper.beginTransaction();
              try {
                const diagRes = await wrapper.query(
                  `SELECT id,
                          (id = $1) AS id_match,
                          (lease_token = $2) AS token_match,
                          (status = 'PROCESSING') AS status_match,
                          (lease_expires_at > clock_timestamp()) AS lease_active
                   FROM public.outbox_events
                   WHERE id = $1
                   FOR UPDATE`,
                  [targetId, targetToken]
                );
                lockResRows = diagRes?.rows || [];
                sameTimeDiag = lockResRows[0] || null;
                const res = await wrapper.query(queryText, values);
                await wrapper.commitTransaction();
                capturedUpdateRowCounts.push({
                  sql: queryText,
                  values,
                  rowCount: res?.rowCount ?? null,
                  sameTimeDiagnostic: sameTimeDiag,
                  lockResultRows: lockResRows,
                  wasIdleBefore: wasIdle,
                  transactionOwnedByWrapper: true,
                  transactionCommitted: wrapper.wasCommittedSuccessfully(),
                  lifecycleHistory: wrapper.getLifecycleHistory(),
                  lastTransactionOperations: wrapper.getLastTransactionOperations(),
                });
                return res;
              } catch (err) {
                await wrapper.rollbackTransaction();
                throw err;
              }
            }
          }
          const res = await wrapper.query(queryText, values);
          if (typeof queryText === 'string' && queryText.includes('UPDATE outbox_events')) {
            capturedUpdateRowCounts.push({
              sql: queryText,
              values,
              rowCount: res?.rowCount ?? null,
              sameTimeDiagnostic: sameTimeDiag,
              lockResultRows: lockResRows,
              wasIdleBefore: wasIdle,
              transactionOwnedByWrapper: wasIdle,
              transactionCommitted: wrapper.wasCommittedSuccessfully(),
              lifecycleHistory: wrapper.getLifecycleHistory(),
              lastTransactionOperations: wrapper.getLastTransactionOperations(),
            });
          }
          return res;
        },
        release: async () => await wrapper.release(),
      };
      return client as any;
    };

    try {
      const worker = new OutboxRevocationProcessor({
        pool: poolWorker as any,
        r2Storage: r2FailingWorker as any,
        purgeService: { purgePhoto: async () => ({ success: true }), purgeWedding: async () => ({ success: true }) } as any,
        doCoordinator: { revokePhoto: async () => {}, revokeWedding: async () => {}, isWeddingRevoked: async () => false, isPhotoRevoked: async () => false } as any,
        leaseDurationSeconds: 60,
        strictRevocationMode: false,
        targetWeddingId: testWeddingId,
        targetEventId: eventId,
      });

      // 1. Worker A acquires event at retry_count = 3
      workerPromise = worker.processBatch(1);
      await workerStarted;

      const activeState = await pool.query(
        `SELECT status, retry_count, lease_token FROM outbox_events WHERE id = $1`,
        [eventId]
      );
      expect(activeState.rows[0].status).toBe('PROCESSING');
      expect(activeState.rows[0].retry_count).toBe(3);
      const originalToken = activeState.rows[0].lease_token;
      expect(originalToken).toBeTruthy();

      // 2. Expire Worker A's lease in PostgreSQL
      await pool.query(
        `UPDATE outbox_events SET lease_expires_at = clock_timestamp() - INTERVAL '1 second' WHERE id = $1`,
        [eventId]
      );

      // 3. Resume Worker A: R2 throws, newRetryCount = 4 >= maxRetries (4), enters DEAD_LETTER branch
      workerResumeResolve();
      await workerPromise;

      // 4. Direct RowCount Assertion & Full Predicate / Value Proof (F15.5):
      const deadLetterMutation = capturedUpdateRowCounts.find(
        (m) => m.sql.includes("status = 'DEAD_LETTER'")
      );
      expect(deadLetterMutation).toBeDefined();
      expect(deadLetterMutation!.rowCount).toBe(0); // DIRECT AFFECTED-ROW ASSERTION: exactly 0 rows affected!

      // Full captured dead-letter SQL assertion:
      const expectedDlSqlNormalized = `UPDATE outbox_events SET status = 'DEAD_LETTER', lease_token = NULL, lease_expires_at = NULL, retry_count = $1, last_error = $2, updated_at = clock_timestamp() WHERE id = $3 AND lease_token = $4 AND status = 'PROCESSING' AND lease_expires_at > clock_timestamp()`;
      expect(deadLetterMutation!.sql.replace(/\s+/g, ' ').trim()).toBe(expectedDlSqlNormalized);

      // Full captured parameter array assertion with exact equality (F15.5 Revision 15):
      const expectedDeadLetterParams = [
        4, // newRetryCount: 3 + 1 = 4 >= max_retries (4)
        'TERMINAL_FAILURE_MAX_RETRIES: Terminal R2 500 error exceeding max retries | original_error: initial_failure',
        String(eventId),
        originalToken,
      ];
      expect(deadLetterMutation!.values).toEqual(expectedDeadLetterParams);

      // Immediately Pre-Mutation Diagnostic Observation (captured on exact client connection immediately prior to update):
      // Under controlled concurrency, this observation proves that id_match, token_match, and status_match were all true,
      // and lease expiry (lease_active: false) was the sole disqualifying condition.
      expect(deadLetterMutation!.lockResultRows).toBeDefined();
      expect(deadLetterMutation!.lockResultRows).toHaveLength(1);
      expect(deadLetterMutation!.lockResultRows![0].id).toBe(String(eventId));
      expect(deadLetterMutation!.lockResultRows![0].id_match).toBe(true);
      expect(deadLetterMutation!.lockResultRows![0].token_match).toBe(true);
      expect(deadLetterMutation!.lockResultRows![0].status_match).toBe(true);
      expect(deadLetterMutation!.lockResultRows![0].lease_active).toBe(false); // Sole failed predicate immediately prior to mutation!
      expect(deadLetterMutation!.wasIdleBefore).toBe(true); // Demonstrates client was transaction-idle
      expect(deadLetterMutation!.transactionOwnedByWrapper).toBe(true); // Proves wrapper owned the row-lock transaction
      expect(deadLetterMutation!.transactionCommitted).toBe(true); // Proves transaction completed and committed successfully
      const dlLifecycleOps = deadLetterMutation!.lastTransactionOperations!.map((h: any) => h.op);
      expect(dlLifecycleOps).toEqual(['BEGIN', 'QUERY', 'QUERY', 'COMMIT']);

      // 5. In PostgreSQL: status remains PROCESSING, retry_count remains 3, lease_token untouched
      const postDlState = await pool.query(
        `SELECT status, retry_count, lease_token, last_error FROM outbox_events WHERE id = $1`,
        [eventId]
      );
      expect(postDlState.rows[0].status).toBe('PROCESSING');
      expect(postDlState.rows[0].retry_count).toBe(3); // UNCHANGED! Not escalated to DEAD_LETTER!
      expect(postDlState.rows[0].lease_token).toBe(originalToken); // Untouched!
      expect(postDlState.rows[0].last_error).toBeNull();
    } finally {
      try { workerResumeResolve?.(); } catch {}
      if (workerPromise) {
        await Promise.allSettled([workerPromise]);
      }
      await poolWorker.end().catch(() => {});
      try {
        await pool.query(`DELETE FROM outbox_events WHERE id = $1`, [eventId!]);
      } catch {}
    }
  }, 15000);

  it('F15.5 Failure-Path Rollback: intermediate query failure inside authoritative transaction wrapper executes rollback, restoring idle state without committing partial mutations', async () => {
    const ts = Date.now();
    const photoId = `f155-rollback-${ts}`;
    const weddingSlug = 'meera-arjun-2027';
    const rawClient = await pool.connect();
    const wrapper = new AuthoritativeClientWrapper(rawClient);

    let eventId: number | null = null;
    try {
      // 1. Seed a test outbox row
      const seedRes = await pool.query(
        `INSERT INTO public.outbox_events (
           wedding_id, event_type, payload, status, retry_count, max_retries
         ) VALUES ($1, 'PHOTO_DELETED', $2::jsonb, 'PENDING', 0, 4)
         RETURNING id`,
        [testWeddingId, JSON.stringify({ photoId, weddingSlug })]
      );
      eventId = seedRes.rows[0].id;

      // 2. Authoritative idle pre-condition check
      expect(wrapper.isIdle()).toBe(true);
      expect(wrapper.isInTransaction()).toBe(false);

      // 3. Initiate guarded transaction
      await wrapper.beginTransaction();
      expect(wrapper.isIdle()).toBe(false);
      expect(wrapper.isInTransaction()).toBe(true);

      // 4. Execute a mutation within the transaction
      await wrapper.query(
        `UPDATE public.outbox_events SET status = 'PROCESSING', last_error = 'intermediate_probe' WHERE id = $1`,
        [eventId]
      );

      // 5. Trigger an intentional failure on an intermediate query
      let errorCaught = false;
      try {
        // Execute malformed SQL or constraint violation to simulate unexpected mid-flight failure
        await wrapper.query(`SELECT * FROM nonexistent_table_for_rollback_test`);
      } catch (err: any) {
        errorCaught = true;
        // Authoritative rollback on failure path:
        await wrapper.rollbackTransaction();
      }

      // 6. Assert failure-path transaction state restoration
      expect(errorCaught).toBe(true);
      expect(wrapper.isInTransaction()).toBe(false);
      expect(wrapper.isIdle()).toBe(true); // Restored to idle!
      expect(wrapper.wasRolledBack()).toBe(true);
      expect(wrapper.wasCommittedSuccessfully()).toBe(false);

      const ops = wrapper.getLifecycleHistory().map((h) => h.op);
      expect(ops).toContain('BEGIN');
      expect(ops).toContain('QUERY');
      expect(ops).toContain('QUERY_FAILED');
      expect(ops).toContain('ROLLBACK');

      // 7. Verify atomic database rollback: row status remains PENDING and last_error is null!
      const postRollbackRes = await pool.query(
        `SELECT status, last_error FROM public.outbox_events WHERE id = $1`,
        [eventId]
      );
      expect(postRollbackRes.rows[0].status).toBe('PENDING'); // Mutation was completely rolled back!
      expect(postRollbackRes.rows[0].last_error).toBeNull();
    } finally {
      await wrapper.release();
      if (eventId) {
        await pool.query(`DELETE FROM public.outbox_events WHERE id = $1`, [eventId]).catch(() => {});
      }
    }
  });

  it('F15.5 Automatic Rollback on Release: uncommitted transaction is automatically rolled back and awaited prior to client release', async () => {
    const ts = Date.now();
    const photoId = `f155-autorelease-${ts}`;
    const weddingSlug = 'meera-arjun-2027';
    const rawClient = await pool.connect();
    const wrapper = new AuthoritativeClientWrapper(rawClient);

    let eventId: number | null = null;
    try {
      // 1. Seed a test outbox row
      const seedRes = await pool.query(
        `INSERT INTO public.outbox_events (
           wedding_id, event_type, payload, status, retry_count, max_retries
         ) VALUES ($1, 'PHOTO_DELETED', $2::jsonb, 'PENDING', 0, 4)
         RETURNING id`,
        [testWeddingId, JSON.stringify({ photoId, weddingSlug })]
      );
      eventId = seedRes.rows[0].id;

      // 2. Start a transaction and mutate the row
      await wrapper.beginTransaction();
      await wrapper.query(
        `UPDATE public.outbox_events SET status = 'PROCESSING', last_error = 'uncommitted_mutation' WHERE id = $1`,
        [eventId]
      );

      // 3. Instead of committing or manually rolling back, invoke release directly
      // This simulates a worker crashing or exiting a scope while a transaction is active.
      await wrapper.release();

      // 4. Verify wrapper state: properly released, transaction cleared, and not destroyed
      expect(wrapper.isReleasedWrapper()).toBe(true);
      expect(wrapper.isDiscarded()).toBe(false);
      expect(wrapper.isInTransaction()).toBe(false);
      expect(wrapper.wasRolledBack()).toBe(true);
      const ops = wrapper.getLifecycleHistory().map((h) => h.op);
      expect(ops).toContain('ROLLBACK_ON_RELEASE');

      // 5. Verify database: the uncommitted update was rolled back before release completed!
      const postState = await pool.query(
        `SELECT status, last_error FROM public.outbox_events WHERE id = $1`,
        [eventId]
      );
      expect(postState.rows[0].status).toBe('PENDING'); // Automatically rolled back!
      expect(postState.rows[0].last_error).toBeNull();
    } finally {
      if (eventId) {
        await pool.query(`DELETE FROM public.outbox_events WHERE id = $1`, [eventId]).catch(() => {});
      }
    }
  });

  it('F15.5 Rollback Failure Destruction: database connection is destroyed via client.release(err) rather than returned cleanly to pool when rollback fails', async () => {
    let releaseErrorPassed: any = null;
    let destroyCalled = false;
    const mockRawClient = {
      query: vi.fn().mockImplementation(async (sql: string) => {
        if (sql.trim().toUpperCase() === 'ROLLBACK') {
          throw new Error('SIMULATED_DATABASE_CONNECTION_RESET_DURING_ROLLBACK');
        }
        return { rows: [], rowCount: 1 };
      }),
      release: vi.fn().mockImplementation((err?: any) => {
        releaseErrorPassed = err;
      }),
      destroy: vi.fn().mockImplementation(() => {
        destroyCalled = true;
      }),
    };

    const wrapper = new AuthoritativeClientWrapper(mockRawClient);
    await wrapper.beginTransaction();

    // Invoking release while in transaction will attempt rollback; simulated rollback fails
    await expect(wrapper.release()).rejects.toThrow(
      /CRITICAL_CLEANUP_FAILURE: Database rollback failed during release, connection destroyed/
    );

    // 1. Assert wrapper is NOT marked idle (it is destroyed and marked unsafe)
    expect(wrapper.isIdle()).toBe(false);
    expect(wrapper.isDiscarded()).toBe(true);

    // 2. Assert error was passed to driver's release(err) mechanism to discard connection from pool
    expect(mockRawClient.release).toHaveBeenCalledWith(expect.any(Error));
    expect(releaseErrorPassed).toBeDefined();
    expect(releaseErrorPassed.message).toBe('SIMULATED_DATABASE_CONNECTION_RESET_DURING_ROLLBACK');

    // 3. Assert original error is preserved
    expect(wrapper.getRollbackError()?.message).toBe('SIMULATED_DATABASE_CONNECTION_RESET_DURING_ROLLBACK');
  });

  it('F15.5 Released Wrapper Invalidation: attempting to execute queries on a released wrapper strictly throws ILLEGAL_STATE', async () => {
    const rawClient = await pool.connect();
    const wrapper = new AuthoritativeClientWrapper(rawClient);
    await wrapper.release();

    // 1. Calling query on released wrapper throws
    await expect(wrapper.query('SELECT 1')).rejects.toThrow(
      /ILLEGAL_STATE: Cannot query on released or destroyed connection wrapper/
    );

    // 2. Calling beginTransaction on released wrapper throws
    await expect(wrapper.beginTransaction()).rejects.toThrow(
      /ILLEGAL_STATE: Cannot begin transaction on released or destroyed connection wrapper/
    );

    // 3. Calling release again on released wrapper throws
    await expect(wrapper.release()).rejects.toThrow(
      /ILLEGAL_STATE: Connection wrapper has already been released/
    );
  });
});

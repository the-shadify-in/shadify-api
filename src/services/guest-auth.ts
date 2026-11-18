import crypto from 'node:crypto';
import pg from 'pg';

/**
 * Guest Authentication & Gallery Authorization Service
 * Remediates Finding F10: Device UUID is an identifier, not a credential.
 * Remediates Finding F13: Cryptographically signed PIN session tokens, distributed rate limiting, and durable revocation.
 * Remediates Finding F14: Strict visibility enforcement (public vs family/private vs rejected).
 */

export interface GuestTokenClaims {
  iss: 'shadify-api';
  aud: 'shadify-guest';
  weddingSlug: string;
  guestFingerprint: string;
  issuedAt: number;
  expiresAt: number;
}

export type PhotoVisibility = 'visibility_public' | 'visibility_family' | 'visibility_private';
export type PhotoStatus = 'processing' | 'pending_review' | 'approved' | 'rejected';

export interface PhotoRecord {
  id: string;
  weddingId: string;
  weddingSlug: string;
  status: PhotoStatus;
  visibility: PhotoVisibility;
  keyThumb: string;
  keyPreview: string;
}

export interface DurableGuestRateLimiter {
  recordAttempt(
    ip: string,
    weddingSlug: string,
    isSuccess: boolean
  ): Promise<{ allowed: boolean; remainingAttempts: number; error?: string }>;
}

export class PostgresGuestRateLimiter implements DurableGuestRateLimiter {
  constructor(private pool: pg.Pool) {}

  async recordAttempt(
    ip: string,
    weddingSlug: string,
    isSuccess: boolean
  ): Promise<{ allowed: boolean; remainingAttempts: number; error?: string }> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      // Acquire transaction-scoped advisory lock on wedding slug (Finding 3)
      // Strictly serializes all concurrent PIN attempts for this wedding across distinct IP addresses,
      // preventing concurrent race conditions from bypassing the wedding-wide lockout threshold.
      await client.query(
        `SELECT pg_advisory_xact_lock(hashtext('wedding_pin_lock:' || $1))`,
        [weddingSlug]
      );

      // 1. Wedding-wide brute-force detection (distributed attack across multiple IPs)
      const weddingAgg = await client.query(
        `SELECT COALESCE(SUM(failed_attempts), 0)::int as total_failures 
         FROM guest_pin_attempts 
         WHERE wedding_slug = $1 AND window_start > NOW() - INTERVAL '15 minutes'`,
        [weddingSlug]
      );
      const totalFailures = weddingAgg.rows[0].total_failures;
      if (totalFailures >= 20) {
        await client.query('COMMIT');
        return {
          allowed: false,
          remainingAttempts: 0,
          error: 'WEDDING_PIN_LOCKED_OUT: Wedding gallery locked due to detected distributed brute-force attack (20+ cumulative failures).',
        };
      }

      // 2. IP + Wedding row check
      const res = await client.query(
        `SELECT failed_attempts, locked_until, window_start 
         FROM guest_pin_attempts 
         WHERE wedding_slug = $1 AND ip_address = $2 
         FOR UPDATE`,
        [weddingSlug, ip]
      );

      const now = new Date();

      if (res.rowCount && res.rowCount > 0) {
        const row = res.rows[0];
        if (row.locked_until && new Date(row.locked_until) > now) {
          const waitSec = Math.ceil((new Date(row.locked_until).getTime() - now.getTime()) / 1000);
          await client.query('COMMIT');
          return {
            allowed: false,
            remainingAttempts: 0,
            error: `PIN_RATE_LIMITED: Too many failed PIN attempts. Locked out for ${waitSec} seconds.`,
          };
        }

        // If window expired (> 15m), reset
        const windowAge = now.getTime() - new Date(row.window_start).getTime();
        let currentFailures = windowAge > 900000 ? 0 : row.failed_attempts;

        if (isSuccess) {
          await client.query(
            `DELETE FROM guest_pin_attempts WHERE wedding_slug = $1 AND ip_address = $2`,
            [weddingSlug, ip]
          );
          await client.query('COMMIT');
          return { allowed: true, remainingAttempts: 5 };
        }

        currentFailures += 1;
        if (currentFailures >= 5) {
          const lockedUntil = new Date(now.getTime() + 900000);
          await client.query(
            `UPDATE guest_pin_attempts 
             SET failed_attempts = $3, locked_until = $4 
             WHERE wedding_slug = $1 AND ip_address = $2`,
            [weddingSlug, ip, currentFailures, lockedUntil]
          );
          await client.query('COMMIT');
          return {
            allowed: false,
            remainingAttempts: 0,
            error: 'PIN_LOCKED_OUT: Maximum PIN attempts exceeded. IP locked for 15 minutes.',
          };
        }

        await client.query(
          `UPDATE guest_pin_attempts 
           SET failed_attempts = $3, locked_until = NULL 
           WHERE wedding_slug = $1 AND ip_address = $2`,
          [weddingSlug, ip, currentFailures]
        );
        await client.query('COMMIT');
        return { allowed: true, remainingAttempts: 5 - currentFailures };
      } else {
        // No prior attempts
        if (isSuccess) {
          await client.query('COMMIT');
          return { allowed: true, remainingAttempts: 5 };
        }

        await client.query(
          `INSERT INTO guest_pin_attempts (wedding_slug, ip_address, failed_attempts, window_start) 
           VALUES ($1, $2, 1, NOW())`,
          [weddingSlug, ip]
        );
        await client.query('COMMIT');
        return { allowed: true, remainingAttempts: 4 };
      }
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  /**
   * Universal Administrative Reset for an entire wedding gallery (Finding 3)
   * Acquires the identical advisory lock namespace to prevent race conditions during admin intervention.
   */
  async adminResetWedding(weddingSlug: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        `SELECT pg_advisory_xact_lock(hashtext('wedding_pin_lock:' || $1))`,
        [weddingSlug]
      );
      await client.query(`DELETE FROM guest_pin_attempts WHERE wedding_slug = $1`, [weddingSlug]);
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  /**
   * Universal Administrative Reset for a single IP within a wedding gallery (Finding 3)
   * Acquires the identical advisory lock namespace.
   */
  async adminResetIp(weddingSlug: string, ip: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        `SELECT pg_advisory_xact_lock(hashtext('wedding_pin_lock:' || $1))`,
        [weddingSlug]
      );
      await client.query(
        `DELETE FROM guest_pin_attempts WHERE wedding_slug = $1 AND ip_address = $2`,
        [weddingSlug, ip]
      );
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }
}

export class InMemoryGuestRateLimiter implements DurableGuestRateLimiter {
  private pinAttempts = new Map<string, { count: number; lockedUntil: number; windowStart: number }>();

  recordAttemptSync(
    ip: string,
    weddingSlug: string,
    isSuccess: boolean
  ): { allowed: boolean; remainingAttempts: number; error?: string } {
    const key = `${ip}:${weddingSlug}`;
    const now = Date.now();
    const entry = this.pinAttempts.get(key) || { count: 0, lockedUntil: 0, windowStart: now };

    if (now < entry.lockedUntil) {
      const waitSec = Math.ceil((entry.lockedUntil - now) / 1000);
      return {
        allowed: false,
        remainingAttempts: 0,
        error: `PIN_RATE_LIMITED: Too many failed PIN attempts. Locked out for ${waitSec} seconds.`,
      };
    }

    if (now - entry.windowStart > 900000) {
      entry.count = 0;
      entry.windowStart = now;
      entry.lockedUntil = 0;
    }

    if (isSuccess) {
      this.pinAttempts.delete(key);
      return { allowed: true, remainingAttempts: 5 };
    }

    entry.count += 1;
    if (entry.count >= 5) {
      entry.lockedUntil = now + 900000;
      this.pinAttempts.set(key, entry);
      return {
        allowed: false,
        remainingAttempts: 0,
        error: 'PIN_LOCKED_OUT: Maximum PIN attempts exceeded. IP locked for 15 minutes.',
      };
    }

    this.pinAttempts.set(key, entry);
    return { allowed: true, remainingAttempts: 5 - entry.count };
  }

  async recordAttempt(
    ip: string,
    weddingSlug: string,
    isSuccess: boolean
  ): Promise<{ allowed: boolean; remainingAttempts: number; error?: string }> {
    return this.recordAttemptSync(ip, weddingSlug, isSuccess);
  }
}

export interface DurableGuestRevocationStore {
  isTokenRevoked(token: string): Promise<boolean>;
  revokeToken(token: string, expiresAt: Date): Promise<void>;
}

export class PostgresGuestRevocationStore implements DurableGuestRevocationStore {
  constructor(private pool: pg.Pool) {}

  async isTokenRevoked(token: string): Promise<boolean> {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const client = await this.pool.connect();
    try {
      const res = await client.query(
        `SELECT 1 FROM revoked_guest_tokens WHERE token_hash = $1 AND expires_at > NOW()`,
        [tokenHash]
      );
      return (res.rowCount ?? 0) > 0;
    } finally {
      client.release();
    }
  }

  async revokeToken(token: string, expiresAt: Date): Promise<void> {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const client = await this.pool.connect();
    try {
      await client.query(
        `INSERT INTO revoked_guest_tokens (token_hash, expires_at) 
         VALUES ($1, $2) 
         ON CONFLICT (token_hash) DO NOTHING`,
        [tokenHash, expiresAt]
      );
    } finally {
      client.release();
    }
  }
}

export class InMemoryGuestRevocationStore implements DurableGuestRevocationStore {
  private revokedTokens = new Set<string>();

  async isTokenRevoked(token: string): Promise<boolean> {
    return this.revokedTokens.has(token) || GuestAuthorizationService.REVOKED_GUEST_TOKENS.has(token);
  }

  async revokeToken(token: string): Promise<void> {
    this.revokedTokens.add(token);
    GuestAuthorizationService.REVOKED_GUEST_TOKENS.add(token);
  }
}

export class GuestAuthorizationService {
  private static readonly GUEST_KEYS: Record<string, string> = {
    'key-guest-current': process.env.GUEST_TOKEN_SECRET || 'shadify-guest-hmac-jwt-secret-min32bytes!!',
    'key-guest-previous': 'shadify-guest-hmac-jwt-secret-previous-key-32ch',
  };

  public static activeKeyId = 'key-guest-current';
  public static readonly REVOKED_GUEST_TOKENS = new Set<string>();

  private static defaultRateLimiter: DurableGuestRateLimiter = new InMemoryGuestRateLimiter();
  private static defaultRevocationStore: DurableGuestRevocationStore = new InMemoryGuestRevocationStore();
  private static memoryLimiter = new InMemoryGuestRateLimiter();

  public static setDefaultPool(pool: pg.Pool) {
    this.defaultRateLimiter = new PostgresGuestRateLimiter(pool);
    this.defaultRevocationStore = new PostgresGuestRevocationStore(pool);
  }

  constructor(
    public rateLimiter: DurableGuestRateLimiter = new InMemoryGuestRateLimiter(),
    public revocationStore: DurableGuestRevocationStore = new InMemoryGuestRevocationStore()
  ) {}

  /**
   * Evaluates and records a PIN verification attempt synchronously in memory (F13 Fast Path).
   * 5 failed attempts locks the IP for 15 minutes.
   */
  static recordPinAttempt(
    ip: string,
    weddingSlug: string,
    isSuccess: boolean
  ): { allowed: boolean; remainingAttempts: number; error?: string } {
    return this.memoryLimiter.recordAttemptSync(ip, weddingSlug, isSuccess);
  }

  /**
   * Evaluates and records a PIN verification attempt against durable storage (PostgreSQL).
   */
  static async recordPinAttemptDurable(
    ip: string,
    weddingSlug: string,
    isSuccess: boolean
  ): Promise<{ allowed: boolean; remainingAttempts: number; error?: string }> {
    return this.defaultRateLimiter.recordAttempt(ip, weddingSlug, isSuccess);
  }

  /**
   * Signs a short-lived (max 24h) guest session token upon successful PIN verification.
   * Supports key rotation via `kid`.
   */
  static issueGuestToken(weddingSlug: string, guestFingerprint: string, ttlHours = 24, keyId?: string): string {
    const now = Date.now();
    const kid = keyId || this.activeKeyId;
    const secret = this.GUEST_KEYS[kid];
    if (!secret) {
      throw new Error(`Unknown guest keyId: ${kid}`);
    }

    const claims: GuestTokenClaims = {
      iss: 'shadify-api',
      aud: 'shadify-guest',
      weddingSlug,
      guestFingerprint,
      issuedAt: now,
      expiresAt: now + ttlHours * 3600 * 1000,
    };

    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid })).toString('base64url');
    const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
    const signature = crypto
      .createHmac('sha256', secret)
      .update(`${header}.${payload}`)
      .digest('base64url');

    return `${header}.${payload}.${signature}`;
  }

  /**
   * Cryptographically verifies a guest token and checks expiration, wedding slug, and revocation.
   */
  static verifyGuestToken(
    token: string,
    targetSlug: string
  ): { valid: boolean; claims?: GuestTokenClaims; error?: string } {
    if (this.REVOKED_GUEST_TOKENS.has(token)) {
      return { valid: false, error: 'TOKEN_REVOKED: Guest session has been explicitly revoked' };
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'MALFORMED_TOKEN' };
    }

    const [headerB64, payload, signature] = parts;

    let kid = this.activeKeyId;
    try {
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
      if (header.kid) {
        kid = header.kid;
      }
    } catch {
      return { valid: false, error: 'INVALID_HEADER_JSON' };
    }

    const secret = this.GUEST_KEYS[kid];
    if (!secret) {
      return { valid: false, error: `UNKNOWN_KEY_ID: ${kid}` };
    }

    const expectedSig = crypto
      .createHmac('sha256', secret)
      .update(`${headerB64}.${payload}`)
      .digest('base64url');

    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
      return { valid: false, error: 'INVALID_SIGNATURE' };
    }

    try {
      const claims: GuestTokenClaims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));

      if (claims.iss !== 'shadify-api' || claims.aud !== 'shadify-guest') {
        return { valid: false, error: 'INVALID_ISSUER_OR_AUDIENCE' };
      }

      if (claims.weddingSlug !== targetSlug) {
        return { valid: false, error: 'SLUG_MISMATCH: Token not valid for this wedding' };
      }

      if (Date.now() > claims.expiresAt) {
        return { valid: false, error: 'TOKEN_EXPIRED' };
      }

      return { valid: true, claims };
    } catch {
      return { valid: false, error: 'INVALID_CLAIMS_JSON' };
    }
  }

  /**
   * Cryptographically verifies a guest token and checks against the durable revocation store (PostgreSQL or In-Memory).
   */
  static async verifyGuestTokenDurable(
    token: string,
    targetSlug: string
  ): Promise<{ valid: boolean; claims?: GuestTokenClaims; error?: string }> {
    if (await this.defaultRevocationStore.isTokenRevoked(token)) {
      return { valid: false, error: 'TOKEN_REVOKED: Guest session has been explicitly revoked' };
    }
    return this.verifyGuestToken(token, targetSlug);
  }

  /**
   * Durably revokes a guest token.
   */
  static async revokeGuestTokenDurable(token: string, expiresAt: Date): Promise<void> {
    await this.defaultRevocationStore.revokeToken(token, expiresAt);
  }

  /**
   * Enforces guest authorization matrix across all operations (F10).
   * Strictly forbids privileged management operations (e.g. photo upload, deletion, settings).
   */
  static canPerformOperation(
    operation: 'view_photo' | 'toggle_favorite' | 'upload_photo' | 'delete_photo' | 'modify_settings',
    params: {
      weddingSlug: string;
      photo?: PhotoRecord;
      guestToken?: string;
    }
  ): { allowed: boolean; error?: string } {
    if (operation === 'upload_photo' || operation === 'delete_photo' || operation === 'modify_settings') {
      return {
        allowed: false,
        error: `GUEST_PRIVILEGE_VIOLATION: Operation '${operation}' is strictly reserved for operators and photographers. Guest tokens cannot perform management mutations.`,
      };
    }

    if (operation === 'toggle_favorite') {
      const res = this.authorizeFavoriteWrite({ weddingSlug: params.weddingSlug, guestToken: params.guestToken });
      return { allowed: res.authorized, error: res.error };
    }

    if (operation === 'view_photo') {
      if (!params.photo) return { allowed: false, error: 'PHOTO_NOT_PROVIDED' };
      const canView = this.canViewPhoto(params.photo, params.guestToken);
      return canView ? { allowed: true } : { allowed: false, error: 'PHOTO_ACCESS_DENIED' };
    }

    return { allowed: false, error: 'UNKNOWN_OPERATION' };
  }

  /**
   * Authorizes viewing of a photo based on visibility rules.
   * Public: any visitor.
   * Family/Private: requires valid PIN guest token for this wedding.
   * Rejected / Pending: hidden from all guest views.
   */
  static canViewPhoto(photo: PhotoRecord, guestToken?: string): boolean {
    // Rejected and processing photos are NEVER visible to guests
    if (photo.status !== 'approved') {
      return false;
    }

    // Public photos are visible to everyone
    if (photo.visibility === 'visibility_public') {
      return true;
    }

    // Family / Private photos require valid PIN session token
    if (!guestToken) {
      return false;
    }

    const verification = this.verifyGuestToken(guestToken, photo.weddingSlug);
    return verification.valid;
  }

  /**
   * Durably authorizes viewing of a photo based on visibility rules, checking PostgreSQL revocation store (F13).
   */
  static async canViewPhotoDurable(photo: PhotoRecord, guestToken?: string): Promise<boolean> {
    if (photo.status !== 'approved') {
      return false;
    }
    if (photo.visibility === 'visibility_public') {
      return true;
    }
    if (!guestToken) {
      return false;
    }
    const verification = await this.verifyGuestTokenDurable(guestToken, photo.weddingSlug);
    return verification.valid;
  }

  /**
   * Authorizes favorite write operations (F10).
   * Strictly rejects device UUID alone without a verified guest token.
   */
  static authorizeFavoriteWrite(params: {
    weddingSlug: string;
    guestToken?: string;
    deviceUuid?: string;
  }): { authorized: boolean; error?: string } {
    if (!params.guestToken) {
      return {
        authorized: false,
        error: 'UNAUTHORIZED: A device UUID alone does not authorize favorite writes. A valid guest session token is required.',
      };
    }

    const result = this.verifyGuestToken(params.guestToken, params.weddingSlug);
    if (!result.valid) {
      return {
        authorized: false,
        error: `INVALID_GUEST_SESSION: ${result.error}`,
      };
    }

    return { authorized: true };
  }
}


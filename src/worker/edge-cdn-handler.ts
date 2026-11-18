import crypto from 'node:crypto';
import {
  getCanonicalDurableObjectId,
  getCanonicalPhotoTombstoneKey,
  getCanonicalWeddingTombstoneKey,
} from '../services/outbox-processor.js';

export interface DurableObjectStubLike {
  isPhotoRevoked: (photoId: string, weddingSlug: string) => Promise<boolean>;
  isWeddingRevoked: (weddingSlug: string) => Promise<boolean>;
  revokePhoto?: (photoId: string, weddingSlug: string) => Promise<void>;
  revokeWedding?: (weddingSlug: string) => Promise<void>;
}

export interface DurableObjectNamespaceLike {
  idFromName: (name: string) => { toString: () => string };
  get: (id: { toString: () => string }) => DurableObjectStubLike;
}

export interface DurableObjectStorageLike {
  get<T = any>(key: string): Promise<T | undefined>;
  put<T = any>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
  list?(options?: any): Promise<Map<string, any>>;
}

export interface RevocationMetadata {
  eventId?: string;
  actorId?: string;
  reason?: string;
  timestamp?: string;
}

export interface RevocationRecord {
  revoked: boolean;
  revokedAt: string;
  weddingSlug: string;
  photoId?: string;
  eventId?: string;
  actorId?: string;
  reason?: string;
}

/**
 * Authoritative Wedding Revocation Coordinator (Cloudflare Workers Durable Object).
 * Invariant: DO instance identity === canonical wedding identity (`wedding:${weddingSlug}`).
 * Binds each coordinator instance strictly to its canonical wedding slug, rejecting
 * mismatched cross-tenant calls. Permanently persists structured revocation records
 * in DO storage with infinite retention and zero stale in-memory caching.
 */
export class WeddingRevocationCoordinator implements DurableObjectStubLike {
  private storage: DurableObjectStorageLike;
  private boundWeddingSlug: string | null = null;

  constructor(state: { storage: DurableObjectStorageLike }, _env?: any, initialSlug?: string) {
    this.storage = state.storage;
    if (initialSlug) {
      this.boundWeddingSlug = initialSlug;
    }
  }

  /**
   * Initializes or verifies the bound tenant identity for this Durable Object instance.
   * Enforces that DO instance identity is permanently coupled to the canonical wedding slug.
   */
  public async getOrAssertBoundSlug(suppliedSlug?: string): Promise<string> {
    if (!this.boundWeddingSlug) {
      const persistedSlug = await this.storage.get<string>('__bound_wedding_slug');
      if (persistedSlug) {
        this.boundWeddingSlug = persistedSlug;
      } else if (suppliedSlug) {
        this.boundWeddingSlug = suppliedSlug;
        await this.storage.put('__bound_wedding_slug', suppliedSlug);
      }
    }

    if (!this.boundWeddingSlug) {
      if (!suppliedSlug) {
        throw new Error('Durable Object instance has no bound wedding slug and none was supplied');
      }
      this.boundWeddingSlug = suppliedSlug;
      await this.storage.put('__bound_wedding_slug', suppliedSlug);
    }

    if (suppliedSlug && suppliedSlug !== this.boundWeddingSlug) {
      throw new Error(
        `Tenant isolation violation: Durable Object instance bound to "${this.boundWeddingSlug}" received request for mismatched slug "${suppliedSlug}"`
      );
    }

    return this.boundWeddingSlug;
  }

  async revokeWedding(weddingSlug: string, meta?: RevocationMetadata): Promise<void> {
    const slug = await this.getOrAssertBoundSlug(weddingSlug);
    const key = `wedding:${slug}:revoked`;

    // Idempotent: check if already revoked
    const existing = await this.storage.get<RevocationRecord | boolean>(key);
    if (existing && (typeof existing === 'boolean' ? existing : existing.revoked)) {
      return;
    }

    const record: RevocationRecord = {
      revoked: true,
      revokedAt: meta?.timestamp || new Date().toISOString(),
      weddingSlug: slug,
      eventId: meta?.eventId,
      actorId: meta?.actorId || 'system-outbox',
      reason: meta?.reason || 'WEDDING_REVOKED_LIFECYCLE',
    };

    // Tenant-scoped authoritative storage persistence (zero in-memory caching)
    await this.storage.put(key, record);
    await this.storage.put('wedding_revoked', record);
    await this.storage.put('wedding_revoked_at', Date.now());
  }

  async revokePhoto(photoId: string, weddingSlug?: string, meta?: RevocationMetadata): Promise<void> {
    if (!photoId) {
      throw new Error('photoId is required for photo-level revocation');
    }
    const slug = await this.getOrAssertBoundSlug(weddingSlug);
    const key = `wedding:${slug}:photo:${photoId}:revoked`;

    // Idempotent: check if already revoked
    const existing = await this.storage.get<RevocationRecord | boolean>(key);
    if (existing && (typeof existing === 'boolean' ? existing : existing.revoked)) {
      return;
    }

    const record: RevocationRecord = {
      revoked: true,
      revokedAt: meta?.timestamp || new Date().toISOString(),
      weddingSlug: slug,
      photoId,
      eventId: meta?.eventId,
      actorId: meta?.actorId || 'system-outbox',
      reason: meta?.reason || 'PHOTO_DELETED_LIFECYCLE',
    };

    // Tenant-scoped authoritative storage persistence (zero in-memory caching)
    await this.storage.put(key, record);
    await this.storage.put(`photo_revoked:${photoId}`, record);
    await this.storage.put(`photo_revoked_at:${photoId}`, Date.now());
  }

  async isWeddingRevoked(weddingSlug?: string): Promise<boolean> {
    const slug = await this.getOrAssertBoundSlug(weddingSlug);
    // Direct authoritative storage read on every decision (zero stale in-memory cache)
    const rec =
      (await this.storage.get<RevocationRecord | boolean>(`wedding:${slug}:revoked`)) ??
      (await this.storage.get<RevocationRecord | boolean>('wedding_revoked'));
    if (!rec) return false;
    return typeof rec === 'boolean' ? rec : rec.revoked;
  }

  async isPhotoRevoked(photoId: string, weddingSlug?: string): Promise<boolean> {
    if (!photoId) {
      throw new Error('photoId is required for photo-level revocation check');
    }
    const slug = await this.getOrAssertBoundSlug(weddingSlug);

    // Inheritance: if wedding is revoked, all photos in it are revoked
    if (await this.isWeddingRevoked(slug)) {
      return true;
    }

    // Direct authoritative storage read on every decision (zero stale in-memory cache)
    const rec =
      (await this.storage.get<RevocationRecord | boolean>(`wedding:${slug}:photo:${photoId}:revoked`)) ??
      (await this.storage.get<RevocationRecord | boolean>(`photo_revoked:${photoId}`));
    if (!rec) return false;
    return typeof rec === 'boolean' ? rec : rec.revoked;
  }
}

export class ProductionRevocationConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProductionRevocationConfigurationError';
  }
}

/**
 * Fixed-iteration byte comparison for security-sensitive tokens (F15.2).
 * Operates cross-runtime (Cloudflare Workers and Node.js) over fixed 128-byte buffers.
 * Enforces strict length bounds (0..128 characters) and guarantees exactly 128 XOR operations
 * for accepted inputs, mitigating length-dependent timing side channels during byte comparison.
 *
 * Operational Scope & Boundary:
 * - The comparison loop executes a fixed 128 iterations for inputs whose UTF-8 byte length is <= 128.
 * - String allocation, TextEncoder UTF-8 processing, and early validation returns for non-string
 *   or oversized inputs are acknowledged as input-dependent operations.
 * - JavaScript engine JIT and garbage collection do not provide absolute hardware-level constant-time guarantees.
 */
export function timingSafeEqualStrings(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length > 128 || b.length > 128) return false;

  const encoder = new TextEncoder();
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);

  if (aBytes.byteLength > 128 || bBytes.byteLength > 128) return false;

  const bufA = new Uint8Array(128);
  const bufB = new Uint8Array(128);
  bufA.set(aBytes);
  bufB.set(bBytes);

  let diff = aBytes.byteLength ^ bBytes.byteLength;
  for (let i = 0; i < 128; i++) {
    diff |= bufA[i] ^ bufB[i];
  }
  return diff === 0;
}

/**
 * Production Deployment Guard:
 * Asserts that strict revocation mode and the authoritative Durable Object binding are active.
 * Fails worker initialization or execution before serving live traffic if requirements are violated.
 */
export function parseConfigBoolean(val: unknown, defaultValue = false): boolean {
  if (typeof val === 'boolean') return val;
  if (typeof val === 'string') {
    const trimmed = val.trim().toLowerCase();
    if (trimmed === 'true' || trimmed === '1') return true;
    if (trimmed === 'false' || trimmed === '0' || trimmed === '') return false;
    throw new ProductionRevocationConfigurationError(`Invalid boolean configuration value: "${val}"`);
  }
  if (val === undefined || val === null) return defaultValue;
  throw new ProductionRevocationConfigurationError(`Invalid boolean configuration type: ${typeof val}`);
}

export function isProductionEnvironment(
  env: EdgeCdnEnv & { NODE_ENV?: string; ENVIRONMENT?: string; DEPLOYMENT_ENVIRONMENT?: string }
): boolean {
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

  // Conflicting environment declarations represent an unsafe operational state (F15.4)
  if (hasProd && hasNonProd) {
    const conflictDetails = declaredEnvs.map((e) => `${e.name}="${e.normalized}"`).join(', ');
    throw new ProductionRevocationConfigurationError(
      `Conflicting environment declarations detected: ${conflictDetails}. Fail-closed active.`
    );
  }

  return hasProd;
}

export function validateProductionRevocationConfig(
  env: EdgeCdnEnv & { NODE_ENV?: string; ENVIRONMENT?: string; DEPLOYMENT_ENVIRONMENT?: string }
): {
  valid: boolean;
  errors: string[];
} {
  const isExplicitProd = isProductionEnvironment(env);
  const errors: string[] = [];

  // In production, STRICT_REVOCATION_MODE must be explicitly set and valid
  let isStrictMode = false;
  try {
    if (isExplicitProd && (env.STRICT_REVOCATION_MODE === undefined || env.STRICT_REVOCATION_MODE === null)) {
      errors.push('CRITICAL: Production environment detected with missing STRICT_REVOCATION_MODE configuration.');
    } else {
      isStrictMode = parseConfigBoolean(env.STRICT_REVOCATION_MODE, false);
    }
  } catch (err: any) {
    errors.push(`CRITICAL: Malformed STRICT_REVOCATION_MODE: ${err.message}`);
  }

  let allowEventual = false;
  try {
    allowEventual = parseConfigBoolean(env.ALLOW_EVENTUAL_CONSISTENCY, false);
  } catch (err: any) {
    errors.push(`CRITICAL: Malformed ALLOW_EVENTUAL_CONSISTENCY: ${err.message}`);
  }

  // Production Environment Invariants:
  if (isExplicitProd) {
    if (!isStrictMode) {
      errors.push('CRITICAL: Production environment detected with STRICT_REVOCATION_MODE disabled or false.');
    }
    if (allowEventual) {
      errors.push('CRITICAL: Production environment detected with ALLOW_EVENTUAL_CONSISTENCY enabled.');
    }
    if (!env.WEDDING_REVOCATION_DO) {
      errors.push('CRITICAL: Production environment detected with missing WEDDING_REVOCATION_DO binding.');
    }
    if (!env.CDN_SIGNING_SECRET || env.CDN_SIGNING_SECRET.length < 32) {
      errors.push('CRITICAL: CDN_SIGNING_SECRET must be configured with at least 32 characters in production.');
    }
  }

  // Strict Revocation Invariants (applicable in any environment where strict mode is declared):
  if (isStrictMode) {
    if (!env.WEDDING_REVOCATION_DO) {
      errors.push('Strict revocation mode active: WEDDING_REVOCATION_DO binding is required.');
    }
    if (!env.CDN_SIGNING_SECRET || env.CDN_SIGNING_SECRET.length < 32) {
      errors.push('STRICT_REVOCATION_MODE active: CDN_SIGNING_SECRET must be at least 32 characters.');
    }
  }

  if (errors.length > 0) {
    if (isExplicitProd || isStrictMode) {
      throw new ProductionRevocationConfigurationError(
        `Production revocation configuration guard failed:\n- ${errors.join('\n- ')}`
      );
    }
    return { valid: false, errors };
  }

  return {
    valid: true,
    errors: [],
  };
}

/**
 * Canonical Wedding Slug Resolver (F15)
 * Resolves the tenant slug with strict validation and precedence:
 * 1. Derives route tenant from recognized media route prefixes:
 *    - `/v1/weddings/:slug/...`
 *    - `/weddings/:slug/...`
 *    - `/originals/:slug/...`
 *    - `/previews/:slug/...`
 *    - `/thumbnails/:slug/...`
 *    - `/watermarked/:slug/...`
 * 2. Enforces exact match between route-derived slug and any explicit slug query parameter.
 * 3. Media Route Restriction: Explicit slug CANNOT invent or override tenant identity on media routes.
 * 4. Rejects encoded separators (%2f, %5c), repeated separators (//), traversal (..), and malformed slugs.
 */
export function resolveCanonicalWeddingSlug(
  rawUrl: string,
  explicitSlug?: string | null,
  options?: { allowExplicitWithoutRoute?: boolean }
): string | null {
  let routeSlug: string | null = null;
  let isMediaRoute = false;

  // Defense against encoded separators, backslashes, repeated path separators, and path traversal
  if (
    rawUrl.includes('\\') ||
    rawUrl.replace(/^https?:\/\/[^\/]+/, '').includes('//') ||
    rawUrl.includes('..') ||
    rawUrl.toLowerCase().includes('%2f') ||
    rawUrl.toLowerCase().includes('%5c') ||
    rawUrl.toLowerCase().includes('%2e%2e')
  ) {
    return null;
  }

  try {
    const parsed = new URL(rawUrl, 'https://cdn.shadify.in');
    const pathname = parsed.pathname;

    // Media route prefix detection
    isMediaRoute = /^\/(?:v1\/)?(?:weddings|originals|previews|thumbnails|watermarked|photos)(?:\/|$)/.test(pathname);

    const routeMatch = pathname.match(/^\/(?:v1\/)?(?:weddings|originals|previews|thumbnails|watermarked|photos)\/([a-z0-9-]+)(?:\/|$)/);
    if (routeMatch && routeMatch[1]) {
      routeSlug = routeMatch[1];
    }
  } catch {
    return null;
  }

  if (explicitSlug) {
    if (!/^[a-z0-9-]+$/.test(explicitSlug)) {
      return null; // Malformed slug rejected
    }
    // Tenant Mismatch Invariant (F15):
    // If the URL route contains a canonical tenant slug, explicitSlug MUST match it!
    if (routeSlug && routeSlug !== explicitSlug) {
      return null; // Reject tenant mismatch!
    }
    // Media Route Restriction:
    // If it is a media route and has no valid route slug, an explicit query parameter CANNOT invent a tenant identity.
    if (isMediaRoute && !routeSlug) {
      return null;
    }
    // If it is an unrecognized route without a route slug, explicit slug is rejected unless explicitly permitted
    if (!routeSlug && !options?.allowExplicitWithoutRoute) {
      return null;
    }
    return explicitSlug;
  }

  return routeSlug;
}

export interface EdgeCdnEnv {
  CDN_SIGNING_SECRET: string;
  CDN_PREVIOUS_SIGNING_SECRET?: string;
  R2_BUCKET?: any; // Cloudflare R2Bucket binding
  ALLOWED_ORIGIN?: string;
  REVOKED_WEDDINGS?: Set<string>;
  REVOKED_PHOTOS?: Set<string>;
  WEDDING_REVOCATION_KV?: {
    get: (key: string) => Promise<string | null>;
    put?: (key: string, value: string) => Promise<void>;
  };
  WEDDING_REVOCATION_DO?: DurableObjectNamespaceLike | DurableObjectStubLike;
  STRICT_REVOCATION_MODE?: boolean; // When true, missing DO binding strictly fails closed (503)
  ALLOW_EVENTUAL_CONSISTENCY?: boolean; // When explicitly true, allows KV-only fallback mode
  INTERNAL_OUTBOX_SECRET_PRIMARY?: string;
  INTERNAL_OUTBOX_SECRET_SECONDARY?: string;
}

export interface EdgeCdnResponse {
  status: number;
  headers: Record<string, string>;
  body: string | Buffer;
}

export class EdgeCdnHandler {
  /**
   * Processes edge request on media.shadify.in
   * Enforces finding F15: Edge verification, signature scope, origin isolation, and response Cache-Control.
   */
  static async handleRequest(
    request: {
      method: string;
      url: string;
      headers: Record<string, string>;
    },
    env: EdgeCdnEnv,
    r2Fetcher?: (key: string) => Promise<{ data: Buffer; contentType: string } | null>
  ): Promise<EdgeCdnResponse> {
    const method = request.method.toUpperCase();
    if (method !== 'GET' && method !== 'HEAD') {
      return {
        status: 405,
        headers: { 'Content-Type': 'application/json', Allow: 'GET, HEAD' },
        body: JSON.stringify({ error: 'METHOD_NOT_ALLOWED' }),
      };
    }

    // Fail-Closed Production Configuration Guard (F15.4)
    // Environment detection, strict mode parsing, and validation run inside a unified exception boundary
    // so any configuration conflict, malformed setting, or missing binding returns HTTP 503.
    try {
      const isExplicitProd = isProductionEnvironment(env as any);
      const isStrictModeConfig = parseConfigBoolean(env.STRICT_REVOCATION_MODE, false);
      if (isExplicitProd || isStrictModeConfig) {
        validateProductionRevocationConfig(env);
      }
    } catch (err: any) {
      return {
        status: 503,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store, private', 'Retry-After': '30' },
        body: JSON.stringify({
          error: 'REVOCATION_COORDINATOR_UNCONFIGURED',
          message: err?.message || 'Production revocation configuration guard failed.',
        }),
      };
    }

    const rawUrl = request.url;
    const urlPathPart = rawUrl.replace(/^https?:\/\/[^\/]+/, '');
    if (
      urlPathPart.includes('/../') ||
      urlPathPart.includes('/..') ||
      urlPathPart.includes('//') ||
      urlPathPart.includes('\\') ||
      rawUrl.toLowerCase().includes('%2e%2e')
    ) {
      return {
        status: 403,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store, private' },
        body: JSON.stringify({ error: 'PATH_TRAVERSAL_DETECTED' }),
      };
    }

    const parsedUrl = new URL(request.url);

    // Strict Path Traversal & URL Normalization Defense (F15)
    let decodedPath = '';
    try {
      decodedPath = decodeURIComponent(parsedUrl.pathname);
    } catch {
      return {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store, private' },
        body: JSON.stringify({ error: 'MALFORMED_URL_ENCODING' }),
      };
    }

    if (
      decodedPath.includes('..') ||
      decodedPath.includes('//') ||
      decodedPath.includes('\\') ||
      parsedUrl.pathname.includes('%2e%2e') ||
      parsedUrl.pathname.includes('%2E%2E')
    ) {
      return {
        status: 403,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store, private' },
        body: JSON.stringify({ error: 'PATH_TRAVERSAL_DETECTED' }),
      };
    }

    // HTTP Parameter Pollution (HPP) Defense: reject multiple exp/sig values
    if (parsedUrl.searchParams.getAll('sig').length > 1 || parsedUrl.searchParams.getAll('exp').length > 1) {
      return {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store, private' },
        body: JSON.stringify({ error: 'HTTP_PARAMETER_POLLUTION_DETECTED' }),
      };
    }

    const pathname = parsedUrl.pathname.replace(/^\/+/, '');
    const expStr = parsedUrl.searchParams.get('exp');
    const sig = parsedUrl.searchParams.get('sig');
    const slug = parsedUrl.searchParams.get('w') || '';
    const pid = parsedUrl.searchParams.get('pid') || '';
    const variant = parsedUrl.searchParams.get('v') || (pathname.includes('original') ? 'download' : 'preview');
    const disposition = parsedUrl.searchParams.get('response-content-disposition') || '';

    // 0. Canonical Tenant Slug Resolution (F15)
    // Resolves and strictly validates the wedding tenant slug from the media route first.
    // Rejects missing, malformed, or mismatched explicit tenant identifiers.
    const resolvedWeddingSlug = resolveCanonicalWeddingSlug(request.url, slug);

    if ((slug && !resolvedWeddingSlug) || (pid && !resolvedWeddingSlug)) {
      return {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store, private' },
        body: JSON.stringify({
          error: 'MALFORMED_TENANT_IDENTIFIER',
          message: 'Cannot resolve canonical wedding slug: malformed, missing, or mismatched tenant parameter.',
        }),
      };
    }

    // 1. Signature & Expiration Presence Verification (F15)
    if (!expStr || !sig) {
      return {
        status: 403,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store, private',
        },
        body: JSON.stringify({
          error: 'FORBIDDEN_UNSIGNED_MEDIA_REQUEST',
          message: 'Direct or unsigned CDN requests to media assets are prohibited.',
        }),
      };
    }

    const exp = parseInt(expStr, 10);
    const nowSec = Math.floor(Date.now() / 1000);

    // 2. Expiration Assertion (F15)
    if (isNaN(exp) || nowSec > exp) {
      return {
        status: 403,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store, private',
        },
        body: JSON.stringify({
          error: 'CDN_TOKEN_EXPIRED',
          message: 'Signed media delivery token has expired.',
        }),
      };
    }

    // 3. Cryptographic Signature Verification (Canonical Scope Enforcement with Key Rotation Support)
    // Canonical format: METHOD\nWEDDING_SLUG\nPHOTO_ID\nVARIANT\nOBJECT_KEY\nEXPIRES\nDISPOSITION
    const canonicalString = `${method}\n${slug}\n${pid}\n${variant}\n${pathname}\n${exp}\n${disposition}`;

    const candidateSecrets = [env.CDN_SIGNING_SECRET];
    if (env.CDN_PREVIOUS_SIGNING_SECRET) {
      candidateSecrets.push(env.CDN_PREVIOUS_SIGNING_SECRET);
    }

    let isValid = false;
    const sigBuf = Buffer.from(sig);

    for (const secret of candidateSecrets) {
      if (!secret) continue;
      const expectedCanonicalSig = crypto
        .createHmac('sha256', secret)
        .update(canonicalString)
        .digest('hex');
      const canonicalBuf = Buffer.from(expectedCanonicalSig);

      if (sigBuf.length === canonicalBuf.length && crypto.timingSafeEqual(sigBuf, canonicalBuf)) {
        isValid = true;
        break;
      }

      // Legacy fallback
      const expectedLegacySig = crypto
        .createHmac('sha256', secret)
        .update(`${pathname}:${exp}`)
        .digest('hex');
      const legacyBuf = Buffer.from(expectedLegacySig);

      if (sigBuf.length === legacyBuf.length && crypto.timingSafeEqual(sigBuf, legacyBuf)) {
        isValid = true;
        break;
      }
    }

    if (!isValid) {
      return {
        status: 403,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store, private',
        },
        body: JSON.stringify({
          error: 'INVALID_CDN_SIGNATURE',
          message: 'Tampered, forged, or cross-scoped CDN signature detected.',
        }),
      };
    }

    // 0A. Immediate Revocation Killswitch Enforcement (Finding 2)
    // Instant edge invalidation: if photo or wedding has been deleted or revoked,
    // immediately reject request with 403 before cache lookup or storage read.
    if (resolvedWeddingSlug && env.REVOKED_WEDDINGS && env.REVOKED_WEDDINGS.has(resolvedWeddingSlug)) {
      return {
        status: 403,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store, private',
        },
        body: JSON.stringify({
          error: 'WEDDING_GALLERY_REVOKED',
          message: 'This wedding gallery has been unpublished or revoked.',
        }),
      };
    }

    if (pid && env.REVOKED_PHOTOS && env.REVOKED_PHOTOS.has(pid)) {
      return {
        status: 403,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store, private',
        },
        body: JSON.stringify({
          error: 'MEDIA_ASSET_REVOKED',
          message: 'This photo has been deleted or revoked by the wedding administrator.',
        }),
      };
    }

    // Dynamic Cloudflare KV Namespace lookup with Fail-Closed behavior (F15)
    // Uses tenant-scoped canonical keys: `revoked_weddings:${slug}` and `revoked_photos:${slug}:${pid}`
    if (env.WEDDING_REVOCATION_KV) {
      try {
        if (resolvedWeddingSlug) {
          const isWeddingRevoked =
            (await env.WEDDING_REVOCATION_KV.get(getCanonicalWeddingTombstoneKey(resolvedWeddingSlug))) ||
            (await env.WEDDING_REVOCATION_KV.get(`revoked_weddings:${resolvedWeddingSlug}`));
          if (isWeddingRevoked) {
            return {
              status: 403,
              headers: {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-store, private',
              },
              body: JSON.stringify({
                error: 'WEDDING_GALLERY_REVOKED',
                message: 'This wedding gallery has been unpublished or revoked via KV.',
              }),
            };
          }
        }
        if (pid && resolvedWeddingSlug) {
          const isPhotoRevoked =
            (await env.WEDDING_REVOCATION_KV.get(getCanonicalPhotoTombstoneKey(resolvedWeddingSlug, pid))) ||
            (await env.WEDDING_REVOCATION_KV.get(`revoked_photos:${pid}`));
          if (isPhotoRevoked) {
            return {
              status: 403,
              headers: {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-store, private',
              },
              body: JSON.stringify({
                error: 'MEDIA_ASSET_REVOKED',
                message: 'This photo has been deleted or revoked via KV.',
              }),
            };
          }
        }
      } catch (kvErr) {
        // Fail closed on KV infrastructure outage: never serve potentially revoked media
        return {
          status: 503,
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store, private',
            'Retry-After': '10',
          },
          body: JSON.stringify({
            error: 'REVOCATION_CHECK_UNAVAILABLE',
            message: 'Edge authorization check failed closed due to KV store failure.',
          }),
        };
      }
    }

    // 0B. Authoritative Durable Object Coordinator Verification (F15 Strongly Consistent Anchor)
    const isStrictMode = parseConfigBoolean(env.STRICT_REVOCATION_MODE, false);
    const allowEventual = parseConfigBoolean(env.ALLOW_EVENTUAL_CONSISTENCY, false);

    if (!env.WEDDING_REVOCATION_DO) {
      if (!allowEventual) {
        return {
          status: 503,
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store, private',
            'Retry-After': '10',
          },
          body: JSON.stringify({
            error: 'REVOCATION_COORDINATOR_UNCONFIGURED',
            message: 'Authoritative Durable Object revocation coordinator binding is missing.',
          }),
        };
      }
    }

    if (env.WEDDING_REVOCATION_DO && (pid || resolvedWeddingSlug)) {
      if (!resolvedWeddingSlug) {
        return {
          status: 400,
          headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store, private' },
          body: JSON.stringify({
            error: 'MALFORMED_TENANT_IDENTIFIER',
            message: 'Unable to derive coordinator authority: malformed or missing wedding tenant.',
          }),
        };
      }

      try {
        let stub: DurableObjectStubLike;
        if ('idFromName' in env.WEDDING_REVOCATION_DO) {
          // Standard Cloudflare Workers Durable Object Namespace API
          // Uses getCanonicalDurableObjectId matching outbox mutation paths
          const canonicalDoName = getCanonicalDurableObjectId(resolvedWeddingSlug);
          const doId = env.WEDDING_REVOCATION_DO.idFromName(canonicalDoName);
          stub = env.WEDDING_REVOCATION_DO.get(doId);
        } else {
          // Direct stub / test double
          stub = env.WEDDING_REVOCATION_DO;
        }

        // 1. Wedding-Wide Revocation Check (Coordinator Authority)
        if (typeof stub.isWeddingRevoked !== 'function') {
          return {
            status: 503,
            headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store, private', 'Retry-After': '10' },
            body: JSON.stringify({
              error: 'REVOCATION_COORDINATOR_METHOD_UNAVAILABLE',
              message: 'Authoritative coordinator missing required isWeddingRevoked implementation.',
            }),
          };
        }

        const isWeddingRevokedByDo = await stub.isWeddingRevoked(resolvedWeddingSlug);

        if (isWeddingRevokedByDo) {
          if (env.WEDDING_REVOCATION_KV?.put) {
            try {
              await env.WEDDING_REVOCATION_KV.put(getCanonicalWeddingTombstoneKey(resolvedWeddingSlug), '1');
            } catch {
              if (env.STRICT_REVOCATION_MODE) {
                return {
                  status: 503,
                  headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store, private' },
                  body: JSON.stringify({ error: 'REVOCATION_CHECK_UNAVAILABLE', message: 'KV write failure in strict mode.' }),
                };
              }
            }
          }
          return {
            status: 403,
            headers: {
              'Content-Type': 'application/json',
              'Cache-Control': 'no-store, private',
            },
            body: JSON.stringify({
              error: 'WEDDING_GALLERY_REVOKED',
              message: 'This wedding gallery has been unpublished or revoked by coordinator.',
            }),
          };
        }

        // 2. Photo-Level Revocation Check (Strictly executed ONLY when pid is present)
        if (pid) {
          if (typeof stub.isPhotoRevoked !== 'function') {
            return {
              status: 503,
              headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store, private', 'Retry-After': '10' },
              body: JSON.stringify({
                error: 'REVOCATION_COORDINATOR_METHOD_UNAVAILABLE',
                message: 'Authoritative coordinator missing required isPhotoRevoked implementation.',
              }),
            };
          }

          const isPhotoRevokedByDo = await stub.isPhotoRevoked(pid, resolvedWeddingSlug);

          if (isPhotoRevokedByDo) {
            if (env.WEDDING_REVOCATION_KV?.put) {
              try {
                await env.WEDDING_REVOCATION_KV.put(getCanonicalPhotoTombstoneKey(resolvedWeddingSlug, pid), '1');
                await env.WEDDING_REVOCATION_KV.put(`revoked_photos:${pid}`, '1');
              } catch {
                if (env.STRICT_REVOCATION_MODE) {
                  return {
                    status: 503,
                    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store, private' },
                    body: JSON.stringify({ error: 'REVOCATION_CHECK_UNAVAILABLE', message: 'KV write failure in strict mode.' }),
                  };
                }
              }
            }
            return {
              status: 403,
              headers: {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-store, private',
              },
              body: JSON.stringify({
                error: 'MEDIA_ASSET_REVOKED',
                message: 'This photo has been authoritatively revoked by the Durable Object coordinator.',
              }),
            };
          }
        }
      } catch (doErr) {
        // Fail closed on coordinator outage: never serve potentially revoked media
        return {
          status: 503,
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store, private',
            'Retry-After': '10',
          },
          body: JSON.stringify({
            error: 'REVOCATION_CHECK_UNAVAILABLE',
            message: 'Edge authorization check failed closed due to coordinator failure.',
          }),
        };
      }
    }

    // 4. Fetch from Private Storage Provider (R2)
    const objectKey = pathname;
    let objectData: { data: Buffer; contentType: string } | null = null;
    if (r2Fetcher) {
      objectData = await r2Fetcher(objectKey);
    } else {
      objectData = {
        data: Buffer.from('mock_r2_image_binary_data'),
        contentType: pathname.endsWith('.webp') ? 'image/webp' : 'image/jpeg',
      };
    }

    if (!objectData) {
      return {
        status: 404,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store, private' },
        body: JSON.stringify({ error: 'OBJECT_NOT_FOUND' }),
      };
    }

    // 5. Response Headers Enforcement (F15)
    // Differentiates preview (3600s) vs download (900s)
    const isDownload = pathname.includes('original') || Boolean(disposition);
    const maxAge = isDownload ? 900 : 3600;

    const responseHeaders: Record<string, string> = {
      'Content-Type': objectData.contentType,
      // Private prevents shared CDN/intermediate edge caches from leaking authenticated assets to different guests
      'Cache-Control': `private, no-transform, max-age=${maxAge}`,
      'X-Content-Type-Options': 'nosniff',
    };

    if (disposition) {
      responseHeaders['Content-Disposition'] = disposition;
    }

    return {
      status: 200,
      headers: responseHeaders,
      body: objectData.data,
    };
  }
}

/**
 * Authoritative HTTP Client for Backend Outbox Processor -> Edge Durable Object Mutations (F15).
 * Communicates with the Cloudflare Worker coordinator mutation endpoint over TLS using the shared outbox secret.
 * Enforces identical canonical Durable Object derivation matching the Edge CDN read path.
 */
export class HttpDurableObjectCoordinatorClient {
  constructor(
    private readonly baseUrl: string,
    private readonly outboxSecret: string
  ) {}

  async revokePhoto(photoId: string, weddingSlug: string): Promise<void> {
    const res = await fetch(`${this.baseUrl}/internal/revocation/photo`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.outboxSecret}`,
        'X-Wedding-Slug': weddingSlug,
      },
      body: JSON.stringify({ photoId, weddingSlug }),
    });
    if (!res.ok) {
      const errBody = await res.text().catch(() => '');
      throw new Error(`Durable Object photo revocation failed (${res.status}): ${errBody}`);
    }
  }

  async revokeWedding(weddingSlug: string): Promise<void> {
    const res = await fetch(`${this.baseUrl}/internal/revocation/wedding`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.outboxSecret}`,
        'X-Wedding-Slug': weddingSlug,
      },
      body: JSON.stringify({ weddingSlug }),
    });
    if (!res.ok) {
      const errBody = await res.text().catch(() => '');
      throw new Error(`Durable Object wedding revocation failed (${res.status}): ${errBody}`);
    }
  }

  async isPhotoRevoked(photoId: string, weddingSlug: string): Promise<boolean> {
    const res = await fetch(
      `${this.baseUrl}/internal/revocation/photo/check?photoId=${encodeURIComponent(photoId)}&weddingSlug=${encodeURIComponent(weddingSlug)}`,
      {
        headers: {
          Authorization: `Bearer ${this.outboxSecret}`,
        },
      }
    );
    if (!res.ok) {
      throw new Error(`Durable Object check failed with status ${res.status}`);
    }
    const data = (await res.json()) as { revoked: boolean };
    return data.revoked;
  }

  async isWeddingRevoked(weddingSlug: string): Promise<boolean> {
    const res = await fetch(
      `${this.baseUrl}/internal/revocation/wedding/check?weddingSlug=${encodeURIComponent(weddingSlug)}`,
      {
        headers: {
          Authorization: `Bearer ${this.outboxSecret}`,
        },
      }
    );
    if (!res.ok) {
      throw new Error(`Durable Object check failed with status ${res.status}`);
    }
    const data = (await res.json()) as { revoked: boolean };
    return data.revoked;
  }
}

export const RESERVED_TENANT_SLUGS = new Set([
  'admin',
  'api',
  'auth',
  'health',
  'login',
  'dashboard',
  'settings',
  'static',
  'cdn',
  'internal',
  'weddings',
  'photos',
  'originals',
  'previews',
  'thumbnails',
  'watermarked',
  'system',
  'root',
]);

export function isReservedTenantSlug(slug: string): boolean {
  return RESERVED_TENANT_SLUGS.has(slug.toLowerCase().trim());
}

/**
 * Streaming bounded request body reader (F15.2).
 * Strictly enforces a hard 16KB (16,384 bytes) limit at the streaming chunk level.
 * Cancels and aborts the reader immediately if total byte count exceeds 16,384 bytes,
 * preventing memory bloat and DOS attacks regardless of Content-Length header validity.
 * Safely parses valid UTF-8 and parses JSON.
 */
export async function readBoundedRequestBody(
  request: Request,
  maxBytes = 16384
): Promise<{ ok: true; body: any } | { ok: false; error: string; status: number }> {
  const clHeader = request.headers.get('Content-Length');
  if (clHeader) {
    const cl = parseInt(clHeader, 10);
    if (!isNaN(cl) && cl > maxBytes) {
      return { ok: false, error: 'PAYLOAD_TOO_LARGE', status: 413 };
    }
  }

  let fullBuffer: Uint8Array;
  if (!request.body) {
    fullBuffer = new Uint8Array(0);
  } else {
    const reader = request.body.getReader();
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          totalBytes += value.byteLength;
          if (totalBytes > maxBytes) {
            await reader.cancel('PAYLOAD_TOO_LARGE');
            return { ok: false, error: 'PAYLOAD_TOO_LARGE', status: 413 };
          }
          chunks.push(value);
        }
      }
    } catch {
      return { ok: false, error: 'BODY_READ_ERROR', status: 400 };
    }

    fullBuffer = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      fullBuffer.set(chunk, offset);
      offset += chunk.byteLength;
    }
  }

  if (fullBuffer.byteLength > maxBytes) {
    return { ok: false, error: 'PAYLOAD_TOO_LARGE', status: 413 };
  }

  let rawText = '';
  try {
    rawText = new TextDecoder('utf-8', { fatal: true }).decode(fullBuffer);
  } catch {
    return { ok: false, error: 'INVALID_UTF8_PAYLOAD', status: 400 };
  }

  if (!rawText.trim()) {
    return { ok: false, error: 'EMPTY_REQUEST_BODY', status: 400 };
  }

  let parsed: any;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    return { ok: false, error: 'INVALID_JSON', status: 400 };
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, error: 'INVALID_REQUEST_BODY', status: 400 };
  }

  return { ok: true, body: parsed };
}

/**
 * Production Cloudflare Worker Export (F15).
 * Mounts EdgeCdnHandler for media reads, and authenticated internal routes for authoritative
 * Durable Object mutations from the backend outbox processor.
 */
export default {
  async fetch(request: Request, env: EdgeCdnEnv, ctx?: any): Promise<Response> {
    // Fail-Closed Production Configuration Guard (F15.4):
    // Unified entrypoint guard: 100% of incoming requests (media reads and internal revocation)
    // pass through this boundary before any processing. Configuration conflicts or missing bindings
    // strictly return HTTP 503 REVOCATION_COORDINATOR_UNCONFIGURED.
    try {
      const isExplicitProd = isProductionEnvironment(env as any);
      const isStrictModeConfig = parseConfigBoolean(env.STRICT_REVOCATION_MODE, false);
      if (isExplicitProd || isStrictModeConfig) {
        validateProductionRevocationConfig(env);
      }
    } catch (err: any) {
      return new Response(
        JSON.stringify({
          error: 'REVOCATION_COORDINATOR_UNCONFIGURED',
          message: err?.message || 'Production revocation configuration guard failed.',
        }),
        {
          status: 503,
          headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store, private', 'Retry-After': '30' },
        }
      );
    }

    const url = new URL(request.url);

    // 1. Internal Outbox Revocation Mutations (POST /internal/revocation/*) and Checks (GET)
    if (url.pathname.startsWith('/internal/revocation/')) {
      const isMutationPath =
        url.pathname === '/internal/revocation/photo' || url.pathname === '/internal/revocation/wedding';
      const isCheckPath =
        url.pathname === '/internal/revocation/photo/check' || url.pathname === '/internal/revocation/wedding/check';

      if (!isMutationPath && !isCheckPath) {
        return new Response(JSON.stringify({ error: 'NOT_FOUND' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (isMutationPath && request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'METHOD_NOT_ALLOWED' }), {
          status: 405,
          headers: { 'Content-Type': 'application/json', Allow: 'POST' },
        });
      }

      if (isCheckPath && request.method !== 'GET') {
        return new Response(JSON.stringify({ error: 'METHOD_NOT_ALLOWED' }), {
          status: 405,
          headers: { 'Content-Type': 'application/json', Allow: 'GET' },
        });
      }

      // Verify Bearer authorization with configured internal secrets (F15.2)
      // Supports seamless zero-downtime secret rotation across PRIMARY and SECONDARY secrets
      const authHeader = request.headers.get('Authorization') || '';
      const primarySecret = env.INTERNAL_OUTBOX_SECRET_PRIMARY;
      const secondarySecret = env.INTERNAL_OUTBOX_SECRET_SECONDARY;
      const encoder = new TextEncoder();

      // Independent PRIMARY secret validation:
      if (!primarySecret || typeof primarySecret !== 'string') {
        return new Response(JSON.stringify({ error: 'REVOCATION_COORDINATOR_UNCONFIGURED', detail: 'INTERNAL_OUTBOX_SECRET_PRIMARY missing' }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      const primaryBytes = encoder.encode(primarySecret);
      if (primaryBytes.byteLength < 8 || primaryBytes.byteLength > 128 || !/^[a-zA-Z0-9_\-\.]+$/.test(primarySecret)) {
        return new Response(JSON.stringify({ error: 'REVOCATION_COORDINATOR_UNCONFIGURED', detail: 'INTERNAL_OUTBOX_SECRET_PRIMARY invalid format or length' }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // Independent SECONDARY secret validation:
      // An invalid secondary secret MUST NOT silently become an unusable fallback credential!
      if (secondarySecret !== undefined && secondarySecret !== null && secondarySecret !== '') {
        if (typeof secondarySecret !== 'string') {
          return new Response(JSON.stringify({ error: 'REVOCATION_COORDINATOR_UNCONFIGURED', detail: 'INTERNAL_OUTBOX_SECRET_SECONDARY invalid type' }), {
            status: 503,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        const secondaryBytes = encoder.encode(secondarySecret);
        if (secondaryBytes.byteLength < 8 || secondaryBytes.byteLength > 128 || !/^[a-zA-Z0-9_\-\.]+$/.test(secondarySecret)) {
          return new Response(JSON.stringify({ error: 'REVOCATION_COORDINATOR_UNCONFIGURED', detail: 'INTERNAL_OUTBOX_SECRET_SECONDARY invalid format or length' }), {
            status: 503,
            headers: { 'Content-Type': 'application/json' },
          });
        }
      }

      if (!authHeader.startsWith('Bearer ')) {
        return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      const token = authHeader.slice(7).trim();
      const tokenBytes = encoder.encode(token);
      // Enforce strict token length bound, UTF-8 byte length bound, and charset
      if (token.length < 8 || token.length > 128 || tokenBytes.byteLength > 128 || !/^[a-zA-Z0-9_\-\.]+$/.test(token)) {
        return new Response(JSON.stringify({ error: 'INVALID_CREDENTIALS', detail: 'Token format or length invalid' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      let authorized = timingSafeEqualStrings(token, primarySecret);
      if (!authorized && secondarySecret) {
        authorized = timingSafeEqualStrings(token, secondarySecret);
      }

      if (!authorized) {
        return new Response(JSON.stringify({ error: 'FORBIDDEN' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (!env.WEDDING_REVOCATION_DO || !('idFromName' in env.WEDDING_REVOCATION_DO)) {
        return new Response(JSON.stringify({ error: 'REVOCATION_COORDINATOR_UNCONFIGURED' }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // Check endpoints (GET)
      if (url.pathname === '/internal/revocation/photo/check') {
        const weddingSlug = url.searchParams.get('weddingSlug') || '';
        const photoId = url.searchParams.get('photoId') || '';

        if (!weddingSlug || typeof weddingSlug !== 'string' || !/^[a-z0-9-]+$/.test(weddingSlug)) {
          return new Response(JSON.stringify({ error: 'INVALID_WEDDING_SLUG' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        if (isReservedTenantSlug(weddingSlug)) {
          return new Response(JSON.stringify({ error: 'RESERVED_TENANT_SLUG' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        if (!photoId || !/^[a-zA-Z0-9_-]+$/.test(photoId)) {
          return new Response(JSON.stringify({ error: 'INVALID_PHOTO_ID' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        const canonicalSlug = resolveCanonicalWeddingSlug('/originals/' + weddingSlug + '/file.jpg', weddingSlug);
        if (!canonicalSlug || canonicalSlug !== weddingSlug) {
          return new Response(JSON.stringify({ error: 'NON_CANONICAL_WEDDING_SLUG' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        const doName = getCanonicalDurableObjectId(canonicalSlug);
        const doId = env.WEDDING_REVOCATION_DO.idFromName(doName);
        const stub = env.WEDDING_REVOCATION_DO.get(doId) as any;
        const revoked = await stub.isPhotoRevoked(photoId, canonicalSlug);
        return new Response(JSON.stringify({ revoked, weddingSlug: canonicalSlug, photoId }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.pathname === '/internal/revocation/wedding/check') {
        const weddingSlug = url.searchParams.get('weddingSlug') || '';
        if (!weddingSlug || typeof weddingSlug !== 'string' || !/^[a-z0-9-]+$/.test(weddingSlug)) {
          return new Response(JSON.stringify({ error: 'INVALID_WEDDING_SLUG' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        if (isReservedTenantSlug(weddingSlug)) {
          return new Response(JSON.stringify({ error: 'RESERVED_TENANT_SLUG' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        const canonicalSlug = resolveCanonicalWeddingSlug('/weddings/' + weddingSlug, weddingSlug);
        if (!canonicalSlug || canonicalSlug !== weddingSlug) {
          return new Response(JSON.stringify({ error: 'NON_CANONICAL_WEDDING_SLUG' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        const doName = getCanonicalDurableObjectId(canonicalSlug);
        const doId = env.WEDDING_REVOCATION_DO.idFromName(doName);
        const stub = env.WEDDING_REVOCATION_DO.get(doId) as any;
        const revoked = await stub.isWeddingRevoked(canonicalSlug);
        return new Response(JSON.stringify({ revoked, weddingSlug: canonicalSlug }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // Mutation endpoints (POST)
      // Hard streaming limit of 16KB enforced (F15.2)
      const bodyResult = await readBoundedRequestBody(request, 16384);
      if (!bodyResult.ok) {
        return new Response(JSON.stringify({ error: bodyResult.error }), {
          status: bodyResult.status,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      const body = bodyResult.body;

      // Complete schema validation (F15.2): strictly check allowed properties
      const allowedPhotoFields = new Set(['weddingSlug', 'photoId', 'reason', 'actorId', 'eventId', 'timestamp']);
      const allowedWeddingFields = new Set(['weddingSlug', 'reason', 'actorId', 'eventId', 'timestamp']);
      const isPhotoMutation = url.pathname === '/internal/revocation/photo';
      const allowedFields = isPhotoMutation ? allowedPhotoFields : allowedWeddingFields;

      for (const field of Object.keys(body)) {
        if (!allowedFields.has(field)) {
          return new Response(JSON.stringify({ error: 'INVALID_SCHEMA', detail: `Unrecognized field "${field}"` }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        }
      }

      const rawSlug = body.weddingSlug;
      if (!rawSlug || typeof rawSlug !== 'string' || !/^[a-z0-9-]+$/.test(rawSlug) || rawSlug.length > 64) {
        return new Response(JSON.stringify({ error: 'INVALID_WEDDING_SLUG', detail: 'weddingSlug is required and must match ^[a-z0-9-]+$ (max 64 chars)' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (isReservedTenantSlug(rawSlug)) {
        return new Response(JSON.stringify({ error: 'RESERVED_TENANT_SLUG' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // Canonical slug resolution (F15.1) - strictly identical to reader path
      const canonicalSlug = resolveCanonicalWeddingSlug('/weddings/' + rawSlug, rawSlug);
      if (!canonicalSlug || canonicalSlug !== rawSlug) {
        return new Response(JSON.stringify({ error: 'NON_CANONICAL_WEDDING_SLUG' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // Check header slug consistency if provided
      const headerSlug = request.headers.get('X-Wedding-Slug');
      if (headerSlug && headerSlug !== canonicalSlug) {
        return new Response(JSON.stringify({ error: 'SLUG_HEADER_MISMATCH' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (isPhotoMutation) {
        const photoId = body.photoId;
        if (!photoId || typeof photoId !== 'string' || !/^[a-zA-Z0-9_-]+$/.test(photoId) || photoId.length > 64) {
          return new Response(JSON.stringify({ error: 'INVALID_PHOTO_ID', detail: 'photoId is required, must match ^[a-zA-Z0-9_-]+$, and be <= 64 characters' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        }
      } else if (body.photoId !== undefined) {
        return new Response(JSON.stringify({ error: 'INVALID_SCHEMA', detail: 'photoId must not be present on wedding-level revocation' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (
        body.reason !== undefined &&
        (typeof body.reason !== 'string' || body.reason.trim().length < 5 || body.reason.length > 500 || /[\x00-\x1F\x7F]/.test(body.reason))
      ) {
        return new Response(JSON.stringify({ error: 'INVALID_REASON', detail: 'reason must be between 5 and 500 characters without control characters' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (
        body.actorId !== undefined &&
        (typeof body.actorId !== 'string' || !/^[a-zA-Z0-9_.:-]+$/.test(body.actorId) || body.actorId.length > 100)
      ) {
        return new Response(JSON.stringify({ error: 'INVALID_ACTOR_ID', detail: 'actorId must be alphanumeric (max 100 characters)' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (
        body.eventId !== undefined &&
        (typeof body.eventId !== 'string' || !/^[a-zA-Z0-9_.:-]+$/.test(body.eventId) || body.eventId.length > 100)
      ) {
        return new Response(JSON.stringify({ error: 'INVALID_EVENT_ID', detail: 'eventId must be alphanumeric (max 100 characters)' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (
        body.timestamp !== undefined &&
        (typeof body.timestamp !== 'string' || isNaN(Date.parse(body.timestamp)))
      ) {
        return new Response(JSON.stringify({ error: 'INVALID_TIMESTAMP', detail: 'timestamp must be a valid ISO-8601 datetime string' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // Authoritative DO instance derivation: strictly matches reader path idFromName("wedding:" + canonicalSlug)
      const doName = getCanonicalDurableObjectId(canonicalSlug);
      const doId = env.WEDDING_REVOCATION_DO.idFromName(doName);
      const stub = env.WEDDING_REVOCATION_DO.get(doId) as any;

      if (url.pathname === '/internal/revocation/photo') {
        const photoId = body.photoId;
        if (!photoId || typeof photoId !== 'string' || !/^[a-zA-Z0-9_-]+$/.test(photoId)) {
          return new Response(JSON.stringify({ error: 'INVALID_PHOTO_ID' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        await stub.revokePhoto(photoId, canonicalSlug);
        return new Response(JSON.stringify({ success: true, photoId, weddingSlug: canonicalSlug }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.pathname === '/internal/revocation/wedding') {
        await stub.revokeWedding(canonicalSlug);
        return new Response(JSON.stringify({ success: true, weddingSlug: canonicalSlug }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      return new Response(JSON.stringify({ error: 'NOT_FOUND' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // 2. Public Edge CDN Media Delivery (GET / HEAD)
    const headersRecord: Record<string, string> = {};
    request.headers.forEach((v, k) => {
      headersRecord[k] = v;
    });

    const cdnResponse = await EdgeCdnHandler.handleRequest(
      {
        method: request.method,
        url: request.url,
        headers: headersRecord,
      },
      env
    );

    return new Response(cdnResponse.body, {
      status: cdnResponse.status,
      headers: cdnResponse.headers,
    });
  },
};



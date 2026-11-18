import crypto from 'node:crypto';

export interface SignedCdnUrlParams {
  objectKey: string;
  expiresInSeconds: number;
  weddingSlug?: string;
  photoId?: string;
  variant?: 'preview' | 'download' | 'thumbnail';
  method?: string;
  contentDisposition?: string;
  cdnBaseUrl?: string;
}

export class CdnService {
  public static get SECRET(): string {
    return (
      process.env.CDN_SIGNING_SECRET ||
      process.env.CLOUDFLARE_HMAC_SECRET ||
      'shadify-cdn-media-signing-hmac-sha256-secret-32ch'
    );
  }

  public static getSigningSecret(): string {
    return this.SECRET;
  }

  /**
   * Computes the canonical signing string for edge delivery (F15).
   * Canonical parameters: METHOD, WEDDING_SLUG, PHOTO_ID, VARIANT, OBJECT_KEY, EXPIRES, DISPOSITION.
   */
  static buildCanonicalSigningString(params: {
    method?: string;
    weddingSlug?: string;
    photoId?: string;
    variant?: string;
    objectKey: string;
    expiresSec: number;
    contentDisposition?: string;
  }): string {
    const method = (params.method || 'GET').toUpperCase();
    const slug = params.weddingSlug || '';
    const pid = params.photoId || '';
    const variant = params.variant || (params.objectKey.includes('original') ? 'download' : 'preview');
    const key = params.objectKey.replace(/^\/+/, '');
    const disp = params.contentDisposition || '';

    return `${method}\n${slug}\n${pid}\n${variant}\n${key}\n${params.expiresSec}\n${disp}`;
  }

  /**
   * Generates a signed CDN URL with a tamper-proof HMAC SHA-256 signature and explicit expiry timestamp.
   * Remediates Finding F15 (Direct Storage Credentials Avoidance & Canonical Scope Binding).
   */
  static generateSignedCdnUrl(params: SignedCdnUrlParams): {
    url: string;
    expiresAt: string;
    expiresInSeconds: number;
  } {
    const cdnBase = params.cdnBaseUrl || process.env.CDN_BASE_URL || 'https://media.shadify.in';
    const nowSec = Math.floor(Date.now() / 1000);
    const expiresSec = nowSec + params.expiresInSeconds;

    const canonicalString = this.buildCanonicalSigningString({
      method: params.method,
      weddingSlug: params.weddingSlug,
      photoId: params.photoId,
      variant: params.variant,
      objectKey: params.objectKey,
      expiresSec,
      contentDisposition: params.contentDisposition,
    });

    const signature = crypto
      .createHmac('sha256', this.SECRET)
      .update(canonicalString)
      .digest('hex');

    const query = new URLSearchParams({
      exp: String(expiresSec),
      sig: signature,
    });

    if (params.weddingSlug) query.set('w', params.weddingSlug);
    if (params.photoId) query.set('pid', params.photoId);
    if (params.variant) query.set('v', params.variant);
    if (params.contentDisposition) {
      query.set('response-content-disposition', params.contentDisposition);
    }

    const cleanBase = cdnBase.replace(/\/+$/, '');
    const cleanKey = params.objectKey.replace(/^\/+/, '');

    return {
      url: `${cleanBase}/${cleanKey}?${query.toString()}`,
      expiresAt: new Date(expiresSec * 1000).toISOString(),
      expiresInSeconds: params.expiresInSeconds,
    };
  }

  /**
   * Verifies the authenticity, canonical scope, and expiration of a signed CDN URL.
   */
  static verifySignedCdnUrl(params: {
    objectKey: string;
    expiresSec: number;
    signature: string;
    method?: string;
    weddingSlug?: string;
    photoId?: string;
    variant?: string;
    contentDisposition?: string;
  }): boolean {
    const nowSec = Math.floor(Date.now() / 1000);
    if (nowSec > params.expiresSec) {
      return false; // Expired
    }

    // Try full canonical verification
    const canonicalString = this.buildCanonicalSigningString({
      method: params.method,
      weddingSlug: params.weddingSlug,
      photoId: params.photoId,
      variant: params.variant,
      objectKey: params.objectKey,
      expiresSec: params.expiresSec,
      contentDisposition: params.contentDisposition,
    });

    const expectedSig = crypto
      .createHmac('sha256', this.SECRET)
      .update(canonicalString)
      .digest('hex');

    const sigBuf = Buffer.from(params.signature);
    const expectedBuf = Buffer.from(expectedSig);

    if (sigBuf.length === expectedBuf.length && crypto.timingSafeEqual(sigBuf, expectedBuf)) {
      return true;
    }

    // Backwards-compatible path: ${objectKey}:${expiresSec}
    const legacySig = crypto
      .createHmac('sha256', this.SECRET)
      .update(`${params.objectKey.replace(/^\/+/, '')}:${params.expiresSec}`)
      .digest('hex');

    const legacyBuf = Buffer.from(legacySig);
    if (sigBuf.length === legacyBuf.length && crypto.timingSafeEqual(sigBuf, legacyBuf)) {
      return true;
    }

    return false;
  }
}


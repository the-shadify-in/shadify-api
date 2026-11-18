/**
 * Cloudflare Edge Cache Purge & Instant Invalidation Service (F14 & F15)
 * Communicates with Cloudflare Zone Purge API for instant edge cache invalidation
 * when assets, guest tokens, or weddings are deleted, revoked, or made private.
 */

export interface CloudflarePurgeConfig {
  zoneId: string;
  apiToken: string;
  baseUrl?: string;
  maxRetries?: number;
  timeoutMs?: number;
}

export interface PurgeResult {
  success: boolean;
  purgedCount?: number;
  error?: string;
  retryCount: number;
}

export class CloudflarePurgeService {
  private zoneId: string;
  private apiToken: string;
  private baseUrl: string;
  private maxRetries: number;
  private timeoutMs: number;

  constructor(config?: Partial<CloudflarePurgeConfig>) {
    this.zoneId = config?.zoneId || process.env.CLOUDFLARE_ZONE_ID || 'mock-zone-id-123456';
    this.apiToken = config?.apiToken || process.env.CLOUDFLARE_API_TOKEN || 'mock-cf-api-token';
    this.baseUrl = config?.baseUrl || 'https://api.cloudflare.com/client/v4';
    this.maxRetries = config?.maxRetries ?? 3;
    this.timeoutMs = config?.timeoutMs ?? 5000;
  }

  /**
   * Purges specific asset URLs from Cloudflare edge caches globally.
   */
  async purgeUrls(urls: string[]): Promise<PurgeResult> {
    if (!urls || urls.length === 0) {
      return { success: true, purgedCount: 0, retryCount: 0 };
    }
    return this.executePurge({ files: urls }, urls.length);
  }

  /**
   * Purges edge caches by Cache-Tags (e.g. `wedding-{slug}`, `photo-{id}`).
   */
  async purgeTags(tags: string[]): Promise<PurgeResult> {
    if (!tags || tags.length === 0) {
      return { success: true, purgedCount: 0, retryCount: 0 };
    }
    return this.executePurge({ tags }, tags.length);
  }

  /**
   * High-level helper: Immediately invalidates all cached variants for a specific photo.
   */
  async purgePhoto(photoId: string, weddingSlug?: string): Promise<PurgeResult> {
    const tags = [`photo-${photoId}`];
    if (weddingSlug) {
      tags.push(`wedding-${weddingSlug}-photo-${photoId}`);
    }
    return this.purgeTags(tags);
  }

  /**
   * High-level helper: Immediately invalidates the entire media cache for a wedding.
   */
  async purgeWedding(weddingSlug: string): Promise<PurgeResult> {
    return this.purgeTags([`wedding-${weddingSlug}`]);
  }

  /**
   * Core request execution with exponential backoff and timeout handling.
   */
  private async executePurge(
    payload: { files?: string[]; tags?: string[]; hosts?: string[] },
    count: number
  ): Promise<PurgeResult> {
    const endpoint = `${this.baseUrl}/zones/${this.zoneId}/purge_cache`;
    let attempt = 0;
    let lastError = '';

    while (attempt < this.maxRetries) {
      attempt++;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${this.apiToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (response.ok) {
          const json = (await response.json()) as { success?: boolean; errors?: any[] };
          if (json.success !== false) {
            return {
              success: true,
              purgedCount: count,
              retryCount: attempt - 1,
            };
          }
          lastError = JSON.stringify(json.errors || 'Unknown purge error');
        } else if (response.status === 429) {
          // Rate-limited: Read Retry-After header or default backoff
          const retryAfterSec = parseInt(response.headers.get('Retry-After') || '1', 10);
          lastError = `RATE_LIMITED_429: Retry-After ${retryAfterSec}s`;
          if (attempt < this.maxRetries) {
            await new Promise((r) => setTimeout(r, retryAfterSec * 1000));
            continue;
          }
        } else if (response.status >= 500) {
          // Transient server error: retry with exponential backoff
          lastError = `SERVER_ERROR_${response.status}`;
          if (attempt < this.maxRetries) {
            const backoffMs = Math.min(1000 * Math.pow(2, attempt - 1), 4000);
            await new Promise((r) => setTimeout(r, backoffMs));
            continue;
          }
        } else {
          // Client error (400, 401, 403, 404): non-retryable
          const errorBody = await response.text();
          return {
            success: false,
            error: `CLIENT_ERROR_${response.status}: ${errorBody}`,
            retryCount: attempt - 1,
          };
        }
      } catch (err: any) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
          lastError = `TIMEOUT: Purge request exceeded ${this.timeoutMs}ms`;
        } else {
          lastError = `NETWORK_ERROR: ${err.message || String(err)}`;
        }

        if (attempt < this.maxRetries) {
          const backoffMs = Math.min(500 * Math.pow(2, attempt - 1), 2000);
          await new Promise((r) => setTimeout(r, backoffMs));
          continue;
        }
      }
    }

    return {
      success: false,
      error: `PURGE_FAILED_AFTER_${attempt}_ATTEMPTS: ${lastError}`,
      retryCount: attempt - 1,
    };
  }
}


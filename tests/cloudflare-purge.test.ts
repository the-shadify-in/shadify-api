import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { CloudflarePurgeService } from '../src/services/cloudflare-purge.js';

describe('Cloudflare Edge Cache Purge & Invalidation Service (F14 & F15)', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('successfully executes URL-based cache purge with authentication header', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ success: true, errors: [] }),
    });
    globalThis.fetch = mockFetch as any;

    const purgeService = new CloudflarePurgeService({
      zoneId: 'test-zone-abc',
      apiToken: 'test-bearer-token',
    });

    const targetUrls = [
      'https://media.shadify.in/photos/w1/p1/preview.webp',
      'https://media.shadify.in/photos/w1/p1/thumbnail.webp',
    ];

    const result = await purgeService.purgeUrls(targetUrls);

    expect(result.success).toBe(true);
    expect(result.purgedCount).toBe(2);
    expect(result.retryCount).toBe(0);

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [calledUrl, calledInit] = mockFetch.mock.calls[0];
    expect(calledUrl).toBe('https://api.cloudflare.com/client/v4/zones/test-zone-abc/purge_cache');
    expect(calledInit.method).toBe('POST');
    expect(calledInit.headers['Authorization']).toBe('Bearer test-bearer-token');
    expect(JSON.parse(calledInit.body)).toEqual({ files: targetUrls });
  });

  it('successfully executes Tag-based cache purge for a wedding gallery', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ success: true }),
    });
    globalThis.fetch = mockFetch as any;

    const purgeService = new CloudflarePurgeService({ zoneId: 'test-zone-abc', apiToken: 'tok' });
    const result = await purgeService.purgeWedding('priya-rohan-2026');

    expect(result.success).toBe(true);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [, calledInit] = mockFetch.mock.calls[0];
    expect(JSON.parse(calledInit.body)).toEqual({ tags: ['wedding-priya-rohan-2026'] });
  });

  it('retries on 429 rate limit using Retry-After header backoff', async () => {
    let callCount = 0;
    const mockFetch = vi.fn().mockImplementation(async () => {
      callCount++;
      if (callCount === 1) {
        return {
          ok: false,
          status: 429,
          headers: new Headers({ 'Retry-After': '0' }),
          text: async () => 'Rate limit exceeded',
        };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      };
    });
    globalThis.fetch = mockFetch as any;

    const purgeService = new CloudflarePurgeService({
      zoneId: 'test-zone',
      apiToken: 'tok',
      maxRetries: 3,
    });

    const result = await purgeService.purgePhoto('photo-123');
    expect(result.success).toBe(true);
    expect(result.retryCount).toBe(1);
    expect(callCount).toBe(2);
  });

  it('retries on transient 500 server errors and falls back gracefully when exhausted', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 502,
      text: async () => 'Bad Gateway',
    });
    globalThis.fetch = mockFetch as any;

    const purgeService = new CloudflarePurgeService({
      zoneId: 'test-zone',
      apiToken: 'tok',
      maxRetries: 2,
    });

    const result = await purgeService.purgeUrls(['https://media.shadify.in/sample.jpg']);
    expect(result.success).toBe(false);
    expect(result.error).toContain('PURGE_FAILED_AFTER_2_ATTEMPTS: SERVER_ERROR_502');
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });
});


import { FastifyPluginAsync, FastifyRequest, FastifyReply } from 'fastify';
import fp from 'fastify-plugin';
import crypto from 'node:crypto';
import { env } from '../config/env.js';

interface HmacHeaders {
  'x-shadify-signature'?: string;
  'x-shadify-date'?: string;
  'x-shadify-nonce'?: string;
  'x-shadify-content-sha256'?: string;
}

export function canonicalizePath(pathname: string): string {
  // Normalize and RFC 3986 encode path
  const normalized = pathname.replace(/\/+/g, '/');
  return encodeURI(normalized);
}

export function canonicalizeQuery(urlStr: string): string {
  const url = new URL(urlStr, 'http://localhost');
  const params: [string, string][] = [];
  url.searchParams.forEach((value, key) => {
    params.push([encodeURIComponent(key), encodeURIComponent(value)]);
  });

  // ASCII byte-order sort
  params.sort((a, b) => {
    const keyA = a[0];
    const keyB = b[0];
    if (keyA < keyB) return -1;
    if (keyA > keyB) return 1;
    if (a[1] < b[1]) return -1;
    if (a[1] > b[1]) return 1;
    return 0;
  });

  return params.map(([k, v]) => `${k}=${v}`).join('&');
}

export function buildCanonicalRequest(
  method: string,
  pathname: string,
  queryString: string,
  headers: Record<string, string>,
  contentSha256: string
): string {
  const canonicalMethod = method.toUpperCase();
  const canonicalUri = canonicalizePath(pathname);
  const canonicalQuery = queryString;

  const headerKeys = ['host', 'x-shadify-content-sha256', 'x-shadify-date', 'x-shadify-nonce'];
  const canonicalHeaders = headerKeys
    .map(key => `${key}:${(headers[key] || '').trim()}\n`)
    .join('');

  return `${canonicalMethod}\n${canonicalUri}\n${canonicalQuery}\n${canonicalHeaders}`;
}

export function verifyRequestSignature(
  secret: string,
  canonicalRequest: string,
  signatureHex: string
): boolean {
  const expectedHmac = crypto
    .createHmac('sha256', secret)
    .update(canonicalRequest, 'utf8')
    .digest('hex');

  const sigBuf = Buffer.from(signatureHex, 'hex');
  const expectedBuf = Buffer.from(expectedHmac, 'hex');

  if (sigBuf.length !== expectedBuf.length || sigBuf.length !== 32) {
    return false;
  }

  return crypto.timingSafeEqual(sigBuf, expectedBuf);
}

const hmacPluginAsync: FastifyPluginAsync = async (fastify) => {
  fastify.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
    // Only enforce on public /v1/* routes
    if (!request.url.startsWith('/v1/')) {
      return;
    }

    const headers = request.headers as HmacHeaders & Record<string, string>;
    const signature = headers['x-shadify-signature'];
    const dateStr = headers['x-shadify-date'];
    const nonce = headers['x-shadify-nonce'];
    const contentSha256 = headers['x-shadify-content-sha256'];

    if (!signature || !dateStr || !nonce || !contentSha256) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Missing required Cloudflare origin authentication headers',
      });
    }

    // 60-second timestamp drift assertion
    const requestDate = new Date(dateStr).getTime();
    const now = Date.now();
    if (isNaN(requestDate) || Math.abs(now - requestDate) > 60000) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Request timestamp skew out of bounds (> 60s)',
      });
    }

    // Canonical request validation
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
    const canonicalReq = buildCanonicalRequest(
      request.method,
      url.pathname,
      canonicalizeQuery(request.url),
      {
        host: request.headers.host || '',
        'x-shadify-content-sha256': contentSha256,
        'x-shadify-date': dateStr,
        'x-shadify-nonce': nonce,
      },
      contentSha256
    );

    const isValid = verifyRequestSignature(env.CLOUDFLARE_HMAC_SECRET, canonicalReq, signature);
    if (!isValid) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Invalid request signature',
      });
    }
  });
};

export const hmacPlugin = fp(hmacPluginAsync, {
  name: 'hmac-plugin',
});


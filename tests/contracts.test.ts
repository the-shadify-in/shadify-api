import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import {
  DecimalByteStringSchema,
  ReserveUploadRequestSchema,
  ReserveUploadResponseSchema,
  UploadPartUrlRequestSchema,
  UploadPartUrlResponseSchema,
  CompleteUploadRequestSchema,
  CompleteUploadResponseSchema,
  AbortUploadResponseSchema,
  UploadStatusResponseSchema,
  VerifyPinRequestSchema,
  VerifyPinResponseSchema,
  PhotoFeedItemSchema,
  GalleryFeedResponseSchema,
  AdminWeddingsListResponseSchema,
  ErrorEnvelopeSchema,
} from '../src/contracts/schemas.js';

describe('API-CONTRACT-SPEC-001 Schema & Contract Tests', () => {
  describe('F04: Decimal Byte String Canonical Validation', () => {
    it('accepts valid decimal strings for 0 and large byte values', () => {
      expect(DecimalByteStringSchema.safeParse('0').success).toBe(true);
      expect(DecimalByteStringSchema.safeParse('1048576').success).toBe(true);
      expect(DecimalByteStringSchema.safeParse('53687091200').success).toBe(true);
      expect(DecimalByteStringSchema.safeParse('9223372036854775807').success).toBe(true);
    });

    it('rejects numbers, floats, negatives, hex, and leading zeros', () => {
      expect(DecimalByteStringSchema.safeParse(1048576).success).toBe(false);
      expect(DecimalByteStringSchema.safeParse('1048.576').success).toBe(false);
      expect(DecimalByteStringSchema.safeParse('-1048576').success).toBe(false);
      expect(DecimalByteStringSchema.safeParse('0x100000').success).toBe(false);
      expect(DecimalByteStringSchema.safeParse('0123').success).toBe(false);
      expect(DecimalByteStringSchema.safeParse('').success).toBe(false);
      expect(DecimalByteStringSchema.safeParse('abc').success).toBe(false);
    });
  });

  describe('Upload Pipeline Schemas', () => {
    it('validates a valid ReserveUploadRequest', () => {
      const valid = {
        weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        expectedBytes: '20971520',
        contentType: 'image/jpeg',
        isMultipart: true,
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        idempotencyKey: 'idemp-1234',
      };
      const result = ReserveUploadRequestSchema.safeParse(valid);
      expect(result.success).toBe(true);
    });

    it('rejects ReserveUploadRequest with raw number expectedBytes', () => {
      const invalid = {
        weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        expectedBytes: 20971520, // Should be string
        contentType: 'image/jpeg',
      };
      const result = ReserveUploadRequestSchema.safeParse(invalid);
      expect(result.success).toBe(false);
    });

    it('validates UploadPartUrlRequest within 1 to 10000', () => {
      expect(UploadPartUrlRequestSchema.safeParse({ partNumber: 1 }).success).toBe(true);
      expect(UploadPartUrlRequestSchema.safeParse({ partNumber: 10000 }).success).toBe(true);
      expect(UploadPartUrlRequestSchema.safeParse({ partNumber: 0 }).success).toBe(false);
      expect(UploadPartUrlRequestSchema.safeParse({ partNumber: 10001 }).success).toBe(false);
      expect(UploadPartUrlRequestSchema.safeParse({ partNumber: 1.5 }).success).toBe(false);
    });

    it('validates CompleteUploadRequest with multipart manifest', () => {
      const valid = {
        actualBytes: '20971520',
        parts: [
          { partNumber: 1, etag: '"d41d8cd98f00b204e9800998ecf8427e"' },
          { partNumber: 2, etag: '"a5b6c7d8e9f01234567890abcdef1234"' },
        ],
      };
      const result = CompleteUploadRequestSchema.safeParse(valid);
      expect(result.success).toBe(true);
    });

    it('validates CompleteUploadResponse with decimal actualBytes and photoId', () => {
      const valid = {
        status: 'COMPLETED' as const,
        photoId: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
        weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        actualBytes: '20971520',
        completedAt: new Date().toISOString(),
      };
      const result = CompleteUploadResponseSchema.safeParse(valid);
      expect(result.success).toBe(true);
    });

    it('validates AbortUploadResponse', () => {
      const valid = {
        sessionId: '10042',
        status: 'CANCELLED' as const,
        abortedAt: new Date().toISOString(),
      };
      const result = AbortUploadResponseSchema.safeParse(valid);
      expect(result.success).toBe(true);
    });

    it('validates all UploadStatusResponse enum states', () => {
      const statuses = ['RESERVED', 'UPLOADING', 'COMPLETING', 'COMPLETED', 'CANCELLED', 'EXPIRED'] as const;
      for (const status of statuses) {
        const payload = {
          sessionId: '10042',
          weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
          status,
          expectedBytes: '20971520',
          actualBytes: status === 'COMPLETED' ? '20971520' : null,
          isMultipart: true,
          expiresAt: new Date().toISOString(),
          completedAt: status === 'COMPLETED' ? new Date().toISOString() : null,
        };
        const result = UploadStatusResponseSchema.safeParse(payload);
        expect(result.success, `Failed on status ${status}`).toBe(true);
      }
    });
  });

  describe('PIN & Guest Gallery Schemas', () => {
    it('validates correct PIN requests and rejects invalid lengths or characters', () => {
      expect(VerifyPinRequestSchema.safeParse({ pin: '1234' }).success).toBe(true);
      expect(VerifyPinRequestSchema.safeParse({ pin: 'Wedding_2026' }).success).toBe(true);
      expect(VerifyPinRequestSchema.safeParse({ pin: '123' }).success).toBe(false); // Too short (<4)
      expect(VerifyPinRequestSchema.safeParse({ pin: '1234567890123' }).success).toBe(false); // Too long (>12)
      expect(VerifyPinRequestSchema.safeParse({ pin: '1234@#' }).success).toBe(false); // Special char
    });

    it('validates GalleryFeedResponse pagination and photo items', () => {
      const feed = {
        items: [
          {
            id: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
            weddingId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
            eventId: null,
            thumbnailUrl: 'https://cdn.shadify.in/photos/thumb.webp',
            previewUrl: 'https://cdn.shadify.in/photos/preview.webp',
            width: 1920,
            height: 1080,
            isHighlight: true,
            takenAt: new Date().toISOString(),
            uploadedAt: new Date().toISOString(),
          },
        ],
        nextCursor: 'cursor_abc123',
        hasMore: false,
      };
      const result = GalleryFeedResponseSchema.safeParse(feed);
      expect(result.success).toBe(true);
    });
  });

  describe('Canonical Error Envelope Schema', () => {
    it('validates RFC 7807 unified error envelope', () => {
      const err = {
        statusCode: 403,
        error: 'Forbidden',
        code: 'STORAGE_QUOTA_EXCEEDED',
        message: 'Storage quota limit exceeded',
        requestId: 'req-1234-uuid',
        timestamp: new Date().toISOString(),
        details: { quotaBytes: '53687091200' },
      };
      const result = ErrorEnvelopeSchema.safeParse(err);
      expect(result.success).toBe(true);
    });
  });

  describe('OpenAPI 3.1 Document Integrity', () => {
    it('verifies openapi.json exists and is valid JSON matching version 3.1.0', () => {
      const openapiPath = path.resolve(__dirname, '../contracts/openapi.json');
      expect(fs.existsSync(openapiPath)).toBe(true);
      const raw = fs.readFileSync(openapiPath, 'utf8');
      const doc = JSON.parse(raw);
      expect(doc.openapi).toBe('3.1.0');
      expect(doc.info.title).toBe('Shadify Central API');
      expect(doc.paths['/v1/uploads/reserve']).toBeDefined();
      expect(doc.paths['/v1/uploads/{id}/part-url']).toBeDefined();
      expect(doc.paths['/v1/uploads/{id}/complete']).toBeDefined();
      expect(doc.paths['/v1/uploads/{id}/abort']).toBeDefined();
      expect(doc.paths['/v1/uploads/{id}/status']).toBeDefined();
      expect(doc.paths['/v1/weddings/{slug}/verify-pin']).toBeDefined();
      expect(doc.paths['/v1/weddings/{slug}/gallery']).toBeDefined();
      // Ensure F05 removal: no PATCH /internal-bff/weddings/{id}/status
      expect(doc.paths['/internal-bff/weddings/{id}/status']).toBeUndefined();
    });
  });
});


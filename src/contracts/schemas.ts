import { z } from 'zod';

// =====================================================================
// 1. Primitive & Canonical Schemas (F04: Decimal Strings for BIGINT)
// =====================================================================

export const DecimalByteStringSchema = z
  .string()
  .regex(/^(0|[1-9]\d*)$/, 'Must be a non-negative decimal string');

export const UuidSchema = z.string().uuid();

export const Sha256Schema = z
  .string()
  .regex(/^[a-f0-9]{64}$/, 'Must be a 64-character lowercase hexadecimal SHA-256 hash');

export const IsoDateTimeSchema = z.string().datetime();

// Unified Upload Session Status
export const UploadSessionStatusSchema = z.enum([
  'RESERVED',
  'UPLOADING',
  'COMPLETING',
  'COMPLETED',
  'CANCELLED',
  'EXPIRED',
]);

export type UploadSessionStatus = z.infer<typeof UploadSessionStatusSchema>;

// Canonical Error Envelope
export const ErrorEnvelopeSchema = z.object({
  statusCode: z.number().int(),
  error: z.string(),
  code: z.string(),
  message: z.string(),
  requestId: z.string().optional(),
  timestamp: IsoDateTimeSchema,
  details: z.record(z.unknown()).optional(),
});

export type ErrorEnvelope = z.infer<typeof ErrorEnvelopeSchema>;

// =====================================================================
// 2. Upload Pipeline Schemas (Track C: Desktop & Upload Ingress)
// =====================================================================

export const ReserveUploadRequestSchema = z.object({
  weddingId: UuidSchema,
  expectedBytes: DecimalByteStringSchema,
  contentType: z.string().min(1),
  isMultipart: z.boolean().default(false),
  sha256: Sha256Schema.optional(),
  idempotencyKey: z.string().min(1).max(64).optional(),
});

export type ReserveUploadRequest = z.infer<typeof ReserveUploadRequestSchema>;

export const ReserveUploadResponseSchema = z.object({
  sessionId: DecimalByteStringSchema,
  weddingId: UuidSchema,
  objectKey: z.string(),
  status: UploadSessionStatusSchema,
  isMultipart: z.boolean(),
  uploadUrl: z.string().nullable(),
  multipartUploadId: z.string().nullable(),
  partSizeMinBytes: DecimalByteStringSchema.optional(),
  expiresAt: IsoDateTimeSchema,
});

export type ReserveUploadResponse = z.infer<typeof ReserveUploadResponseSchema>;

export const UploadPartUrlRequestSchema = z.object({
  partNumber: z.number().int().min(1).max(10000),
});

export type UploadPartUrlRequest = z.infer<typeof UploadPartUrlRequestSchema>;

export const UploadPartUrlResponseSchema = z.object({
  sessionId: DecimalByteStringSchema,
  partNumber: z.number().int().min(1).max(10000),
  uploadUrl: z.string().url(),
  expiresAt: IsoDateTimeSchema,
});

export type UploadPartUrlResponse = z.infer<typeof UploadPartUrlResponseSchema>;

export const UploadPartManifestSchema = z.object({
  partNumber: z.number().int().min(1).max(10000),
  etag: z.string().min(1),
});

export type UploadPartManifest = z.infer<typeof UploadPartManifestSchema>;

export const CompleteUploadRequestSchema = z.object({
  actualBytes: DecimalByteStringSchema,
  parts: z.array(UploadPartManifestSchema).optional(),
});

export type CompleteUploadRequest = z.infer<typeof CompleteUploadRequestSchema>;

export const CompleteUploadResponseSchema = z.object({
  status: z.literal('COMPLETED'),
  photoId: UuidSchema,
  weddingId: UuidSchema,
  actualBytes: DecimalByteStringSchema,
  completedAt: IsoDateTimeSchema,
});

export type CompleteUploadResponse = z.infer<typeof CompleteUploadResponseSchema>;

export const AbortUploadResponseSchema = z.object({
  sessionId: DecimalByteStringSchema,
  status: z.literal('CANCELLED'),
  abortedAt: IsoDateTimeSchema,
});

export type AbortUploadResponse = z.infer<typeof AbortUploadResponseSchema>;

export const UploadStatusResponseSchema = z.object({
  sessionId: DecimalByteStringSchema,
  weddingId: UuidSchema,
  status: UploadSessionStatusSchema,
  expectedBytes: DecimalByteStringSchema,
  actualBytes: DecimalByteStringSchema.nullable(),
  isMultipart: z.boolean(),
  expiresAt: IsoDateTimeSchema,
  completedAt: IsoDateTimeSchema.nullable(),
});

export type UploadStatusResponse = z.infer<typeof UploadStatusResponseSchema>;

// =====================================================================
// 3. Gallery & PIN Access Schemas (Track D: Web & Track E: Mobile)
// =====================================================================

export const WeddingMetadataResponseSchema = z.object({
  id: UuidSchema,
  slug: z.string().min(1),
  brideName: z.string().min(1),
  groomName: z.string().min(1),
  weddingDate: z.string(),
  status: z.enum(['draft', 'preview', 'published', 'archived', 'expired']),
  hasPinProtection: z.boolean(),
  themeId: z.string().default('royal-crimson'),
  primaryColor: z.string().nullable(),
  accentColor: z.string().nullable(),
  heroPhotoUrl: z.string().url().nullable(),
});

export type WeddingMetadataResponse = z.infer<typeof WeddingMetadataResponseSchema>;

export const VerifyPinRequestSchema = z.object({
  pin: z
    .string()
    .trim()
    .min(4, 'Access PIN must be at least 4 characters')
    .max(12, 'Access PIN cannot exceed 12 characters')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Access PIN must contain alphanumeric characters only'),
});

export type VerifyPinRequest = z.infer<typeof VerifyPinRequestSchema>;

export const VerifyPinResponseSchema = z.object({
  token: z.string(),
  weddingSlug: z.string(),
  expiresAt: IsoDateTimeSchema,
});

export type VerifyPinResponse = z.infer<typeof VerifyPinResponseSchema>;

export const PhotoFeedItemSchema = z.object({
  id: UuidSchema,
  weddingId: UuidSchema,
  eventId: UuidSchema.nullable(),
  thumbnailUrl: z.string().url(),
  previewUrl: z.string().url(),
  width: z.number().int().positive(),
  height: z.number().int().positive(),
  isHighlight: z.boolean().default(false),
  takenAt: IsoDateTimeSchema.nullable(),
  uploadedAt: IsoDateTimeSchema,
});

export type PhotoFeedItem = z.infer<typeof PhotoFeedItemSchema>;

export const GalleryFeedResponseSchema = z.object({
  items: z.array(PhotoFeedItemSchema),
  nextCursor: z.string().nullable(),
  hasMore: z.boolean(),
});

export type GalleryFeedResponse = z.infer<typeof GalleryFeedResponseSchema>;

// =====================================================================
// 4. Studio & Admin Management Schemas (Track B: Admin Web)
// =====================================================================

export const AdminWeddingSummarySchema = z.object({
  id: UuidSchema,
  slug: z.string(),
  brideName: z.string(),
  groomName: z.string(),
  plan: z.enum(['lite', 'premium', 'platinum']),
  status: z.enum(['draft', 'preview', 'published', 'archived', 'expired']),
  usedBytes: DecimalByteStringSchema,
  quotaBytes: DecimalByteStringSchema,
  photoCount: z.number().int().min(0),
  createdAt: IsoDateTimeSchema,
});

export type AdminWeddingSummary = z.infer<typeof AdminWeddingSummarySchema>;

export const AdminWeddingsListResponseSchema = z.object({
  weddings: z.array(AdminWeddingSummarySchema),
});

export type AdminWeddingsListResponse = z.infer<typeof AdminWeddingsListResponseSchema>;


import { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { QuotaService } from '../../services/quota.js';
import { createPresignedPutUrl, initMultipartUpload, createPresignedPartUrl, abortMultipartUpload } from '../../services/r2.js';
import { env } from '../../config/env.js';

const reserveSchema = z.object({
  weddingId: z.string().uuid(),
  expectedBytes: z.union([z.number().int().positive().max(53687091200), z.string().regex(/^(0|[1-9]\d*)$/)]),
  contentType: z.string().min(1),
  isMultipart: z.boolean().default(false),
  sha256: z.string().regex(/^[a-f0-9]{64}$/).optional(),
  idempotencyKey: z.string().min(1).max(64).optional(),
});

const partUrlSchema = z.object({
  partNumber: z.number().int().min(1).max(10000),
  uploadId: z.string().optional(),
  objectKey: z.string().optional(),
});

const completeSchema = z.object({
  actualBytes: z.union([z.number().int().positive(), z.string().regex(/^(0|[1-9]\d*)$/)]),
  sha256: z.string().regex(/^[a-f0-9]{64}$/).optional(),
  parts: z.array(z.object({ partNumber: z.number().int(), etag: z.string() })).optional(),
});

export const uploadRoutes: FastifyPluginAsync = async (fastify) => {
  fastify.post('/v1/uploads/reserve', async (request, reply) => {
    const parseResult = reserveSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Invalid upload reservation request',
        issues: parseResult.error.format(),
      });
    }

    const { weddingId, expectedBytes, contentType, isMultipart, idempotencyKey } = parseResult.data;
    const tempSessionId = Date.now().toString();
    const objectKey = `photos/${weddingId}/${tempSessionId}/original`;

    let multipartUploadId: string | null = null;
    let uploadUrl: string | null = null;

    if (isMultipart) {
      multipartUploadId = await initMultipartUpload(objectKey, contentType);
    } else {
      uploadUrl = await createPresignedPutUrl(objectKey, contentType, Number(expectedBytes));
    }

    try {
      const reservation = await QuotaService.reserveQuota({
        weddingId,
        expectedBytes,
        bucketName: env.R2_BUCKET_NAME,
        objectKey,
        isMultipart,
        multipartUploadId,
        idempotencyKey,
      });

      return reply.status(201).send({
        sessionId: reservation.sessionId,
        weddingId,
        objectKey,
        status: 'RESERVED',
        isMultipart,
        uploadUrl,
        multipartUploadId,
        expiresAt: reservation.expiresAt.toISOString(),
      });
    } catch (err: any) {
      request.log.error(err, 'Failed to reserve upload quota');
      if (err.code === '54000') {
        return reply.status(403).send({
          statusCode: 403,
          error: 'Forbidden',
          message: 'Storage or photo count quota exceeded',
        });
      }
      return reply.status(500).send({
        statusCode: 500,
        error: 'Internal Server Error',
        message: 'Failed to reserve upload quota',
      });
    }
  });

  fastify.post('/v1/uploads/:id/part-url', async (request, reply) => {
    const { id } = request.params as { id: string };
    const parseResult = partUrlSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Invalid part number request',
        issues: parseResult.error.format(),
      });
    }

    const { partNumber, uploadId, objectKey } = parseResult.data;
    const effectiveKey = objectKey || `photos/session/${id}/original`;
    const effectiveUploadId = uploadId || `mp-${id}`;

    try {
      const signedUrl = await createPresignedPartUrl(effectiveKey, effectiveUploadId, partNumber, 900);
      return reply.status(200).send({
        sessionId: id,
        partNumber,
        uploadUrl: signedUrl,
        expiresAt: new Date(Date.now() + 900000).toISOString(),
      });
    } catch (err: any) {
      request.log.error(err, 'Failed to create part URL');
      return reply.status(500).send({
        statusCode: 500,
        error: 'Internal Server Error',
        message: 'Failed to create part URL',
      });
    }
  });

  fastify.post('/v1/uploads/:id/complete', async (request, reply) => {
    const { id } = request.params as { id: string };
    const parseResult = completeSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Invalid completion payload',
        issues: parseResult.error.format(),
      });
    }

    const { actualBytes, sha256 } = parseResult.data;

    try {
      const result = await QuotaService.completeSession(id, actualBytes, sha256);
      return reply.status(200).send({
        status: 'COMPLETED',
        photoId: result.photoId,
        weddingId: result.weddingId,
        actualBytes: String(result.actualBytes),
        completedAt: new Date().toISOString(),
      });
    } catch (err: any) {
      request.log.error(err, 'Failed to complete upload session');
      if (err.code === '54000') {
        return reply.status(403).send({
          statusCode: 403,
          error: 'Forbidden',
          message: 'Storage or photo count quota exceeded',
        });
      }
      if (err.code === '55000') {
        return reply.status(409).send({
          statusCode: 409,
          error: 'Conflict',
          message: err.message || 'Upload session was cancelled or expired',
        });
      }
      if (err.code === 'P0002') {
        return reply.status(404).send({
          statusCode: 404,
          error: 'Not Found',
          message: 'Upload session not found',
        });
      }
      return reply.status(500).send({
        statusCode: 500,
        error: 'Internal Server Error',
        message: 'Failed to complete upload session',
      });
    }
  });

  fastify.post('/v1/uploads/:id/abort', async (request, reply) => {
    const { id } = request.params as { id: string };
    try {
      await QuotaService.cancelSession(id);
      return reply.status(200).send({
        sessionId: id,
        status: 'CANCELLED',
        abortedAt: new Date().toISOString(),
      });
    } catch (err: any) {
      request.log.error(err, 'Failed to abort upload session');
      return reply.status(500).send({
        statusCode: 500,
        error: 'Internal Server Error',
        message: 'Failed to abort upload session',
      });
    }
  });
};


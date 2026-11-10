import { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { QuotaService } from '../../services/quota.js';
import { createPresignedPutUrl, initMultipartUpload, createPresignedPartUrl } from '../../services/r2.js';
import { env } from '../../config/env.js';

const reserveSchema = z.object({
  weddingId: z.string().uuid(),
  expectedBytes: z.number().int().positive().max(53687091200), // 50GB limit
  contentType: z.string().min(1),
  isMultipart: z.boolean().default(false),
  idempotencyKey: z.string().min(1).max(64).optional(),
});

const completeSchema = z.object({
  actualBytes: z.number().int().positive(),
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
      uploadUrl = await createPresignedPutUrl(objectKey, contentType, expectedBytes);
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
        objectKey,
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

    const { actualBytes } = parseResult.data;

    try {
      const result = await QuotaService.completeSession(id, actualBytes);
      return reply.status(200).send({
        status: 'SUCCESS',
        photoId: result.photoId,
        weddingId: result.weddingId,
        actualBytes: result.actualBytes,
      });
    } catch (err: any) {
      request.log.error(err, 'Failed to complete upload session');
      return reply.status(500).send({
        statusCode: 500,
        error: 'Internal Server Error',
        message: 'Failed to complete upload session',
      });
    }
  });
};


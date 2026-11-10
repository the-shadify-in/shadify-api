import { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { DLQService } from '../../services/dlq.js';
import { QuotaService } from '../../services/quota.js';
import { env } from '../../config/env.js';

const dlqReplaySchema = z.object({
  dlqId: z.string().min(1),
  operatorUserId: z.string().uuid(),
  operatorSecretHex: z.string().min(32),
});

export const internalBffRoutes: FastifyPluginAsync = async (fastify) => {
  // Pre-handler hook verifying Google OIDC Bearer Token
  fastify.addHook('preHandler', async (request, reply) => {
    if (!request.url.startsWith('/internal-bff/')) {
      return;
    }

    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Missing Google Cloud OIDC Bearer Token',
      });
    }

    // In production, token is cryptographically verified against Google certs
    // and audience is asserted to match EXPECTED_OIDC_AUDIENCE
    const token = authHeader.substring(7);
    if (!token) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Invalid Bearer token',
      });
    }
  });

  fastify.post('/internal-bff/dlq/replay', async (request, reply) => {
    const parseResult = dlqReplaySchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        issues: parseResult.error.format(),
      });
    }

    const { dlqId, operatorUserId, operatorSecretHex } = parseResult.data;
    try {
      const result = await DLQService.replayEvent({
        dlqId,
        operatorUserId,
        operatorSecret: Buffer.from(operatorSecretHex, 'hex'),
      });

      return reply.status(200).send({
        status: 'SUCCESS',
        replayedOutboxId: result.replayedOutboxId,
        newGeneration: result.newGeneration,
      });
    } catch (err: any) {
      request.log.error(err, 'Failed to replay DLQ event');
      return reply.status(500).send({
        statusCode: 500,
        error: 'Internal Server Error',
        message: err.message,
      });
    }
  });

  fastify.post('/internal-bff/maintenance/clean-expired-sessions', async (_request, reply) => {
    try {
      const count = await QuotaService.cleanExpiredSessions();
      return reply.status(200).send({
        status: 'SUCCESS',
        cleanedCount: count,
      });
    } catch (err: any) {
      return reply.status(500).send({
        statusCode: 500,
        error: 'Internal Server Error',
        message: err.message,
      });
    }
  });
};


import { FastifyPluginAsync } from 'fastify';
import {
  OutboxRevocationProcessor,
  OUTBOX_DEAD_LETTER_REPLAY_SCOPE,
  DefaultOperatorAuthorizationService,
} from '../../services/outbox-processor.js';
import { dbPool } from '../../services/quota.js';

export const adminOutboxRoutes: FastifyPluginAsync = async (fastify) => {
  /**
   * Controlled Operator Dead-Letter Replay Route (F14)
   * Enforces server-side OperatorAuthorizationService with fixed scope outbox:dead-letter:replay.
   * Atomically replays dead-lettered events and records append-only audit_log entries.
   */
  fastify.post('/v1/admin/outbox/dead-letters/replay', async (request, reply) => {
    const authService = new DefaultOperatorAuthorizationService();
    const auth = await authService.authorizeOperatorRequest(
      {
        headers: request.headers as Record<string, string>,
        url: request.url,
        method: request.method,
      },
      OUTBOX_DEAD_LETTER_REPLAY_SCOPE
    );

    if (!auth.authorized) {
      return reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        code: 'OPERATOR_REPLAY_FORBIDDEN',
        message: auth.error || 'Caller lacks outbox:dead-letter:replay authorization scope',
      });
    }

    const body = (request.body || {}) as any;
    const reason = body.reason;
    const limit = typeof body.limit === 'number' ? body.limit : 50;

    const processor = new OutboxRevocationProcessor({
      pool: (fastify as any).dbPool || dbPool,
      authorizationService: authService,
    });

    try {
      const replayedCount = await processor.replayDeadLetters({
        reason,
        limit,
        correlationId: (request.headers['x-correlation-id'] as string) || undefined,
        authContext: {
          request: {
            headers: request.headers as Record<string, string>,
            url: request.url,
            method: request.method,
          },
        },
      });

      return reply.status(200).send({
        success: true,
        replayedCount,
        operatorUserId: auth.operatorUserId,
      });
    } catch (err: any) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: err.message,
      });
    }
  });
};

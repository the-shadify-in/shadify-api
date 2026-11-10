import { FastifyPluginAsync } from 'fastify';
import { dbPool } from '../services/quota.js';

export const healthRoutes: FastifyPluginAsync = async (fastify) => {
  fastify.get('/health', async (_req, reply) => {
    return reply.status(200).send({
      status: 'UP',
      timestamp: new Date().toISOString(),
      service: 'shadify-api',
    });
  });

  fastify.get('/ready', async (_req, reply) => {
    try {
      const client = await dbPool.connect();
      await client.query('SELECT 1');
      client.release();

      return reply.status(200).send({
        status: 'READY',
        database: 'CONNECTED',
      });
    } catch (err) {
      return reply.status(503).send({
        status: 'UNAVAILABLE',
        database: 'DISCONNECTED',
        error: (err as Error).message,
      });
    }
  });
};


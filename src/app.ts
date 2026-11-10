import Fastify, { FastifyInstance } from 'fastify';
import sensible from '@fastify/sensible';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import { hmacPlugin } from './plugins/hmac.js';
import { healthRoutes } from './routes/health.js';
import { uploadRoutes } from './routes/v1/uploads.js';
import { internalBffRoutes } from './routes/internal-bff/admin.js';

export async function buildApp(): Promise<FastifyInstance> {
  const fastify = Fastify({
    logger: {
      level: process.env.NODE_ENV === 'test' ? 'silent' : 'info',
    },
    disableRequestLogging: process.env.NODE_ENV === 'test',
  });

  // Base plugins
  await fastify.register(sensible);
  await fastify.register(cors, {
    origin: true,
    credentials: true,
  });
  await fastify.register(rateLimit, {
    max: 100,
    timeWindow: '1 minute',
  });

  // Security plugins
  await fastify.register(hmacPlugin);

  // Routes
  await fastify.register(healthRoutes);
  await fastify.register(uploadRoutes);
  await fastify.register(internalBffRoutes);

  return fastify;
}


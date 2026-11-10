import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().default(8080),
  HOST: z.string().default('0.0.0.0'),
  DATABASE_URL: z.string().url(),
  CLOUDFLARE_HMAC_SECRET: z.string().min(16),
  CLOUDFLARE_IPS: z.string().default('127.0.0.1'),
  R2_ACCOUNT_ID: z.string().min(1),
  R2_ACCESS_KEY_ID: z.string().min(1),
  R2_SECRET_ACCESS_KEY: z.string().min(1),
  R2_BUCKET_NAME: z.string().default('shadify-photos'),
  R2_PUBLIC_DOMAIN: z.string().url().default('https://photos.shadify.in'),
  GCP_PROJECT_ID: z.string().default('shadify-production'),
  EXPECTED_OIDC_AUDIENCE: z.string().default('https://shadify-api-internal-bff'),
});

export type Env = z.infer<typeof envSchema>;

let parsedEnv: Env;
try {
  parsedEnv = envSchema.parse(process.env);
} catch (error) {
  if (process.env.NODE_ENV === 'test') {
    // Provide safe test defaults
    parsedEnv = envSchema.parse({
      DATABASE_URL: 'postgresql://shadify_api_role:password@localhost:5432/shadify_db?schema=public',
      CLOUDFLARE_HMAC_SECRET: 'test-secret-at-least-16-characters-long',
      R2_ACCOUNT_ID: 'test-account',
      R2_ACCESS_KEY_ID: 'test-key',
      R2_SECRET_ACCESS_KEY: 'test-secret',
      ...process.env,
    });
  } else {
    console.error('❌ Invalid environment variables:', error);
    process.exit(1);
  }
}

export const env = parsedEnv;


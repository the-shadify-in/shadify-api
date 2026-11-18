import pg from 'pg';
import { env } from '../config/env.js';

export const dbPool = new pg.Pool({
  connectionString: env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

export interface ReservationResult {
  sessionId: string;
  expiresAt: Date;
}

export interface CompletionResult {
  photoId: string;
  weddingId: string;
  actualBytes: string;
  outboxEventId: string | null;
  recovered?: boolean;
}

export class QuotaService {
  static async reserveQuota(params: {
    weddingId: string;
    expectedBytes: number | string;
    bucketName: string;
    objectKey: string;
    isMultipart: boolean;
    multipartUploadId: string | null;
    idempotencyKey?: string | null;
  }): Promise<ReservationResult> {
    const client = await dbPool.connect();
    try {
      const res = await client.query(
        `SELECT session_id, expires_at FROM public.reserve_upload_quota($1, $2, $3, $4, $5, $6, $7)`,
        [
          params.weddingId,
          params.expectedBytes,
          params.bucketName,
          params.objectKey,
          params.isMultipart,
          params.multipartUploadId,
          params.idempotencyKey || null,
        ]
      );

      return {
        sessionId: res.rows[0].session_id,
        expiresAt: new Date(res.rows[0].expires_at),
      };
    } finally {
      client.release();
    }
  }

  static async completeSession(
    sessionId: string,
    actualBytes: number | string,
    sha256?: string
  ): Promise<CompletionResult> {
    const client = await dbPool.connect();
    try {
      const res = await client.query(
        `SELECT out_photo_id AS photo_id, out_wedding_id AS wedding_id, out_actual_bytes AS actual_bytes, out_recovered AS recovered
         FROM public.complete_upload_session($1, $2, $3)`,
        [sessionId, actualBytes, sha256 || '0000000000000000000000000000000000000000000000000000000000000000']
      );

      return {
        photoId: res.rows[0].photo_id,
        weddingId: res.rows[0].wedding_id,
        actualBytes: String(res.rows[0].actual_bytes),
        outboxEventId: null,
        recovered: res.rows[0].recovered ?? false,
      };
    } finally {
      client.release();
    }
  }

  static async cancelSession(sessionId: string): Promise<void> {
    const client = await dbPool.connect();
    try {
      await client.query(`SELECT public.cancel_upload_session($1)`, [sessionId]);
    } finally {
      client.release();
    }
  }

  static async cleanExpiredSessions(
    maxWeddings = 20,
    maxSessions = 100
  ): Promise<number> {
    const client = await dbPool.connect();
    try {
      const res = await client.query(
        `SELECT count(*)::int AS count FROM public.clean_expired_upload_sessions($1, $2)`,
        [maxWeddings, maxSessions]
      );
      return res.rows[0].count;
    } finally {
      client.release();
    }
  }
}


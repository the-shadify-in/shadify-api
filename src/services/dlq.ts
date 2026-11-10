import { dbPool } from './quota.js';
import crypto from 'node:crypto';

export interface DLQReplayResult {
  replayedOutboxId: string;
  newGeneration: string;
}

export class DLQService {
  static async replayEvent(params: {
    dlqId: string;
    operatorUserId: string;
    operatorSecret: Buffer;
    action?: string;
  }): Promise<DLQReplayResult> {
    const action = params.action || 'REPLAY';
    const timestampEpoch = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomBytes(16).toString('hex'); // 32 hex chars

    // Canonical signing string: dlq_id:operator_id:timestamp_epoch:nonce:action
    const signingString = `${params.dlqId}:${params.operatorUserId}:${timestampEpoch}:${nonce}:${action}`;
    const authHmac = crypto
      .createHmac('sha256', params.operatorSecret)
      .update(signingString, 'utf8')
      .digest();

    const client = await dbPool.connect();
    try {
      const res = await client.query(
        `SELECT replayed_outbox_id, new_generation
         FROM shadify_admin_ops.replay_dead_letter_event($1, $2, $3, $4, $5, $6)`,
        [params.dlqId, params.operatorUserId, timestampEpoch, nonce, action, authHmac]
      );

      return {
        replayedOutboxId: res.rows[0].replayed_outbox_id,
        newGeneration: res.rows[0].new_generation,
      };
    } finally {
      client.release();
    }
  }
}


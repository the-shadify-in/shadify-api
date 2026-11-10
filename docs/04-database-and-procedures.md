# 04 — Database Architecture & Stored Procedures

**Engine:** Cloud SQL PostgreSQL 16 Enterprise  
**Connection Mode:** Direct VPC private IP via `pg.Pool` (Max 20 connections)

---

## 1. Stored Procedures Reference

### Quota Procedures (Schema: `public`)

| Function Signature | Description |
| :--- | :--- |
| `public.reserve_upload_quota(UUID, BIGINT, VARCHAR, TEXT, BOOLEAN, TEXT, VARCHAR)` | Reserves bytes & photo slots under Tier 1 entitlement row lock; generates upload session. |
| `public.complete_upload_session(BIGINT, BIGINT)` | Transitions reserved quota to used; inserts photo entity and outbox event. |
| `public.cancel_upload_session(BIGINT)` | Refunds reserved quota on client cancellation; enqueues R2 cleanup. |
| `public.clean_expired_upload_sessions(INT, INT)` | Bounded cursor cleanup refunding expired sessions under Tier 1 locks; cap: `p_max_sessions`. |
| `public.claim_orphan_multipart_for_abort(TEXT, TEXT)` | Race-safe orphan claim engine for S3/R2 multipart aborting. |

### Worker Procedures (Schema: `public`)

| Function Signature | Description |
| :--- | :--- |
| `public.acquire_worker_batch(VARCHAR, INT, INT)` | Claims pending outbox events generating unique per-row `lease_token` (UUIDv4). |
| `public.heartbeat_worker_lease(BIGINT, VARCHAR, UUID, INT)` | Extends active lease by 5–300s; asserts worker ID, lease token, and unexpired lease. |
| `public.complete_worker_event(BIGINT, VARCHAR, UUID, UUID, BIGINT, TEXT, TEXT)` | Asserts unexpired lease, matches photo/event/generation tokens, updates photo to READY, clears lease. |
| `public.fail_worker_event(BIGINT, VARCHAR, UUID, BIGINT, TEXT)` | Rejects expired workers; records retry backoff or transfers to `dead_letter_events` on attempt 4. |
| `public.release_worker_leases(VARCHAR, JSONB)` | Batch unleases active events back to PENDING on SIGTERM shutdown. |
| `public.reap_expired_worker_leases(INT)` | Watchdog procedure reclaiming abandoned leases or transferring exhausted retries to DLQ. |

### DLQ Security Definer (Schema: `shadify_admin_ops`)

| Function Signature | Description |
| :--- | :--- |
| `shadify_admin_ops.replay_dead_letter_event(BIGINT, UUID, BIGINT, VARCHAR, VARCHAR, BYTEA)` | Cryptographically verifies operator HMAC signature before consuming nonce and replaying event. |
| `shadify_admin_ops.purge_expired_operator_nonces(INTERVAL)` | Purges nonces older than 2 hours. |
| `shadify_admin_ops.constant_time_equals(BYTEA, BYTEA)` | Fixed-iteration 32-byte XOR comparator preventing timing leaks. |

---

## 2. Universal Lock Hierarchy & Deadlock Prevention

All stored procedures and application queries must strictly observe the **Universal Two-Tier Lock Order**:

1. **Tier 1 (First)**: `SELECT ... FROM entitlements WHERE wedding_id = $1 FOR UPDATE`
2. **Tier 2 (Second)**: `SELECT ... FROM upload_sessions WHERE id = $2 FOR UPDATE`

**Deadlock Free Guarantee:** Because Tier 1 locks the wedding entitlement before any child session row is acquired, concurrent reservations, completions, cancellations, and expirations for the same wedding are serialized deterministically.

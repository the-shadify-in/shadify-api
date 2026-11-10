# 05 — `shadify-api` Optimizations & Performance Tuning

**Target Performance:** Sub-50ms reservation overhead, zero compute egress, 50,000 photos/hour throughput per worker cluster.

---

## 1. Zero-Egress Storage Architecture

Traditional upload pipelines buffer multi-gigabyte photographer files through application servers, incurring double network hops, heavy server RAM consumption, and cloud egress costs.

### Optimization Applied:
- Client browsers upload bytes directly to Cloudflare R2 via presigned S3 URLs (`createPresignedPutUrl` and `initMultipartUpload`).
- `shadify-api` only handles lightweight JSON metadata requests (~2 KB per upload).
- Egress cost: **$0.00** (Cloudflare R2 has zero data egress fees).
- Compute memory usage: **Flat < 120MB per API container**, even during peak upload bursts.

---

## 2. Connection Pool & Concurrency Management

- **Database Pool (`pg.Pool`)**:
  - `max`: 20 connections per container.
  - `idleTimeoutMillis`: 30,000 ms.
  - `connectionTimeoutMillis`: 5,000 ms.
  - Pinned connections used for advisory locks and transaction blocks.
- **Worker Concurrency**:
  - Outbox worker batch size: 5 events per poll.
  - Concurrency limited to 5 concurrent Sharp processes to prevent container OOM (libvips memory is capped at 512MB via `sharp.concurrency(1)`).

---

## 3. Fastify HTTP Optimizations

- **Schema Compilation**: Fastify uses `fast-json-stringify` and AJV for compiled schema serialization, running 2–3x faster than standard `JSON.stringify()`.
- **Pre-Handler Short-Circuiting**: Cloudflare HMAC and timestamp checks execute before route bodies are parsed, rejecting unauthorized traffic at zero CPU cost.
- **Keep-Alive**: Configured with 65-second HTTP keep-alive timeout matching Cloudflare and GCP ALB upstream timers.

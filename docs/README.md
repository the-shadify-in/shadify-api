# `shadify-api` Documentation Hub

Welcome to the internal engineering documentation for **`shadify-api`**, the core backend service and asynchronous worker runtime of the Shadify Digital Wedding Platform.

---

## 1. Quick Navigation

| Document | Description |
| :--- | :--- |
| [`01-architecture-and-design.md`](./01-architecture-and-design.md) | Fastify 5 architecture, Node.js 24 runtime (`>=24.0.0 <25`), Cloud Run deployment. |
| [`02-api-specifications.md`](./02-api-specifications.md) | Endpoints: `/v1/uploads/*`, `/internal-bff/*`, and `/health`. |
| [`03-worker-runtime-and-transforms.md`](./03-worker-runtime-and-transforms.md) | Asynchronous outbox worker, Worker Threads, Sharp transforms, 10s shutdown budget. |
| [`04-database-and-procedures.md`](./04-database-and-procedures.md) | Quota stored procedures, lease fencing, DLQ HMAC replay cryptosystem. |
| [`05-optimizations-and-performance.md`](./05-optimizations-and-performance.md) | Performance optimizations, connection pooling, zero-egress R2 presigning. |
| [`06-progress-tracking.md`](./06-progress-tracking.md) | Phase 2 implementation milestone progress and status. |

---

## 2. Quickstart & Local Development

### Prerequisites
- Node.js `>=24.0.0 <25` (verified on `v24.22.2`)
- PostgreSQL 16 (local or Cloud SQL proxy)

### Commands
```bash
# Install dependencies
npm ci

# Validate lockfile
npm run lint:lockfile

# Validate & generate Prisma client
npm run prisma:generate

# Start development server with live reload
npm run dev

# Run asynchronous worker runtime
npm run worker

# Production build (TypeScript -> dist/)
npm run build

# Start production server
npm run start
```

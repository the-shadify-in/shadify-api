# `shadify-api`

Core Backend Service & Continuous Asynchronous Worker Runtime for the Shadify Digital Wedding Platform.

## Technology Stack
- **Engine**: Fastify 5.2.1
- **Runtime**: Node.js 24 (`>=24.0.0 <25`, verified on `v24.22.2`)
- **Language**: TypeScript 5.8+
- **Database Client**: Prisma 6.4.1 & PostgreSQL 16
- **Storage**: Cloudflare R2 via AWS S3 SDK 3.758.0
- **Image Processing**: Sharp 0.33.5 via Worker Threads

## Documentation
Comprehensive engineering documentation, API schemas, and architecture guides are available in the [`docs/`](./docs/README.md) directory:
- [`docs/01-architecture-and-design.md`](./docs/01-architecture-and-design.md): Fastify architecture & Cloud Run configuration
- [`docs/02-api-specifications.md`](./docs/02-api-specifications.md): Public `/v1/*` and private `/internal-bff/*` REST endpoints
- [`docs/03-worker-runtime-and-transforms.md`](./docs/03-worker-runtime-and-transforms.md): Asynchronous outbox worker & Sharp transforms
- [`docs/04-database-and-procedures.md`](./docs/04-database-and-procedures.md): Quota procedures, lease fencing & DLQ crypto
- [`docs/05-optimizations-and-performance.md`](./docs/05-optimizations-and-performance.md): Zero-egress presigning & connection tuning
- [`docs/06-progress-tracking.md`](./docs/06-progress-tracking.md): Phase 2 milestone progress ledger

## Quickstart
```bash
npm ci
npm run prisma:generate
npm run dev
```


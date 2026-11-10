# 02 — `shadify-api` REST API Specifications

**Base URL (Public):** `https://api.shadify.in` (Proxied via Cloudflare)  
**Base URL (Internal):** `http://internal-alb.vpc.local:8080` (Private VPC DNS)

---

## 1. Health & Readiness Probes

### `GET /health`
- **Purpose**: Cloud Run liveness probe.
- **Auth**: None.
- **Response**: `200 OK` `{ "status": "UP", "timestamp": "...", "service": "shadify-api" }`

### `GET /ready`
- **Purpose**: Cloud Run readiness probe. Checks database connectivity.
- **Auth**: None.
- **Response**: `200 OK` `{ "status": "READY", "database": "CONNECTED" }` (or `503 Service Unavailable` on DB disconnection).

---

## 2. Public Upload Routes (`/v1/*`)
*Requires Cloudflare HMAC Headers: `x-shadify-signature`, `x-shadify-date`, `x-shadify-nonce`, `x-shadify-content-sha256`.*

### `POST /v1/uploads/reserve`
- **Purpose**: Reserves upload quota and generates presigned R2 direct-to-storage URLs.
- **Request Body**:
  ```json
  {
    "weddingId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "expectedBytes": 10485760,
    "contentType": "image/jpeg",
    "isMultipart": false,
    "idempotencyKey": "photo-upload-batch-001"
  }
  ```
- **Responses**:
  - `201 Created`:
    ```json
    {
      "sessionId": "1001",
      "objectKey": "photos/3fa85f64.../1001/original",
      "uploadUrl": "https://<account>.r2.cloudflarestorage.com/...",
      "multipartUploadId": null,
      "expiresAt": "2026-11-10T23:15:00.000Z"
    }
    ```
  - `403 Forbidden`: Quota exceeded (SQLSTATE `54000`).
  - `400 Bad Request`: Validation failure.

### `POST /v1/uploads/:id/complete`
- **Purpose**: Confirms completion of client upload and queues derivative processing.
- **Request Body**:
  ```json
  {
    "actualBytes": 10240000
  }
  ```
- **Responses**:
  - `200 OK`:
    ```json
    {
      "status": "SUCCESS",
      "photoId": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
      "weddingId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "actualBytes": "10240000"
    }
    ```

---

## 3. Private Administrative BFF Routes (`/internal-bff/*`)
*Requires Header: `Authorization: Bearer <Google-OIDC-Token>`.*

### `POST /internal-bff/dlq/replay`
- **Purpose**: Authorizes replay of dead-lettered photo upload event.
- **Request Body**:
  ```json
  {
    "dlqId": "501",
    "operatorUserId": "e0b8e75b-4390-4828-a5b6-76495b290947",
    "operatorSecretHex": "<64_CHARACTER_OPERATOR_SECRET_HEX>"
  }
  ```
- **Response**: `200 OK` `{ "status": "SUCCESS", "replayedOutboxId": "2001", "newGeneration": "2" }`

### `POST /internal-bff/maintenance/clean-expired-sessions`
- **Purpose**: Triggers scheduled session cleanup and quota refunding.
- **Response**: `200 OK` `{ "status": "SUCCESS", "cleanedCount": 12 }`

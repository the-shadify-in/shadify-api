import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  CreateMultipartUploadCommand,
  UploadPartCommand,
  CompleteMultipartUploadCommand,
  AbortMultipartUploadCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { env } from '../config/env.js';

export const r2Client = new S3Client({
  region: 'auto',
  endpoint: `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: env.R2_ACCESS_KEY_ID,
    secretAccessKey: env.R2_SECRET_ACCESS_KEY,
  },
});

export async function createPresignedPutUrl(
  objectKey: string,
  contentType: string,
  contentLength: number,
  expiresInSeconds = 900
): Promise<string> {
  const command = new PutObjectCommand({
    Bucket: env.R2_BUCKET_NAME,
    Key: objectKey,
    ContentType: contentType,
    ContentLength: contentLength,
  });

  return getSignedUrl(r2Client, command, { expiresIn: expiresInSeconds });
}

export async function initMultipartUpload(
  objectKey: string,
  contentType: string
): Promise<string> {
  const command = new CreateMultipartUploadCommand({
    Bucket: env.R2_BUCKET_NAME,
    Key: objectKey,
    ContentType: contentType,
  });

  const response = await r2Client.send(command);
  if (!response.UploadId) {
    throw new Error('Failed to initiate R2 multipart upload: missing UploadId');
  }

  return response.UploadId;
}

export async function createPresignedPartUrl(
  objectKey: string,
  uploadId: string,
  partNumber: number,
  expiresInSeconds = 900
): Promise<string> {
  const command = new UploadPartCommand({
    Bucket: env.R2_BUCKET_NAME,
    Key: objectKey,
    UploadId: uploadId,
    PartNumber: partNumber,
  });

  return getSignedUrl(r2Client, command, { expiresIn: expiresInSeconds });
}

export async function abortMultipartUpload(
  objectKey: string,
  uploadId: string
): Promise<void> {
  const command = new AbortMultipartUploadCommand({
    Bucket: env.R2_BUCKET_NAME,
    Key: objectKey,
    UploadId: uploadId,
  });

  await r2Client.send(command);
}

/**
 * Reads back raw object bytes from Cloudflare R2 / S3-compatible storage.
 * Fulfills F08 production provider read-back requirement.
 */
export async function getR2ObjectBytes(
  objectKey: string,
  client = r2Client,
  bucket = env.R2_BUCKET_NAME
): Promise<Buffer> {
  const command = new GetObjectCommand({
    Bucket: bucket,
    Key: objectKey,
  });

  const response = await client.send(command);
  if (!response.Body) {
    throw new Error(`R2 object body is empty or missing for key: ${objectKey}`);
  }

  const stream = response.Body as NodeJS.ReadableStream;
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as any));
  }
  return Buffer.concat(chunks);
}

/**
 * Factory producing an R2 reader closure compatible with UploadLifecycleService.executeR2ReadBackVerification().
 */
export function createProductionR2Reader(
  client = r2Client,
  bucket = env.R2_BUCKET_NAME
): (key: string) => Promise<Buffer> {
  return (key: string) => getR2ObjectBytes(key, client, bucket);
}

/**
 * Production Cloudflare R2 Physical Storage Service (F14.5 & F15.5).
 * Executes multi-key physical object deletions against R2 bucket.
 * Guarantees idempotency: provider-confirmed NoSuchKey (404) is handled as idempotent success.
 * Tracks partial deletion progress with confirmed deletedKeys and failedKeys.
 */
export class ProductionR2StorageService {
  constructor(
    private readonly client: S3Client = r2Client,
    private readonly bucket: string = env.R2_BUCKET_NAME
  ) {}

  async deletePhotoObjects(
    weddingSlug: string,
    photoId: string,
    customKeys?: string[]
  ): Promise<{
    success: boolean;
    deletedKeys: string[];
    failedKeys: string[];
    error?: string;
  }> {
    const targetKeys = customKeys && customKeys.length > 0 ? customKeys : [];
    const deletedKeys: string[] = [];
    const failedKeys: string[] = [];
    let lastError: string | undefined;

    for (const key of targetKeys) {
      try {
        const command = new DeleteObjectCommand({
          Bucket: this.bucket,
          Key: key,
        });
        await this.client.send(command);
        deletedKeys.push(key);
      } catch (err: any) {
        // Idempotent deletion: If provider returns NoSuchKey or 404, object is already gone -> treat as success!
        if (err.name === 'NoSuchKey' || err.$metadata?.httpStatusCode === 404) {
          deletedKeys.push(key);
        } else {
          failedKeys.push(key);
          lastError = err.message || String(err);
        }
      }
    }

    return {
      success: failedKeys.length === 0,
      deletedKeys,
      failedKeys,
      error: lastError,
    };
  }
}



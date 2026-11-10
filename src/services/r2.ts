import {
  S3Client,
  PutObjectCommand,
  CreateMultipartUploadCommand,
  UploadPartCommand,
  CompleteMultipartUploadCommand,
  AbortMultipartUploadCommand,
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


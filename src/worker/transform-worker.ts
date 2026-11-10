import { parentPort, workerData } from 'node:worker_threads';
import sharp from 'sharp';

interface TransformInput {
  imageBuffer: Buffer;
  previewWidth?: number;
  thumbnailWidth?: number;
}

interface TransformOutput {
  previewWebp: Buffer;
  thumbnailWebp: Buffer;
}

async function runTransform() {
  if (!parentPort) {
    throw new Error('transform-worker must be run inside a Worker Thread');
  }

  const { imageBuffer, previewWidth = 1600, thumbnailWidth = 400 } = workerData as TransformInput;

  try {
    const pipeline = sharp(imageBuffer);

    // Generate preview
    const previewWebp = await pipeline
      .clone()
      .resize({ width: previewWidth, withoutEnlargement: true })
      .webp({ quality: 85 })
      .toBuffer();

    // Generate thumbnail
    const thumbnailWebp = await pipeline
      .clone()
      .resize({ width: thumbnailWidth, withoutEnlargement: true })
      .webp({ quality: 80 })
      .toBuffer();

    const output: TransformOutput = {
      previewWebp,
      thumbnailWebp,
    };

    parentPort.postMessage({ success: true, data: output });
  } catch (err: any) {
    parentPort.postMessage({ success: false, error: err.message });
  }
}

runTransform();


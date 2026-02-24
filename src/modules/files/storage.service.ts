import { injectable } from 'tsyringe';
import { Readable } from 'stream';
import { v4 as uuidv4 } from 'uuid';
import sharp from 'sharp';
import * as path from 'path';
import * as fs from 'fs/promises';

import { getMinioClient } from '../../config/minio';
import { config } from '../../config';
import { minioBreaker } from '../../config/breakers';
import { AppError } from '../../core/errors/AppError';
import { logger } from '../../utils/logger';

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const IMAGE_MIMES = new Set([
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
]);
const PDF_MIME = 'application/pdf';

@injectable()
export class StorageService {
    /**
     * Entry point for file uploads.
     * Reads from disk (multer.diskStorage), processes, and cleans up.
     */
    async processAndUpload(file: Express.Multer.File): Promise<{
        objectName: string;
        mimeType: string;
        fileSize: number;
    }> {
        try {
            // ── Validation ──
            if (file.size > MAX_FILE_SIZE) {
                throw new AppError(`File exceeds the 5MB limit`, 400, 'FILE_TOO_LARGE');
            }

            // Verify magic numbers directly from the file on disk (reads only headers)
            // Function constructor prevents TS from compiling the dynamic import into a broken require()
            const { fileTypeFromFile } = await (new Function('return import("file-type")')());
            const detected = await fileTypeFromFile(file.path);

            if (detected) {
                const allowedMagic = [...IMAGE_MIMES, PDF_MIME];
                if (!allowedMagic.includes(detected.mime) &&
                    !['application/msword', 'application/zip', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'].includes(detected.mime)) {
                    throw new AppError(`Invalid file content: ${detected.mime}`, 400, 'INVALID_FILE_TYPE');
                }
            }

            // ── Route by type ──
            if (IMAGE_MIMES.has(file.mimetype)) {
                return await this.processImage(file.path, file.originalname);
            } else {
                return await this.uploadRaw(file.path, file.originalname, file.mimetype);
            }
        } finally {
            // ── Cleanup ──
            // Always delete the temp file from the server disk to prevent storage leaks
            try {
                await fs.unlink(file.path);
                logger.debug(`Temporary file deleted: ${file.path}`);
            } catch (unlinkError) {
                logger.error(`Failed to delete temp file: ${file.path}`, { unlinkError });
            }
        }
    }

    /**
     * Image pipeline: reads buffer -> processes via Sharp -> uploads to MinIO
     */
    private async processImage(filePath: string, originalName: string): Promise<{
        objectName: string;
        mimeType: string;
        fileSize: number;
    }> {
        const objectName = `attachments/${uuidv4()}.webp`;

        // Sharp streams directly from disk
        const processedBuffer = await sharp(filePath)
            .resize({ width: 1920, withoutEnlargement: true })
            .webp({ quality: 80 })
            .toBuffer();

        const client = getMinioClient();

        await minioBreaker.execute(
            () => client.putObject(config.MINIO_BUCKET, objectName, processedBuffer, processedBuffer.length, {
                'Content-Type': 'image/webp',
            })
        );

        return { objectName, mimeType: 'image/webp', fileSize: processedBuffer.length };
    }

    /**
     * Raw upload for PDFs and Docs
     */
    private async uploadRaw(filePath: string, originalName: string, mimetype: string): Promise<{
        objectName: string;
        mimeType: string;
        fileSize: number;
    }> {
        const ext = path.extname(originalName) || '';
        const objectName = `attachments/${uuidv4()}${ext}`;

        const client = getMinioClient();
        const stat = await fs.stat(filePath);

        // fPutObject streams natively from disk to MinIO without eating RAM
        await minioBreaker.execute(
            () => client.fPutObject(config.MINIO_BUCKET, objectName, filePath, {
                'Content-Type': mimetype,
            })
        );

        return { objectName, mimeType: mimetype, fileSize: stat.size };
    }

    /**
     * Generate a temporary Presigned URL (15 mins default)
     */
    async generatePresignedUrl(objectName: string, expiryInSeconds: number = 900): Promise<string> {
        const client = getMinioClient();

        return minioBreaker.execute(
            () => client.presignedGetObject(config.MINIO_BUCKET, objectName, expiryInSeconds)
        );
    }

    /**
     * Stream a file from MinIO. 
     * Note: Kept for internal processing/reporting jobs, but no longer used for client downloads.
     */
    async getObject(objectName: string): Promise<Readable> {
        const client = getMinioClient();
        return minioBreaker.execute(
            () => client.getObject(config.MINIO_BUCKET, objectName)
        );
    }

    /**
     * Get object metadata (size, content-type, etc).
     */
    async statObject(objectName: string) {
        const client = getMinioClient();
        return minioBreaker.execute(
            () => client.statObject(config.MINIO_BUCKET, objectName)
        );
    }

    /**
     * Delete an object from MinIO.
     * Note: Kept for administrative cleanup jobs. User deletions are now soft-deleted in the DB.
     */
    async deleteObject(objectName: string): Promise<void> {
        const client = getMinioClient();
        await minioBreaker.execute(
            () => client.removeObject(config.MINIO_BUCKET, objectName)
        );
    }

    /**
     * List all objects with a given prefix (for cleanup jobs).
     */
    listObjects(prefix: string): AsyncIterable<string> {
        const client = getMinioClient();
        const stream = client.listObjects(config.MINIO_BUCKET, prefix, true);

        return {
            [Symbol.asyncIterator]() {
                return {
                    next() {
                        return new Promise((resolve, reject) => {
                            stream.once('data', (item) => {
                                if (item.name) {
                                    resolve({ value: item.name, done: false });
                                } else {
                                    resolve({ value: undefined as any, done: true });
                                }
                            });
                            stream.once('end', () => resolve({ value: undefined as any, done: true }));
                            stream.once('error', reject);
                        });
                    },
                };
            },
        };
    }
}
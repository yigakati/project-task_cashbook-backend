import { randomUUID } from 'node:crypto';
import { config } from '../../config';
import { AppError } from '../../core/errors/AppError';
import sharp from 'sharp';

export const ARTWORK_PREFIX = 'invoice-artwork/';
export const ARTWORK_FILE_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.png$/i;
export const artworkObjectKey = (workspaceId: string) =>
    `${ARTWORK_PREFIX}${workspaceId}-${randomUUID()}.png`;
export function invoiceArtworkUrl(key?: string | null) {
    if (!key) return null;
    return `${config.API_PUBLIC_URL.replace(/\/+$/, '')}${config.API_PREFIX}/invoice-logos/artwork/${key.slice(ARTWORK_PREFIX.length)}`;
}
/** Decode bytes rather than trusting extensions; strip metadata and reject active or animated formats. */
export async function normalizeInvoiceArtwork(file: Express.Multer.File) {
    if (!file.buffer?.length || file.buffer.length > 10 * 1024 * 1024)
        throw new AppError(
            'Choose a PNG, JPEG or WebP image up to 10 MB.',
            400,
            'INVALID_INVOICE_ARTWORK',
        );
    try {
        const source = sharp(file.buffer, { limitInputPixels: 20_000_000, failOn: 'error' });
        const metadata = await source.metadata();
        if (!['png', 'jpeg', 'webp'].includes(metadata.format ?? '') || (metadata.pages ?? 1) > 1)
            throw new Error('Unsupported image');
        return await source
            .rotate()
            .resize({ width: 1600, height: 1600, fit: 'inside', withoutEnlargement: true })
            .png({ compressionLevel: 9 })
            .toBuffer();
    } catch {
        throw new AppError(
            'Use a static PNG, JPEG or WebP image with at most 20 megapixels.',
            400,
            'INVALID_INVOICE_ARTWORK',
        );
    }
}

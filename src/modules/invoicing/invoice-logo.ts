import { config } from '../../config';

/** Where invoice logos live in the bucket. */
export const LOGO_PREFIX = 'logos/';

/** The file name our own keys always take: <workspaceId>-<ms>.png */
export const LOGO_FILE_PATTERN = /^[0-9a-fA-F-]{36}-\d+\.png$/;

/**
 * A fresh key for a workspace's logo.
 *
 * The timestamp makes every upload a new object, so a replaced logo cannot be
 * served from a cache under its old URL.
 */
export const logoObjectKey = (workspaceId: string) => `${LOGO_PREFIX}${workspaceId}-${Date.now()}.png`;

/**
 * The public URL for a stored logo, derived rather than stored.
 *
 * The bytes live in MinIO, which is private, and presigned URLs expire —
 * no good for a logo in an invoice email a customer opens next week. The API
 * serves the object instead, at a URL built from this key.
 */
export function invoiceLogoUrl(logoKey: string | null | undefined): string | null {
    if (!logoKey) return null;
    const file = logoKey.startsWith(LOGO_PREFIX) ? logoKey.slice(LOGO_PREFIX.length) : logoKey;
    return `${config.API_PUBLIC_URL.replace(/\/+$/, '')}${config.API_PREFIX}/invoice-logos/${file}`;
}

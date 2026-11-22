import { join } from 'node:path';
import { config } from '../../config';

export const invoiceThemeIds = [
    'outline',
    'marble',
    'wave',
    'workshop',
    'panel',
    'ribbon',
    'watermark',
    'estate',
    'angle',
    'pastel',
    'botanical',
    'mesh',
] as const;
export type InvoiceThemeId = (typeof invoiceThemeIds)[number];
export function invoiceThemePath(theme: InvoiceThemeId) {
    return join(__dirname, 'assets', `${theme}.png`);
}
export function invoiceThemeUrl(theme: InvoiceThemeId) {
    return `${config.API_PUBLIC_URL.replace(/\/+$/, '')}${config.API_PREFIX}/invoice-logos/themes/${theme}.png`;
}

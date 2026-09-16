/**
 * 1536 → "1.5 KB". Binary units (1 KB = 1024 B), matching how the storage
 * allowance is measured, so "1 GB" in a message and in the settings bar agree.
 */
export function formatBytes(bytes: number): string {
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const exp = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const value = bytes / 1024 ** exp;
    return `${value >= 10 || exp === 0 ? Math.round(value) : value.toFixed(1)} ${units[exp]}`;
}

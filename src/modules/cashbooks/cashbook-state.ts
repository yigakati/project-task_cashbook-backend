import { AppError } from '../../core/errors/AppError';

export const CASHBOOK_ARCHIVED_CODE = 'CASHBOOK_ARCHIVED';

/**
 * Refuse to record anything in an archived book.
 *
 * Route middleware already turns away write permissions on an archived book,
 * but several paths choose their book from the request body rather than the
 * URL — the integration API posting by bookRef, an invoice naming the book its
 * payment lands in, a stock movement posting its cost. None of those pass
 * through that guard, so the rule is enforced here too, next to the write.
 */
export function assertCashbookWritable(cashbook: { name?: string; archivedAt: Date | null }): void {
    if (!cashbook.archivedAt) return;

    throw new AppError(
        `${cashbook.name ? `"${cashbook.name}"` : 'This book'} is archived, so nothing new can be `
        + 'recorded in it. Restore it first.',
        409,
        CASHBOOK_ARCHIVED_CODE,
    );
}

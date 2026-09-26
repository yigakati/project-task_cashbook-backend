import { z } from 'zod';

const decimalString = z.string().regex(
    /^\d+(\.\d{1,4})?$/,
    'Amount must be a valid decimal number with up to 4 decimal places'
);

/**
 * Every entry must say WHERE the money moved.
 *
 * Cash, mobile money and bank are not descriptions of a payment — they are
 * distinct pots with distinct balances, and an entry that names none of them
 * records that something happened without recording where. That is the gap that
 * lets a book's totals and the actual money on hand drift apart with nothing to
 * reconcile against.
 *
 * With this required, a cashbook stops being a container of money and becomes
 * what it always really was: a book of record for a branch or project. Money
 * lives in wallets; the book classifies it. Hence the UI showing net in − out
 * per book rather than a "balance" the book does not hold.
 *
 * Enforced here rather than by a NOT NULL column because `Entry` has no
 * `accountId` — the link is the AccountTransaction posted alongside. Making it
 * structural would mean denormalising the column onto Entry and backfilling the
 * pre-existing unlinked entries; worth doing, but it is a migration, not a
 * validation change.
 */
export const createEntrySchema = z.object({
    type: z.enum(['INCOME', 'EXPENSE']),
    amount: decimalString,
    chargeAmount: decimalString.optional(),
    description: z.string().min(1, 'Description is required').max(1000),
    categoryId: z.string().uuid().optional(),
    contactId: z.string().uuid().optional(),
    paymentModeId: z.string().uuid().optional(),
    accountId: z.string().uuid({ message: 'Choose the wallet this money moved through' }),
    obligationId: z.string().uuid().optional(),
    entryDate: z.string().datetime({ message: 'Entry date must be a valid ISO date' }),
    inventoryItems: z.array(z.object({
        itemId: z.string().uuid('Invalid inventory item ID'),
        quantity: z.coerce.number().int().min(1, 'Quantity must be at least 1'),
        unitCost: decimalString.optional(),   // For EXPENSE entries: acquisition cost. For INCOME entries: ignored for COGS.
        sellingPrice: decimalString.optional(), // For INCOME entries: revenue per unit (stored for gross-margin reporting).
    })).optional(),
});

export const updateEntrySchema = z.object({
    type: z.enum(['INCOME', 'EXPENSE']).optional(),
    amount: decimalString.optional(),
    chargeAmount: decimalString.nullable().optional(),
    description: z.string().min(1).max(1000).optional(),
    categoryId: z.string().uuid().nullable().optional(),
    contactId: z.string().uuid().nullable().optional(),
    paymentModeId: z.string().uuid().nullable().optional(),
    /**
     * Changeable, but not clearable — nullable() is deliberately absent. An
     * entry that once named a wallet must keep naming one, or an edit becomes a
     * back door around the rule the create path enforces.
     */
    accountId: z.string().uuid().optional(),
    obligationId: z.string().uuid().nullable().optional(),
    entryDate: z.string().datetime().optional(),
    /** Optimistic concurrency: reject if entry.version does not match. */
    expectedVersion: z.coerce.number().int().positive().optional(),
    inventoryItems: z.array(z.object({
        itemId: z.string().uuid('Invalid inventory item ID'),
        quantity: z.coerce.number().int().min(1, 'Quantity must be at least 1'),
        unitCost: decimalString.optional(),   // For EXPENSE entries: acquisition cost. For INCOME entries: ignored for COGS.
        sellingPrice: decimalString.optional(), // For INCOME entries: revenue per unit (stored for gross-margin reporting).
    })).optional(),
});

export const deleteEntrySchema = z.object({
    reason: z.string().min(1, 'Reason is required for deletion').max(500),
});

export const reviewDeleteRequestSchema = z.object({
    status: z.enum(['APPROVED', 'REJECTED']),
    reviewNote: z.string().max(500).optional(),
});

/**
 * A boolean read from a query string.
 *
 * Not `z.coerce.boolean()`: that runs `Boolean(value)`, and every non-empty
 * string is truthy, so `?includeReversed=false` parsed as TRUE. The client
 * sends exactly that on every request, which meant reversed entries were
 * always included and the "show reversed" toggle did nothing.
 */
const queryBoolean = z
    .union([z.boolean(), z.enum(['true', 'false', '1', '0'])])
    .transform((value) => value === true || value === 'true' || value === '1');

export const entryQuerySchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
    type: z.enum(['INCOME', 'EXPENSE']).optional(),
    categoryId: z.string().uuid().optional(),
    contactId: z.string().uuid().optional(),
    paymentModeId: z.string().uuid().optional(),
    /** Only entries this person posted. */
    memberId: z.string().uuid().optional(),
    /** Only entries through this wallet — or `none` for book cash, no wallet. */
    accountId: z.union([z.string().uuid(), z.literal('none')]).optional(),
    /** Description, contact, category, payment mode, or an exact amount. */
    search: z.string().trim().max(100).optional().transform((value) => value || undefined),
    startDate: z.string().datetime().optional(),
    endDate: z.string().datetime().optional(),
    sortBy: z.enum(['entryDate', 'amount', 'createdAt']).default('entryDate'),
    sortOrder: z.enum(['asc', 'desc']).default('desc'),
    /** Show reversed entries alongside live ones. Default false. */
    includeReversed: queryBoolean.default(false),
}).refine(
    (q) => !q.startDate || !q.endDate || new Date(q.startDate) <= new Date(q.endDate),
    { message: 'The start date must be on or before the end date', path: ['endDate'] },
);

// Integration-only provenance is intentionally not part of the public UI
// schema. Manual create requests still pass createEntrySchema, while trusted
// internal callers may omit accountId to post against the cashbook itself.
export type CreateEntryDto = Omit<z.infer<typeof createEntrySchema>, 'accountId'> & {
    accountId?: string;
    integrationApiKeyId?: string;
    externalRef?: string;
};
export type UpdateEntryDto = z.infer<typeof updateEntrySchema>;
export type DeleteEntryDto = z.infer<typeof deleteEntrySchema>;
export type ReviewDeleteRequestDto = z.infer<typeof reviewDeleteRequestSchema>;
export type EntryQueryDto = z.infer<typeof entryQuerySchema>;

/**
 * Moving an entry to another book.
 *
 * `reason` is required, not optional. Reattributing money between books is the
 * kind of change that looks like tidying when you do it and like a discrepancy
 * when someone else finds it six months later — the audit row is only useful if
 * it says why.
 */
export const reassignEntrySchema = z.object({
    targetCashbookId: z.string().uuid('Choose the book to move this entry into'),
    reason: z.string().min(3, 'Say why this entry is moving').max(500),
    expectedVersion: z.coerce.number().int().positive(),
});

export type ReassignEntryDto = z.infer<typeof reassignEntrySchema>;

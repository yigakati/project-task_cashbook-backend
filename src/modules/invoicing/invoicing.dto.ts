import { z } from 'zod';

const decimalString = z.string().regex(
    /^\d+(\.\d{1,4})?$/,
    'Must be a valid decimal number with up to 4 decimal places'
);

// ─── Invoice Item (line item) ──────────────────────────

const invoiceItemSchema = z.object({
    productServiceId: z.string().uuid().optional(),
    // Explicit inventory item link — use this on free-text lines that represent physical goods
    // (not needed when productServiceId resolves to a product with inventoryItemId set)
    inventoryItemId: z.string().uuid().optional(),
    lineType: z.enum(['SALE', 'RENTAL']).default('SALE'),
    name: z.string().min(1, 'Item name is required').max(200),
    description: z.string().max(1000).optional(),
    quantity: decimalString,
    unitPrice: decimalString,
    taxId: z.string().uuid().optional(),
    rentalStart: z.string().datetime().optional(),
    rentalEnd: z.string().datetime().optional(),
    rentalPeriodUnit: z.enum(['DAY', 'WEEK', 'MONTH']).optional(),
    rentalPeriodCount: z.coerce.number().int().min(1).optional(),
}).refine(
    (data) => {
        const qty = parseFloat(data.quantity);
        if (qty <= 0) return false;
        return true;
    },
    { message: 'Quantity must be greater than zero', path: ['quantity'] }
).refine(
    (data) => {
        if (data.lineType !== 'RENTAL') return true;
        return Boolean(data.rentalStart && data.rentalPeriodUnit);
    },
    { message: 'Rental lines require rentalStart and rentalPeriodUnit', path: ['rentalStart'] }
);

// ─── Invoice Schemas ───────────────────────────────────

export const createInvoiceSchema = z.object({
    customerId: z.string().uuid('Invalid customer ID'),
    invoiceNumber: z.string().min(1, 'Invoice number is required').max(50).optional(), // auto-generated if not provided
    issueDate: z.string().datetime({ message: 'Issue date must be a valid ISO date' }),
    dueDate: z.string().datetime({ message: 'Due date must be a valid ISO date' }),
    currency: z.string().max(10).default('UGX'),
    discountAmount: decimalString.optional(),
    notes: z.string().max(2000).optional(),
    footer: z.string().max(2000).optional(),
    items: z.array(invoiceItemSchema).min(1, 'At least one item is required'),
    cashbookId: z.string().uuid('Cashbook ID is required'), // needed for obligation creation
});

export const updateInvoiceSchema = z.object({
    customerId: z.string().uuid().optional(),
    invoiceNumber: z.string().min(1).max(50).optional(),
    issueDate: z.string().datetime().optional(),
    dueDate: z.string().datetime().optional(),
    currency: z.string().max(10).optional(),
    discountAmount: decimalString.optional(),
    notes: z.string().max(2000).nullable().optional(),
    footer: z.string().max(2000).nullable().optional(),
    items: z.array(invoiceItemSchema).min(1).optional(),
    cashbookId: z.string().uuid().optional(),
});

export const invoiceQuerySchema = z.object({
    page: z.coerce.number().min(1).default(1),
    limit: z.coerce.number().min(1).max(100).default(20),
    status: z.enum(['DRAFT', 'SENT', 'PARTIALLY_PAID', 'PAID', 'OVERDUE', 'VOID']).optional(),
    customerId: z.string().uuid().optional(),
    startDate: z.string().datetime().optional(),
    endDate: z.string().datetime().optional(),
    sortBy: z.enum(['issueDate', 'dueDate', 'totalAmount', 'createdAt']).default('createdAt'),
    sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

/** Optional body when sending: apply a full or partial payment in the same flow. */
export const sendInvoiceSchema = z.object({
    paymentAmount: decimalString.optional(),
    /**
     * The wallet account the payment landed in.
     *
     * Required whenever paymentAmount is supplied. Without it the payment
     * entry has no account to post to, breaking the wallet audit trail that
     * requires every entry to name the pot it moved through.
     */
    accountId: z.string().uuid('Choose the wallet this payment was received into').optional(),
    paymentDescription: z.string().max(500).optional(),
    entryDate: z.string().datetime().optional(),
}).refine(
    (data) => {
        if (!data.paymentAmount) return true;
        return parseFloat(data.paymentAmount) > 0;
    },
    { message: 'paymentAmount must be greater than zero', path: ['paymentAmount'] },
).refine(
    (data) => {
        // A payment without an account would create an unlinked entry —
        // the same gap entries.dto.ts guards against at the cashbook level.
        if (!data.paymentAmount) return true;
        return Boolean(data.accountId);
    },
    { message: 'accountId is required when recording a payment', path: ['accountId'] },
);

export type SendInvoiceDto = z.infer<typeof sendInvoiceSchema>;

// ─── Invoice Settings ──────────────────────────────────

export const updateInvoiceSettingsSchema = z.object({
    /**
     * Only `null` (remove) or the current value is accepted — logos are
     * uploaded, not linked. See InvoicingService#updateSettings.
     */
    logoUrl: z.string().url().nullable().optional(),
    accentColor: z.string().max(20).optional(),
    template: z.enum(['classic', 'modern', 'contemporary']).optional(),
    defaultTerms: z.string().max(2000).nullable().optional(),
    defaultFooter: z.string().max(2000).nullable().optional(),
    defaultNotes: z.string().max(2000).nullable().optional(),
});

// ─── Types ─────────────────────────────────────────────

export type CreateInvoiceDto = z.infer<typeof createInvoiceSchema>;
export type UpdateInvoiceDto = z.infer<typeof updateInvoiceSchema>;
export type InvoiceQueryDto = z.infer<typeof invoiceQuerySchema>;
export type UpdateInvoiceSettingsDto = z.infer<typeof updateInvoiceSettingsSchema>;

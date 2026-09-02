import { z } from 'zod';

const decimalString = z.string().regex(
    /^\d+(\.\d{1,4})?$/,
    'Must be a valid decimal number with up to 4 decimal places'
);

// ─── Inventory Item Schemas ────────────────────────────

const currencyCode = z
    .string()
    .trim()
    .length(3, 'Currency must be a 3-letter code')
    .transform((c) => c.toUpperCase());

export const createInventoryItemSchema = z.object({
    name: z.string().min(1, 'Name is required').max(200),
    sku: z.string().max(100).optional(),
    unit: z.string().min(1, 'Unit is required').max(50),
    category: z.string().max(100).optional(),
    currency: currencyCode.default('UGX'),
    commercialMode: z.enum(['SELL_ONLY', 'RENT_ONLY', 'SELL_AND_RENT']).default('SELL_ONLY'),
    // Nullable, not just optional: the frontend sends an explicit null for
    // rent-only items (no selling price applies), and Zod rejects null against
    // a plain .optional() — the "validation failed with no clear error" bug.
    sellingPrice: decimalString.nullable().optional(),
    defaultSellingPrice: decimalString.nullable().optional(),
    defaultRentalRate: decimalString.optional(),
    defaultRentalPeriodUnit: z.enum(['DAY', 'WEEK', 'MONTH']).optional(),
    lowStockThreshold: z.coerce.number().int().min(0).optional(),
    // Costing is a sale concept — only items that sell (SELL_ONLY or
    // SELL_AND_RENT) need a COGS method. Rent-only items never stock-out for
    // sale, so the method is refused rather than silently defaulted.
    costMethod: z.enum(['WEIGHTED_AVERAGE', 'FIFO', 'LIFO']).optional(),
    allowNegativeStock: z.boolean().default(false),
    createProductService: z.boolean().optional().default(false),
    productServiceType: z.enum(['PRODUCT', 'SERVICE']).optional(),
    productServiceName: z.string().min(1).max(200).optional(),
    productServiceDescription: z.string().max(1000).optional(),
    productServicePrice: decimalString.optional(),
});

export const updateInventoryItemSchema = z.object({
    name: z.string().min(1).max(200).optional(),
    sku: z.string().max(100).nullable().optional(),
    unit: z.string().min(1).max(50).optional(),
    category: z.string().max(100).nullable().optional(),
    currency: currencyCode.optional(),
    commercialMode: z.enum(['SELL_ONLY', 'RENT_ONLY', 'SELL_AND_RENT']).optional(),
    defaultSellingPrice: decimalString.nullable().optional(),
    defaultRentalRate: decimalString.nullable().optional(),
    defaultRentalPeriodUnit: z.enum(['DAY', 'WEEK', 'MONTH']).nullable().optional(),
    lowStockThreshold: z.coerce.number().int().min(0).nullable().optional(),
    allowNegativeStock: z.boolean().optional(),
    isActive: z.boolean().optional(),
});

export const inventoryItemQuerySchema = z.object({
    page: z.coerce.number().min(1).default(1),
    limit: z.coerce.number().min(1).max(100).default(20),
    category: z.string().optional(),
    isActive: z.enum(['true', 'false']).optional(),
    search: z.string().optional(),
    currency: currencyCode.optional(),
    commercialMode: z.enum(['SELL_ONLY', 'RENT_ONLY', 'SELL_AND_RENT']).optional(),
    /** When true, only RENT_ONLY and SELL_AND_RENT items. */
    rentable: z.enum(['true', 'false']).optional(),
});

/**
 * A rental recorded and paid in one step — no invoice. The entry posts into
 * `cashbookId` immediately; `accountId` optionally names the wallet.
 */
export const createDirectRentalSchema = z.object({
    customerId: z.string().uuid('A customer is required'),
    cashbookId: z.string().uuid('A cashbook is required'),
    itemId: z.string().uuid('An inventory item is required'),
    quantity: z.coerce.number().int().min(1, 'Quantity must be at least 1'),
    unitRate: decimalString,
    periodUnit: z.enum(['DAY', 'WEEK', 'MONTH']),
    periodCount: z.coerce.number().int().min(1).default(1),
    startDate: z.string().refine((v) => !isNaN(Date.parse(v)), { message: 'Invalid start date' }),
    endDate: z.string().refine((v) => !isNaN(Date.parse(v)), { message: 'Invalid end date' }).optional(),
    depositAmount: decimalString.optional(),
    notes: z.string().max(1000).optional(),
    accountId: z.string().uuid().optional(),
});

export const returnRentalSchema = z.object({
    lineReturns: z
        .array(
            z.object({
                lineId: z.string().uuid(),
                quantity: z.coerce.number().int().min(1),
            }),
        )
        .optional(),
    notes: z.string().max(1000).optional(),
});

export const rentalQuerySchema = z.object({
    page: z.coerce.number().min(1).default(1),
    limit: z.coerce.number().min(1).max(100).default(20),
    status: z.enum(['DRAFT', 'ACTIVE', 'RETURNED', 'OVERDUE', 'CANCELLED']).optional(),
    itemId: z.string().uuid().optional(),
});

// ─── Inventory Transaction Schemas ─────────────────────

const STOCK_IN_TYPES = ['PURCHASE', 'TRANSFER_IN', 'RETURN_IN', 'ADJUSTMENT'] as const;
const STOCK_OUT_TYPES = ['SALE', 'TRANSFER_OUT', 'RETURN_OUT', 'ADJUSTMENT'] as const;
const ALL_TRANSACTION_TYPES = [
    'PURCHASE', 'SALE', 'ADJUSTMENT', 'TRANSFER_IN', 'TRANSFER_OUT',
    'RETURN_IN', 'RETURN_OUT', 'RENTAL_OUT', 'RENTAL_IN', 'RENTAL_LOSS',
] as const;

// Stock direction helpers (mirrors the service constants)
const STOCK_IN_TRANSACTION_TYPES = ['PURCHASE', 'TRANSFER_IN', 'RETURN_IN'] as const;
const STOCK_OUT_TRANSACTION_TYPES = ['SALE', 'TRANSFER_OUT', 'RETURN_OUT'] as const;

export const createInventoryTransactionSchema = z.object({
    itemId: z.string().uuid('Invalid item ID'),
    transactionType: z.enum(ALL_TRANSACTION_TYPES),
    quantity: z.coerce.number().int().min(1, 'Quantity must be at least 1'),
    // unitCost is required only for stock-IN types (PURCHASE, TRANSFER_IN, RETURN_IN, ADJUSTMENT).
    // For stock-OUT types (SALE, TRANSFER_OUT, RETURN_OUT) COGS is always calculated by the cost
    // method (WAC / FIFO / LIFO) and unitCost is ignored — omit it to avoid confusion.
    unitCost: decimalString.optional(),
    // sellingPrice is the revenue per unit. Relevant only for stock-OUT types.
    // Stored separately from COGS so gross-margin can be computed per transaction.
    sellingPrice: decimalString.optional(),
    referenceType: z.enum(['ENTRY', 'ACCOUNT_TRANSACTION', 'OBLIGATION', 'MANUAL']).optional(),
    referenceId: z.string().uuid().optional(),
    notes: z.string().max(1000).optional(),
})
.refine(
    (data) => {
        // Stock-in types require an acquisition cost so the lot / WAC can be recorded.
        const isStockIn = (STOCK_IN_TRANSACTION_TYPES as readonly string[]).includes(data.transactionType);
        if (isStockIn && !data.unitCost) return false;
        return true;
    },
    {
        message: 'unitCost is required for stock-in transactions (PURCHASE, TRANSFER_IN, RETURN_IN)',
        path: ['unitCost'],
    }
)
.refine(
    (data) => {
        // ADJUSTMENTs act as stock-in but also need a cost for the lot value.
        if (data.transactionType === 'ADJUSTMENT' && !data.unitCost) return false;
        return true;
    },
    {
        message: 'unitCost is required for ADJUSTMENT transactions',
        path: ['unitCost'],
    }
)
.refine(
    (data) => {
        // Notes are mandatory for ADJUSTMENT so there is always an explanation.
        if (data.transactionType === 'ADJUSTMENT' && (!data.notes || data.notes.trim() === '')) return false;
        return true;
    },
    { message: 'Notes are required for adjustment transactions', path: ['notes'] }
);

export const inventoryTransactionQuerySchema = z.object({
    page: z.coerce.number().min(1).default(1),
    limit: z.coerce.number().min(1).max(100).default(20),
    itemId: z.string().uuid().optional(),
    transactionType: z.enum(ALL_TRANSACTION_TYPES).optional(),
    startDate: z.string().datetime().optional(),
    endDate: z.string().datetime().optional(),
    sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

// ─── Inventory Line Item (for Entry/AccTransaction attachments) ──

export const inventoryLineItemSchema = z.object({
    itemId: z.string().uuid('Invalid inventory item ID'),
    quantity: z.coerce.number().int().min(1, 'Quantity must be at least 1'),
    unitCost: decimalString.optional(),      // Acquisition cost (EXPENSE/purchase contexts)
    sellingPrice: decimalString.optional(),  // Selling price per unit (INCOME/sale contexts, for gross-margin reporting)
});

// ─── Report query schemas ──────────────────────────────

export const cogsReportQuerySchema = z.object({
    startDate: z.string().datetime().optional(),
    endDate: z.string().datetime().optional(),
});

export const analyticsQuerySchema = z
    .object({
        startDate: z.string().datetime().optional(),
        endDate: z.string().datetime().optional(),
        /** Preferred: DAILY | WEEKLY | MONTHLY */
        interval: z.enum(['DAILY', 'WEEKLY', 'MONTHLY']).optional(),
        /** Alias used by some clients (daily/weekly/monthly) */
        period: z.enum(['daily', 'weekly', 'monthly', 'DAILY', 'WEEKLY', 'MONTHLY']).optional(),
    })
    .transform((q) => {
        const raw = (q.interval || q.period || 'DAILY').toString().toUpperCase();
        const interval = (['DAILY', 'WEEKLY', 'MONTHLY'].includes(raw)
            ? raw
            : 'DAILY') as 'DAILY' | 'WEEKLY' | 'MONTHLY';
        return {
            startDate: q.startDate,
            endDate: q.endDate,
            interval,
        };
    });

// ─── Params schemas ────────────────────────────────────

export const itemIdParamSchema = z.object({
    itemId: z.string().uuid('Invalid inventory item ID'),
}).passthrough();

// ─── Types ─────────────────────────────────────────────

export type CreateInventoryItemDto = z.infer<typeof createInventoryItemSchema>;
export type UpdateInventoryItemDto = z.infer<typeof updateInventoryItemSchema>;
export type InventoryItemQueryDto = z.infer<typeof inventoryItemQuerySchema>;
export type CreateInventoryTransactionDto = z.infer<typeof createInventoryTransactionSchema>;
export type InventoryTransactionQueryDto = z.infer<typeof inventoryTransactionQuerySchema>;
export type InventoryLineItemDto = z.infer<typeof inventoryLineItemSchema>;
export type CogsReportQueryDto = z.infer<typeof cogsReportQuerySchema>;
export type AnalyticsQueryDto = z.infer<typeof analyticsQuerySchema>;
export type ReturnRentalDto = z.infer<typeof returnRentalSchema>;
export type CreateDirectRentalDto = z.infer<typeof createDirectRentalSchema>;
export type RentalQueryDto = z.infer<typeof rentalQuerySchema>;

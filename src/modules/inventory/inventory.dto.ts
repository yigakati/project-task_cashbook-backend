import { z } from 'zod';

const decimalString = z.string().regex(
    /^\d+(\.\d{1,4})?$/,
    'Must be a valid decimal number with up to 4 decimal places'
);

// ─── Inventory Item Schemas ────────────────────────────

export const createInventoryItemSchema = z.object({
    name: z.string().min(1, 'Name is required').max(200),
    sku: z.string().max(100).optional(),
    unit: z.string().min(1, 'Unit is required').max(50),
    category: z.string().max(100).optional(),
    lowStockThreshold: z.coerce.number().int().min(0).optional(),
    costMethod: z.enum(['WEIGHTED_AVERAGE', 'FIFO', 'LIFO']).default('WEIGHTED_AVERAGE'),
    allowNegativeStock: z.boolean().default(false),
});

export const updateInventoryItemSchema = z.object({
    name: z.string().min(1).max(200).optional(),
    sku: z.string().max(100).nullable().optional(),
    unit: z.string().min(1).max(50).optional(),
    category: z.string().max(100).nullable().optional(),
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
});

// ─── Inventory Transaction Schemas ─────────────────────

const STOCK_IN_TYPES = ['PURCHASE', 'TRANSFER_IN', 'RETURN_IN', 'ADJUSTMENT'] as const;
const STOCK_OUT_TYPES = ['SALE', 'TRANSFER_OUT', 'RETURN_OUT', 'ADJUSTMENT'] as const;
const ALL_TRANSACTION_TYPES = ['PURCHASE', 'SALE', 'ADJUSTMENT', 'TRANSFER_IN', 'TRANSFER_OUT', 'RETURN_IN', 'RETURN_OUT'] as const;

export const createInventoryTransactionSchema = z.object({
    itemId: z.string().uuid('Invalid item ID'),
    transactionType: z.enum(ALL_TRANSACTION_TYPES),
    quantity: z.coerce.number().int().min(1, 'Quantity must be at least 1'),
    unitCost: decimalString,
    referenceType: z.enum(['ENTRY', 'ACCOUNT_TRANSACTION', 'OBLIGATION', 'MANUAL']).optional(),
    referenceId: z.string().uuid().optional(),
    notes: z.string().max(1000).optional(),
}).refine(
    (data) => {
        // Require notes for ADJUSTMENT type
        if (data.transactionType === 'ADJUSTMENT' && (!data.notes || data.notes.trim() === '')) {
            return false;
        }
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
    unitCost: decimalString.optional(), // If omitted, derived from entry amount / total quantity
});

// ─── Report query schemas ──────────────────────────────

export const cogsReportQuerySchema = z.object({
    startDate: z.string().datetime().optional(),
    endDate: z.string().datetime().optional(),
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

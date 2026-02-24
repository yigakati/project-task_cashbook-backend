import { z } from 'zod';

const decimalString = z.string().regex(
    /^\d+(\.\d{1,4})?$/,
    'Amount must be a valid decimal number with up to 4 decimal places'
);

export const createEntrySchema = z.object({
    type: z.enum(['INCOME', 'EXPENSE']),
    amount: decimalString,
    description: z.string().min(1, 'Description is required').max(1000),
    categoryId: z.string().uuid().optional(),
    contactId: z.string().uuid().optional(),
    paymentModeId: z.string().uuid().optional(),
    accountId: z.string().uuid().optional(),
    entryDate: z.string().datetime({ message: 'Entry date must be a valid ISO date' }),
});

export const updateEntrySchema = z.object({
    type: z.enum(['INCOME', 'EXPENSE']).optional(),
    amount: decimalString.optional(),
    description: z.string().min(1).max(1000).optional(),
    categoryId: z.string().uuid().nullable().optional(),
    contactId: z.string().uuid().nullable().optional(),
    paymentModeId: z.string().uuid().nullable().optional(),
    accountId: z.string().uuid().nullable().optional(),
    entryDate: z.string().datetime().optional(),
});

export const deleteEntrySchema = z.object({
    reason: z.string().min(1, 'Reason is required for deletion').max(500),
});

export const reviewDeleteRequestSchema = z.object({
    status: z.enum(['APPROVED', 'REJECTED']),
    reviewNote: z.string().max(500).optional(),
});

export const entryQuerySchema = z.object({
    page: z.coerce.number().min(1).default(1),
    limit: z.coerce.number().min(1).max(100).default(20),
    type: z.enum(['INCOME', 'EXPENSE']).optional(),
    categoryId: z.string().uuid().optional(),
    contactId: z.string().uuid().optional(),
    paymentModeId: z.string().uuid().optional(),
    startDate: z.string().datetime().optional(),
    endDate: z.string().datetime().optional(),
    sortBy: z.enum(['entryDate', 'amount', 'createdAt']).default('entryDate'),
    sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

export type CreateEntryDto = z.infer<typeof createEntrySchema>;
export type UpdateEntryDto = z.infer<typeof updateEntrySchema>;
export type DeleteEntryDto = z.infer<typeof deleteEntrySchema>;
export type ReviewDeleteRequestDto = z.infer<typeof reviewDeleteRequestSchema>;
export type EntryQueryDto = z.infer<typeof entryQuerySchema>;

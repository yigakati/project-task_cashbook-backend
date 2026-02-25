import { z } from 'zod';
import { EntryType } from '@prisma/client';

export const createAccountTransactionSchema = z.object({
    type: z.nativeEnum(EntryType, {
        message: 'Invalid transaction type'
    }),
    amount: z.union([z.string(), z.number()]).refine((val) => {
        const num = typeof val === 'string' ? parseFloat(val) : val;
        return !isNaN(num) && num > 0;
    }, 'Amount must be a positive number'),
    description: z.string().min(1, 'Description is required').max(255, 'Description too long'),
    accountCategoryId: z.string().uuid('Invalid category ID').optional().nullable(),
});

export const updateAccountTransactionSchema = createAccountTransactionSchema.partial();

export type CreateAccountTransactionBody = z.infer<typeof createAccountTransactionSchema>;
export type UpdateAccountTransactionBody = z.infer<typeof updateAccountTransactionSchema>;

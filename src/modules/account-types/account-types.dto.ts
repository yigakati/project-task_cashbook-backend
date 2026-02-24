import { z } from 'zod';
import { AccountClassification } from '@prisma/client';

export const createAccountTypeSchema = z.object({
    name: z.string().min(1, 'Name is required').max(100, 'Name must be at most 100 characters'),
    classification: z.nativeEnum(AccountClassification, {
        message: 'Invalid account classification'
    })
});

export const updateAccountTypeSchema = z.object({
    name: z.string().min(1, 'Name is required').max(100, 'Name must be at most 100 characters').optional()
});

export type CreateAccountTypeBody = z.infer<typeof createAccountTypeSchema>;
export type UpdateAccountTypeBody = z.infer<typeof updateAccountTypeSchema>;

import { z } from 'zod';

export const createAccountCategorySchema = z.object({
    name: z.string().min(1, 'Name is required').max(100, 'Name must be at most 100 characters')
});

export const updateAccountCategorySchema = z.object({
    name: z.string().min(1, 'Name is required').max(100, 'Name must be at most 100 characters').optional()
});

export type CreateAccountCategoryBody = z.infer<typeof createAccountCategorySchema>;
export type UpdateAccountCategoryBody = z.infer<typeof updateAccountCategorySchema>;

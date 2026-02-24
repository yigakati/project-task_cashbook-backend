import { z } from 'zod';

export const createAccountSchema = z.object({
    accountTypeId: z.string().uuid('Invalid account type ID'),
    name: z.string().min(1, 'Name is required').max(100, 'Name must be at most 100 characters'),
    currency: z.string().length(3, 'Currency must be a 3-letter code'),
    icon: z.string().optional(),
    excludeFromTotal: z.boolean().optional(),
    allowNegative: z.boolean().optional(),
    note: z.string().max(500).optional(),
});

export const updateAccountSchema = z.object({
    name: z.string().min(1).max(100).optional(),
    icon: z.string().optional(),
    excludeFromTotal: z.boolean().optional(),
    allowNegative: z.boolean().optional(),
    note: z.string().max(500).optional(),
});

export const archiveAccountSchema = z.object({
    archive: z.boolean(),
});

export type CreateAccountBody = z.infer<typeof createAccountSchema>;
export type UpdateAccountBody = z.infer<typeof updateAccountSchema>;
export type ArchiveAccountBody = z.infer<typeof archiveAccountSchema>;

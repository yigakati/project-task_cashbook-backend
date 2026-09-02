import { z } from 'zod';
import { SUPPORTED_BASE_CURRENCY_CODES } from '../../core/finance';

const eastAfricanCurrency = z
    .string()
    .trim()
    .transform((c) => c.toUpperCase())
    .refine((c) => (SUPPORTED_BASE_CURRENCY_CODES as readonly string[]).includes(c), {
        message: `Currency must be one of: ${SUPPORTED_BASE_CURRENCY_CODES.join(', ')}`,
    });

export const createWorkspaceSchema = z.object({
    name: z.string().min(1, 'Workspace name is required').max(200),
    type: z.literal('BUSINESS'),
    defaultCurrency: eastAfricanCurrency.default('UGX'),
});

export const updateWorkspaceSchema = z.object({
    name: z.string().min(1).max(200).optional(),
    defaultCurrency: eastAfricanCurrency.optional(),
});

export type CreateWorkspaceDto = z.infer<typeof createWorkspaceSchema>;
export type UpdateWorkspaceDto = z.infer<typeof updateWorkspaceSchema>;

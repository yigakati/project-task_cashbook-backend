import { z } from 'zod';
import { ObligationType, ObligationStatus } from '@prisma/client';

const decimalString = z.string().regex(
    /^\d+(\.\d{1,4})?$/,
    'Amount must be a valid decimal number with up to 4 decimal places'
);

export const createObligationSchema = z.object({
    type: z.nativeEnum(ObligationType).refine((val) => val !== undefined, { message: 'Invalid obligation type' }),
    title: z.string().min(1, 'Title is required').max(200, 'Title is too long'),
    description: z.string().max(1000, 'Description is too long').optional(),
    totalAmount: decimalString,
    dueDate: z.string()
        .refine((val) => !isNaN(Date.parse(val)), { message: 'Invalid date format' })
        .optional(),
});

export const updateObligationSchema = z.object({
    title: z.string().min(1, 'Title is required').max(200, 'Title is too long').optional(),
    description: z.string().max(1000, 'Description is too long').optional().nullable(),
    dueDate: z.string()
        .refine((val) => !isNaN(Date.parse(val)), { message: 'Invalid date format' })
        .optional()
        .nullable(),
});

export const obligationQuerySchema = z.object({
    page: z.coerce.number().min(1).default(1),
    limit: z.coerce.number().min(1).max(100).default(20),
    type: z.nativeEnum(ObligationType).optional(),
    status: z.nativeEnum(ObligationStatus).optional(),
    isOverdue: z.enum(['true', 'false']).transform(val => val === 'true').optional(),
    sortBy: z.enum(['createdAt', 'dueDate', 'totalAmount', 'outstandingAmount']).default('createdAt'),
    sortOrder: z.enum(['asc', 'desc']).default('desc'),
    includeArchived: z.enum(['true', 'false']).transform(val => val === 'true').optional(),
});

export type CreateObligationDto = z.infer<typeof createObligationSchema>;
export type UpdateObligationDto = z.infer<typeof updateObligationSchema>;
export type ObligationQueryDto = z.infer<typeof obligationQuerySchema>;

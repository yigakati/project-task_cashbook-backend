import { z } from 'zod';
import { ObligationType, ObligationStatus } from '@prisma/client';

export const createObligationSchema = z.object({
    type: z.nativeEnum(ObligationType).refine((val) => val !== undefined, { message: 'Invalid obligation type' }),
    title: z.string().min(1, 'Title is required').max(200, 'Title is too long'),
    description: z.string().max(1000, 'Description is too long').optional(),
    totalAmount: z.number().positive('Total amount must be greater than zero'),
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
    page: z.string().regex(/^\d+$/).transform(Number).optional(),
    limit: z.string().regex(/^\d+$/).transform(Number).optional(),
    type: z.nativeEnum(ObligationType).optional(),
    status: z.nativeEnum(ObligationStatus).optional(),
    isOverdue: z.enum(['true', 'false']).transform(val => val === 'true').optional(),
    sortBy: z.enum(['createdAt', 'dueDate', 'totalAmount', 'outstandingAmount']).optional(),
    sortOrder: z.enum(['asc', 'desc']).optional(),
    includeArchived: z.enum(['true', 'false']).transform(val => val === 'true').optional(),
});

export type CreateObligationDto = z.infer<typeof createObligationSchema>;
export type UpdateObligationDto = z.infer<typeof updateObligationSchema>;
export type ObligationQueryDto = z.infer<typeof obligationQuerySchema>;

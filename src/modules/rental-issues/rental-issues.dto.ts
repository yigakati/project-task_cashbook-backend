import { z } from 'zod';
import { pageSchema } from '../housing/housing.dto';
export const subjectSchema = z
    .object({ tenancyId: z.string().uuid().optional(), rentalId: z.string().uuid().optional() })
    .refine((d) => Boolean(d.tenancyId) !== Boolean(d.rentalId), 'Choose one tenancy or rental');
export const issueQuerySchema = pageSchema
    .extend({ tenancyId: z.string().uuid().optional(), rentalId: z.string().uuid().optional() })
    .refine((d) => Boolean(d.tenancyId) !== Boolean(d.rentalId), 'Choose one tenancy or rental');
export const issueSchema = z
    .object({
        tenancyId: z.string().uuid().optional(),
        rentalId: z.string().uuid().optional(),
        title: z.string().trim().min(3).max(160),
        description: z.string().trim().min(3).max(4000),
        kind: z.enum(['MAINTENANCE', 'PAYMENT_DISPUTE', 'CONCERN']),
        priority: z.enum(['LOW', 'NORMAL', 'URGENT']).default('NORMAL'),
    })
    .refine((d) => Boolean(d.tenancyId) !== Boolean(d.rentalId), 'Choose one tenancy or rental');
export const messageSchema = z.object({
    body: z.string().trim().min(1).max(4000),
    expectedVersion: z.number().int().positive(),
    status: z.enum(['OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED']).optional(),
});

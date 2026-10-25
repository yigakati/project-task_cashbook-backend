import { z } from 'zod';
import { createEntrySchema } from '../entries/entries.dto';

export const sharedEntryQuerySchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
    status: z.enum(['PENDING', 'ACCEPTED', 'DECLINED', 'CANCELLED']).optional(),
});

export const acceptSharedEntrySchema = createEntrySchema.pick({
    categoryId: true, paymentModeId: true, obligationId: true,
    chargeAmount: true, entryDate: true,
}).partial().extend({
    cashbookId: z.string().uuid(),
    accountId: z.string().uuid('Choose the account this payment belongs to'),
    expectedVersion: z.number().int().positive(),
}).strict();

export const declineSharedEntrySchema = z.object({ reason: z.string().trim().max(500).optional() }).strict();
export type AcceptSharedEntryDto = z.infer<typeof acceptSharedEntrySchema>;
export type SharedEntryQueryDto = z.infer<typeof sharedEntryQuerySchema>;

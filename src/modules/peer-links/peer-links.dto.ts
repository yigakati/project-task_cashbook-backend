import { z } from 'zod';
import { PeerLinkDirection } from '@prisma/client';

const decimalString = z.string().regex(
    /^\d+(\.\d{1,4})?$/,
    'Amount must be a valid decimal number with up to 4 decimal places'
);

/**
 * Proposing a peer link — a loan agreement with another platform user.
 *
 * Amounts follow the same two-shape convention as obligations: either a plain
 * total, or a principal with interest on top (rate XOR amount). Interest is
 * flat and resolved once at proposal time, exactly like obligations.
 *
 * `direction` is from the initiator's point of view: LENDING means "I am
 * giving them money and expect it back" (my obligation is a RECEIVABLE);
 * BORROWING means "I owe them and will confirm their record" (my obligation is
 * a PAYABLE).
 */
export const createPeerLinkSchema = z.object({
    direction: z.nativeEnum(PeerLinkDirection),
    counterpartyEmail: z.string().email('A valid counterparty email is required'),
    title: z.string().min(1, 'Title is required').max(200, 'Title is too long'),
    description: z.string().max(1000, 'Description is too long').optional(),
    totalAmount: decimalString.optional(),
    principalAmount: decimalString.optional(),
    /** Flat percentage of the principal, charged once. Not per-annum. */
    interestRate: z.string()
        .regex(/^\d+(\.\d{1,4})?$/, 'Interest rate must be a positive number')
        .refine((v) => Number(v) <= 1000, 'Interest rate looks too large')
        .optional(),
    interestAmount: decimalString.optional(),
    dueDate: z.string()
        .refine((val) => !isNaN(Date.parse(val)), { message: 'Invalid date format' })
        .optional(),
}).refine(
    (v) => Boolean(v.totalAmount) || Boolean(v.principalAmount),
    { message: 'Give an amount, or a principal to charge interest on', path: ['totalAmount'] },
).refine(
    (v) => !(v.interestRate && v.interestAmount),
    { message: 'Set the interest as a rate or as an amount, not both', path: ['interestRate'] },
).refine(
    (v) => !((v.interestRate || v.interestAmount) && !v.principalAmount),
    {
        message: 'Interest needs a principal to be charged on',
        path: ['principalAmount'],
    },
);

export const respondPeerLinkSchema = z.object({
    /** The counterparty's book the mirrored obligation is recorded in. */
    cashbookId: z.string().uuid('Invalid cashbook ID'),
});

export const declinePeerLinkSchema = z.object({
    reason: z.string().max(500, 'Reason is too long').optional(),
});

export const cancelPeerLinkSchema = z.object({
    reason: z.string().max(500, 'Reason is too long').optional(),
});

export const settlementDecisionSchema = z.object({
    decision: z.enum(['CONFIRM', 'REJECT']),
    /** For CONFIRM: an entry the counterparty already recorded, if any. */
    matchedEntryId: z.string().uuid('Invalid entry ID').optional(),
    reason: z.string().max(500, 'Reason is too long').optional(),
}).refine(
    (v) => v.decision === 'CONFIRM' || !v.matchedEntryId,
    {
        message: 'A matched entry can only be provided when confirming',
        path: ['matchedEntryId'],
    },
);

export const peerLinkQuerySchema = z.object({
    page: z.coerce.number().min(1).default(1),
    limit: z.coerce.number().min(1).max(100).default(20),
    direction: z.enum(['incoming', 'outgoing']).optional(),
    status: z.enum(['PENDING', 'ACCEPTED', 'DECLINED', 'CANCELLED']).optional(),
});

export const userLookupQuerySchema = z.object({
    email: z.string().email('A valid email is required'),
});

export const workspaceObligationsQuerySchema = z.object({
    page: z.coerce.number().min(1).default(1),
    limit: z.coerce.number().min(1).max(100).default(20),
    /** ACTIVE = OPEN + PARTIAL (the "active obligations" tab). */
    status: z.enum(['ACTIVE', 'OPEN', 'PARTIAL', 'PAID', 'CANCELLED']).optional(),
    type: z.enum(['RECEIVABLE', 'PAYABLE']).optional(),
    cashbookId: z.string().uuid('Invalid cashbook ID').optional(),
    search: z.string().max(200).optional(),
});

export type CreatePeerLinkDto = z.infer<typeof createPeerLinkSchema>;
export type RespondPeerLinkDto = z.infer<typeof respondPeerLinkSchema>;
export type DeclinePeerLinkDto = z.infer<typeof declinePeerLinkSchema>;
export type CancelPeerLinkDto = z.infer<typeof cancelPeerLinkSchema>;
export type SettlementDecisionDto = z.infer<typeof settlementDecisionSchema>;
export type PeerLinkQueryDto = z.infer<typeof peerLinkQuerySchema>;
export type UserLookupQueryDto = z.infer<typeof userLookupQuerySchema>;

import { z } from 'zod';

const decimalString = z.string().regex(
    /^\d+(\.\d{1,4})?$/,
    'Must be a valid decimal number with up to 4 decimal places'
);

// ─── Stock Requests (cross-workspace) ──────────────────

/**
 * Requesting stock from a vendor. The request is made from the item's page:
 * it names the ITEM being stocked (which fixes the origin workspace — the
 * goods land back into that exact item on receipt) and the vendor, by a
 * contact or an email. Nothing moves yet.
 */
export const createStockRequestSchema = z.object({
    /** The requester's item the incoming stock will be added to. */
    itemId: z.string().uuid('The item this stock request is for'),
    quantity: z.coerce.number().int().min(1, 'Quantity must be at least 1'),
    /** Preferred: a contact in the requester's workspace. */
    contactId: z.string().uuid().optional(),
    vendorEmail: z.string().email('A valid vendor email is required').optional(),
    notes: z.string().max(1000).optional(),
}).refine(
    (v) => Boolean(v.contactId || v.vendorEmail),
    { message: 'Choose a contact or provide a vendor email', path: ['contactId'] },
);

/** The vendor's send: which of their workspaces, and which item, fulfils it. */
export const respondStockRequestSchema = z.object({
    senderWorkspaceId: z.string().uuid('Choose the workspace sending the stock'),
    senderItemId: z.string().uuid('Choose the item fulfilling the request'),
});

/** The one-time money legs — the same shape both sides use. */
export const recordTransferEntrySchema = z.object({
    cashbookId: z.string().uuid('Choose the book'),
    accountId: z.string().uuid().optional(),
    entryDate: z.string().refine((v) => !isNaN(Date.parse(v)), { message: 'Invalid date' }).optional(),
});

export const stockTransferQuerySchema = z.object({
    page: z.coerce.number().min(1).default(1),
    limit: z.coerce.number().min(1).max(100).default(20),
    /** 'sent' = requests I'm the vendor on; 'received' = requests I made. */
    direction: z.enum(['sent', 'received']).optional(),
    status: z.enum(['PENDING', 'SENT', 'COMPLETED', 'DECLINED', 'CANCELLED']).optional(),
    /**
     * Scope to one workspace's view: requests that workspace made, and
     * requests it sent. Unanswered requests addressed to the current user
     * surface only in their personal workspace (the vendor's inbox) — the
     * vendor has tied them to no workspace of theirs yet.
     */
    workspaceId: z.string().uuid().optional(),
});

// ─── Rental Agreements ─────────────────────────────────

/**
 * Offering a loan: the item (route param), the terms, and the borrower by
 * email. Proposing reserves the units until the borrower decides.
 */
export const createRentalAgreementSchema = z.object({
    quantity: z.coerce.number().int().min(1, 'Quantity must be at least 1'),
    /**
     * The customer being lent the item — a contact in the lender's workspace.
     * Preferred over the raw email: the contact's linked account is the
     * reliable identity (emails drift), and the rental form already works in
     * terms of customers.
     */
    customerId: z.string().uuid().optional(),
    borrowerEmail: z.string().email('A valid borrower email is required').optional(),
    periodUnit: z.enum(['DAY', 'WEEK', 'MONTH']),
    periodCount: z.coerce.number().int().min(1).default(1),
    startDate: z.string().refine((v) => !isNaN(Date.parse(v)), { message: 'Invalid start date' }),
    endDate: z.string().refine((v) => !isNaN(Date.parse(v)), { message: 'Invalid end date' }).optional(),
    /** Optional charge per period — a loan may be free. */
    rate: decimalString.optional(),
    notes: z.string().max(1000).optional(),
}).refine(
    (v) => Boolean(v.customerId || v.borrowerEmail),
    { message: 'A customer (or a borrower email) is required', path: ['customerId'] },
);

/** The borrower's acceptance: their workspace, recorded as provenance. */
export const respondRentalAgreementSchema = z.object({
    borrowerWorkspaceId: z.string().uuid().optional(),
});

/** The borrower recording the rental cost as an expense in their accepted
 *  workspace — the book must belong to that workspace (enforced in service). */
export const recordAgreementExpenseSchema = z.object({
    cashbookId: z.string().uuid('Choose the book the expense is recorded in'),
    accountId: z.string().uuid().optional(),
    entryDate: z.string().refine((v) => !isNaN(Date.parse(v)), { message: 'Invalid date' }).optional(),
});

export const rentalAgreementQuerySchema = z.object({
    page: z.coerce.number().min(1).default(1),
    limit: z.coerce.number().min(1).max(100).default(20),
    direction: z.enum(['lent', 'borrowed']).optional(),
    status: z.enum(['PENDING', 'ACCEPTED', 'DECLINED', 'CANCELLED']).optional(),
});

const reasonSchema = z.object({
    reason: z.string().max(500).optional(),
});

export { reasonSchema };

// ─── Types ─────────────────────────────────────────────

export type CreateStockRequestDto = z.infer<typeof createStockRequestSchema>;
export type RespondStockRequestDto = z.infer<typeof respondStockRequestSchema>;
export type RecordTransferEntryDto = z.infer<typeof recordTransferEntrySchema>;
export type StockTransferQueryDto = z.infer<typeof stockTransferQuerySchema>;
// periodCount stays optional for direct service callers; the HTTP layer's
// Zod validation defaults it to 1, and the service guards `?? 1` as well.
export type CreateRentalAgreementDto = Omit<z.infer<typeof createRentalAgreementSchema>, 'periodCount'> & {
    periodCount?: number;
};
export type RespondRentalAgreementDto = z.infer<typeof respondRentalAgreementSchema>;
export type RecordAgreementExpenseDto = z.infer<typeof recordAgreementExpenseSchema>;
export type RentalAgreementQueryDto = z.infer<typeof rentalAgreementQuerySchema>;

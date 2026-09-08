import { z } from 'zod';

/**
 * A connection is requested against a person's email — the same exact-match
 * lookup peer links already use. Deliberately not a fuzzy search over the user
 * table: a partial-match endpoint over everyone's email is a user-enumeration
 * oracle, and knowing someone's address already is the closest thing to
 * consent we have before they have agreed to anything.
 */
export const lookupRecipientSchema = z.object({
    email: z.string().email('A valid email is required'),
});

export const createContactLinkRequestSchema = z.object({
    email: z.string().email('A valid email is required'),
    /**
     * How the requester will file them. The recipient's own contact defaults to
     * the inverse — a CUSTOMER here is a VENDOR there — because the two are
     * mirror roles, not the same label applied twice.
     */
    requestedType: z.enum(['CUSTOMER', 'VENDOR', 'PERSONAL']).default('CUSTOMER'),
    /**
     * An existing hand-typed contact to attach this connection to. Optional:
     * when omitted the server still looks for one by email, so the common case
     * needs no client involvement at all.
     */
    contactId: z.string().uuid().optional(),
    message: z.string().max(500).optional(),
});

export const acceptContactLinkRequestSchema = z.object({
    /** Which of the recipient's workspaces answers — personal or a business. */
    workspaceId: z.string().uuid('Choose which workspace to share'),
    /** Overrides the inverted default if they classify the relationship differently. */
    type: z.enum(['CUSTOMER', 'VENDOR', 'PERSONAL']).optional(),
});

export const declineContactLinkRequestSchema = z.object({
    reason: z.string().max(500).optional(),
});

export const contactLinkRequestQuerySchema = z.object({
    status: z.enum(['PENDING', 'ACCEPTED', 'DECLINED', 'CANCELLED', 'EXPIRED']).optional(),
});

export type LookupRecipientDto = z.infer<typeof lookupRecipientSchema>;
export type CreateContactLinkRequestDto = z.infer<typeof createContactLinkRequestSchema>;
export type AcceptContactLinkRequestDto = z.infer<typeof acceptContactLinkRequestSchema>;
export type DeclineContactLinkRequestDto = z.infer<typeof declineContactLinkRequestSchema>;
export type ContactLinkRequestQueryDto = z.infer<typeof contactLinkRequestQuerySchema>;

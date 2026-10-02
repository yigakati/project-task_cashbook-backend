import { z } from 'zod';

const reason = z.string().trim().max(1000).optional();

/** In the app: re-confirm with the password, or for an account without one, the email. */
export const requestDeletionSchema = z.object({
    password: z.string().max(200).optional(),
    confirmEmail: z.string().trim().max(320).optional(),
    reason,
});

/** On the website, signed out. */
export const webDeletionRequestSchema = z.object({
    email: z.string().trim().email('Enter a valid email address').max(320),
    reason,
    /**
     * Honeypot: hidden from people, filled in by naive bots. A submission that
     * fills it is acknowledged like any other and then dropped.
     */
    website: z.string().max(200).optional(),
});

export const confirmDeletionSchema = z.object({
    token: z.string().min(20).max(200),
});

export const adminScheduleDeletionSchema = z.object({
    reason,
    /** How support verified the person — kept with the request. */
    note: z.string().trim().max(1000).optional(),
});

export const adminCancelDeletionSchema = z.object({
    note: z.string().trim().max(1000).optional(),
});

export const deletionListQuerySchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(25),
    status: z.enum([
        'PENDING_VERIFICATION', 'SCHEDULED', 'PROCESSING', 'BLOCKED',
        'CANCELLED', 'EXPIRED', 'COMPLETED', 'FAILED',
    ]).optional(),
    search: z.string().trim().max(200).optional(),
});

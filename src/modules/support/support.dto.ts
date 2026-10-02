import { z } from 'zod';

export const CONTACT_CATEGORIES = [
    'general', 'billing', 'api', 'account', 'privacy', 'security', 'feedback',
] as const;

export const contactMessageSchema = z.object({
    name: z.string().trim().min(1, 'Your name is required').max(100),
    email: z.string().trim().email('A valid email address is required').max(320),
    category: z.enum(CONTACT_CATEGORIES).default('general'),
    subject: z.string().trim().min(1, 'Please enter a subject').max(200),
    message: z.string().trim().min(20, 'Please describe your issue in at least 20 characters').max(5000),
    /** Honeypot — see webDeletionRequestSchema. */
    website: z.string().max(200).optional(),
});

export const contactListQuerySchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(25),
    status: z.enum(['OPEN', 'RESOLVED']).optional(),
    search: z.string().trim().max(200).optional(),
});

export const updateContactMessageSchema = z.object({
    status: z.enum(['OPEN', 'RESOLVED']),
    note: z.string().trim().max(1000).optional(),
});

export type ContactMessageDto = z.infer<typeof contactMessageSchema>;

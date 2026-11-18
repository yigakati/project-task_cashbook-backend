import { z } from 'zod';

// ─── Contact Schemas (extended with type) ──────────────

export const createContactSchema = z.object({
    name: z.string().trim().min(1, 'Contact name is required').max(200),
    email: z.string().trim().toLowerCase().email().optional(),
    phone: z.string().max(30).optional(),
    company: z.string().max(200).optional(),
    notes: z.string().max(1000).optional(),
    type: z.enum(['PERSONAL', 'CUSTOMER', 'VENDOR']).default('PERSONAL'),
});

export const updateContactSchema = z.object({
    name: z.string().trim().min(1).max(200).optional(),
    email: z.string().trim().toLowerCase().email().optional(),
    phone: z.string().max(30).optional(),
    company: z.string().max(200).optional(),
    notes: z.string().max(1000).optional(),
    type: z.enum(['PERSONAL', 'CUSTOMER', 'VENDOR']).optional(),
});

export const contactQuerySchema = z.object({
    type: z.enum(['PERSONAL', 'CUSTOMER', 'VENDOR']).optional(),
});

// ─── Customer Profile Schemas ──────────────────────────

export const createCustomerProfileSchema = z.object({
    billingAddress: z.record(z.string(), z.any()).optional(),
    shippingAddress: z.record(z.string(), z.any()).optional(),
    currency: z.string().max(10).optional(),
    accountNumber: z.string().max(100).optional(),
    taxId: z.string().max(100).optional(),
    notes: z.string().max(1000).optional(),
});

export const updateCustomerProfileSchema = z.object({
    billingAddress: z.record(z.string(), z.any()).nullable().optional(),
    shippingAddress: z.record(z.string(), z.any()).nullable().optional(),
    currency: z.string().max(10).nullable().optional(),
    accountNumber: z.string().max(100).nullable().optional(),
    taxId: z.string().max(100).nullable().optional(),
    notes: z.string().max(1000).nullable().optional(),
});

// ─── Types ─────────────────────────────────────────────

export type CreateContactDto = z.infer<typeof createContactSchema>;
export type UpdateContactDto = z.infer<typeof updateContactSchema>;
export type ContactQueryDto = z.infer<typeof contactQuerySchema>;
export type CreateCustomerProfileDto = z.infer<typeof createCustomerProfileSchema>;
export type UpdateCustomerProfileDto = z.infer<typeof updateCustomerProfileSchema>;

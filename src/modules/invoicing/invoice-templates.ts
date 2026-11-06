import { z } from 'zod';

export const invoiceTemplateIds = [
    'classic',
    'modern',
    'contemporary',
    'minimal',
    'ledger',
    'letterhead',
    'executive',
    'editorial',
    'studio',
    'signature',
] as const;
export type InvoiceTemplateId = (typeof invoiceTemplateIds)[number];

/** This catalogue is also returned to clients; access decisions stay on the server. */
export const invoiceTemplates = [
    {
        id: 'classic',
        name: 'Classic',
        tier: 'professional',
        description: 'Familiar business stationery with a clear, framed table.',
        header: 'rule',
        table: 'ruled',
        font: 'sans',
    },
    {
        id: 'modern',
        name: 'Modern',
        tier: 'professional',
        description: 'A bold colour banner and crisp, spacious totals.',
        header: 'banner',
        table: 'striped',
        font: 'sans',
    },
    {
        id: 'contemporary',
        name: 'Contemporary',
        tier: 'professional',
        description: 'An asymmetric accent rail with a quiet, open table.',
        header: 'rail',
        table: 'minimal',
        font: 'sans',
    },
    {
        id: 'minimal',
        name: 'Essential',
        tier: 'professional',
        description: 'Restrained typography and generous white space; economical to print.',
        header: 'minimal',
        table: 'minimal',
        font: 'sans',
    },
    {
        id: 'ledger',
        name: 'Ledger',
        tier: 'professional',
        description: 'Structured columns and ruled rows for detailed orders.',
        header: 'boxed',
        table: 'ruled',
        font: 'sans',
    },
    {
        id: 'letterhead',
        name: 'Letterhead',
        tier: 'professional',
        description: 'Centred business identity with traditional serif headings.',
        header: 'centered',
        table: 'minimal',
        font: 'serif',
    },
    {
        id: 'executive',
        name: 'Executive',
        tier: 'premium',
        description: 'A dark masthead and confident, high-contrast summary.',
        header: 'dark',
        table: 'striped',
        font: 'sans',
    },
    {
        id: 'editorial',
        name: 'Editorial',
        tier: 'premium',
        description: 'Oversized serif typography with a double-rule finish.',
        header: 'editorial',
        table: 'minimal',
        font: 'serif',
    },
    {
        id: 'studio',
        name: 'Studio',
        tier: 'premium',
        description: 'A colour-block title and alternating rows for creative businesses.',
        header: 'split',
        table: 'striped',
        font: 'sans',
    },
    {
        id: 'signature',
        name: 'Signature',
        tier: 'premium',
        description: 'A fine border, centred title and refined serif details.',
        header: 'frame',
        table: 'ruled',
        font: 'serif',
    },
] as const;

export const invoiceCustomizationSchema = z
    .object({
        font: z.enum(['template', 'sans', 'serif']).default('template'),
        density: z.enum(['comfortable', 'compact']).default('comfortable'),
        tableStyle: z.enum(['template', 'striped', 'ruled', 'minimal']).default('template'),
        logoPlacement: z.enum(['left', 'right']).default('left'),
        paperSize: z.enum(['A4', 'LETTER']).default('A4'),
    })
    .strict();
export type InvoiceCustomization = z.infer<typeof invoiceCustomizationSchema>;
export const defaultInvoiceCustomization = invoiceCustomizationSchema.parse({});

export function invoiceTemplate(id?: string | null) {
    return invoiceTemplates.find((template) => template.id === id) ?? invoiceTemplates[0];
}

export function readInvoiceCustomization(value: unknown): InvoiceCustomization {
    const result = invoiceCustomizationSchema.safeParse(value);
    return result.success ? result.data : { ...defaultInvoiceCustomization };
}

export function invoiceDesignAccess(
    environment: string,
    subscriptionsActive: boolean,
    ownerPlan: string,
) {
    const development = environment === 'development' || environment === 'test';
    const paid = ownerPlan !== 'FREE';
    return {
        subscriptionsActive,
        premiumTemplatesAllowed: development || !subscriptionsActive || paid,
        customizationAllowed: development || (subscriptionsActive && paid),
        customizationReason: development
            ? 'development'
            : !subscriptionsActive
              ? 'subscriptions_not_active'
              : paid
                ? 'paid_plan'
                : 'paid_plan_required',
    };
}

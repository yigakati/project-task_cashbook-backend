import { z } from 'zod';
import { invoiceThemeIds } from './invoice-theme-assets';

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
    ...invoiceThemeIds,
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
    {
        id: 'outline',
        name: 'Blueprint',
        tier: 'professional',
        description:
            'A fine blue frame, paired customer and reference details, and a clear balance bar.',
        header: 'rule',
        table: 'striped',
        font: 'sans',
        theme: 'outline',
        layout: 'compact',
        color: '#3267C8',
    },
    {
        id: 'marble',
        name: 'Mineral',
        tier: 'premium',
        description: 'Soft mineral artwork behind a readable white invoice body.',
        header: 'minimal',
        table: 'striped',
        font: 'sans',
        theme: 'marble',
        layout: 'compact',
        color: '#233747',
    },
    {
        id: 'wave',
        name: 'Noir Wave',
        tier: 'premium',
        description: 'A black curved masthead and layered silver waves.',
        header: 'dark',
        table: 'striped',
        font: 'sans',
        theme: 'wave',
        layout: 'compact',
        color: '#172033',
    },
    {
        id: 'workshop',
        name: 'Workshop',
        tier: 'premium',
        description:
            'An illustrated industrial masthead; replace its artwork with a business photo when customization is available.',
        header: 'dark',
        table: 'striped',
        font: 'sans',
        theme: 'workshop',
        layout: 'compact',
        color: '#353A40',
    },
    {
        id: 'panel',
        name: 'Navy Panel',
        tier: 'professional',
        description: 'A navy surround with a white document panel and geometric footer.',
        header: 'dark',
        table: 'striped',
        font: 'sans',
        theme: 'panel',
        layout: 'compact',
        color: '#243458',
    },
    {
        id: 'ribbon',
        name: 'Ribbon',
        tier: 'premium',
        description: 'A tailored navy banner with angled silver ribbon accents.',
        header: 'dark',
        table: 'striped',
        font: 'sans',
        theme: 'ribbon',
        layout: 'compact',
        color: '#203263',
    },
    {
        id: 'watermark',
        name: 'Brandmark',
        tier: 'premium',
        description: 'A crisp red table with a subtle business-logo watermark.',
        header: 'minimal',
        table: 'striped',
        font: 'sans',
        theme: 'watermark',
        layout: 'compact',
        color: '#C53432',
    },
    {
        id: 'estate',
        name: 'Architecture',
        tier: 'premium',
        description: 'An original architectural illustration in a muted teal masthead.',
        header: 'banner',
        table: 'striped',
        font: 'sans',
        theme: 'estate',
        layout: 'compact',
        color: '#51808A',
    },
    {
        id: 'angle',
        name: 'Prism',
        tier: 'premium',
        description: 'A bold green diagonal with generous white space for line items.',
        header: 'minimal',
        table: 'striped',
        font: 'sans',
        theme: 'angle',
        layout: 'compact',
        color: '#087C62',
    },
    {
        id: 'pastel',
        name: 'Aura',
        tier: 'premium',
        description: 'A pastel blue and rose masthead with a sky-blue table.',
        header: 'minimal',
        table: 'striped',
        font: 'sans',
        theme: 'pastel',
        layout: 'compact',
        color: '#287CAE',
    },
    {
        id: 'botanical',
        name: 'Botanical',
        tier: 'premium',
        description: 'Light leaf-like side ribbons and fresh green headings.',
        header: 'minimal',
        table: 'striped',
        font: 'sans',
        theme: 'botanical',
        layout: 'compact',
        color: '#3D872F',
    },
    {
        id: 'mesh',
        name: 'Lattice',
        tier: 'premium',
        description: 'Fine geometric linework with a restrained indigo summary.',
        header: 'minimal',
        table: 'striped',
        font: 'sans',
        theme: 'mesh',
        layout: 'compact',
        color: '#20336A',
    },
] as const;

export const invoiceCustomizationSchema = z
    .object({
        font: z.enum(['template', 'sans', 'serif']).default('template'),
        density: z.enum(['comfortable', 'compact']).default('comfortable'),
        tableStyle: z.enum(['template', 'striped', 'ruled', 'minimal']).default('template'),
        logoPlacement: z.enum(['left', 'right']).default('left'),
        paperSize: z.enum(['A4', 'LETTER']).default('A4'),
        theme: z.enum(['template', 'none', ...invoiceThemeIds]).default('template'),
        artworkPlacement: z.enum(['header', 'background', 'watermark']).default('header'),
        artworkOpacity: z.number().min(0.04).max(0.25).default(0.12),
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

export function invoiceTheme(
    template: ReturnType<typeof invoiceTemplate>,
    customization: InvoiceCustomization,
) {
    return customization.theme === 'none'
        ? null
        : customization.theme === 'template'
          ? 'theme' in template
              ? template.theme
              : null
          : customization.theme;
}

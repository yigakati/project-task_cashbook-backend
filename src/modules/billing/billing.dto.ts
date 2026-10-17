import { z } from 'zod';

export const planKey = z.enum(['FREE', 'STARTER', 'GROWTH', 'ENTERPRISE']);

const extraStorage = z.number().min(0).max(100).multipleOf(0.5, 'Storage is added in 0.5 GB steps');

export const quoteQuerySchema = z.object({
    plan: planKey.default('STARTER'),
    /** Extra storage on top of the plan's, per workspace, in 0.5 GB steps. */
    extraStorageGb: z.coerce.number().pipe(extraStorage).default(0),
});

/**
 * A mobile-money number in the forms Ugandans write it: 07XXXXXXXX,
 * 7XXXXXXXX, 256XXXXXXXXX or +256XXXXXXXXX. Normalised to +256… before it
 * would reach a provider.
 */
const ugandanMobile = z.string().trim().transform((value) => value.replace(/[\s-]/g, ''))
    .refine((value) => /^(?:\+?256|0)?7\d{8}$/.test(value), 'Enter a Ugandan mobile-money number, e.g. 07XX XXX XXX');

export const checkoutSchema = z.object({
    plan: z.enum(['STARTER', 'GROWTH'], {
        message: 'Choose Starter or Growth. Free needs no payment, and Enterprise is arranged with us.',
    }),
    extraStorageGb: extraStorage.default(0),
    phone: ugandanMobile,
});

export type QuoteQuery = z.infer<typeof quoteQuerySchema>;
export type CheckoutDto = z.infer<typeof checkoutSchema>;

/** "+256771234567" from whatever the person typed. */
export function normalizePhone(value: string): string {
    const digits = value.replace(/[\s-]/g, '');
    const local = digits.replace(/^\+?256/, '').replace(/^0/, '');
    return `+256${local}`;
}

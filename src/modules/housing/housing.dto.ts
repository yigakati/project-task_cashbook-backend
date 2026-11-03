import { z } from 'zod';
import { DateTime } from 'luxon';
import { Decimal } from '@prisma/client/runtime/library';

export const money = z
    .string()
    .regex(/^\d{1,16}(\.\d{1,4})?$/, 'Use a decimal amount with at most four decimal places');
export const positiveMoney = money.refine(
    (v) => new Decimal(v).gt(0),
    'Amount must be greater than zero',
);
export const dateOnly = z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/)
    .refine((v) => {
        const date = DateTime.fromISO(v, { zone: 'UTC' });
        return date.isValid && date.year >= 2000 && date.year <= 2200;
    }, 'Use a valid date between 2000 and 2200');
export const pageSchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
});
export const propertyFilterSchema = z.object({ propertyId: z.string().uuid().optional() });
export const tenancyQuerySchema = pageSchema.extend(propertyFilterSchema.shape);
export const propertyQuerySchema = pageSchema.extend({
    search: z.string().trim().max(100).optional(),
    archived: z.enum(['true', 'false']).default('false'),
});
export const unitQuerySchema = propertyQuerySchema.extend(propertyFilterSchema.shape);
export const unitKind = z.enum(['ROOM', 'APARTMENT', 'HOUSE']);
const label = z.string().trim().min(1).max(120);
const prefix = z.string().max(100);
const startNumber = z.number().int().min(1).max(1000000);
export const unitFields = z.object({
    name: label,
    description: z.string().trim().max(2000).optional(),
    kind: unitKind,
    monthlyRent: positiveMoney,
});
export const unitSchema = unitFields
    .partial({ kind: true, monthlyRent: true })
    .extend({
        propertyId: z.string({ error: 'Create or select a property before adding a unit' }).uuid(),
        requestId: z.string().uuid(),
    })
    .strict();
// PATCH schemas deliberately have no creation defaults, including nested defaults.
export const updateUnitSchema = unitFields
    .partial()
    .extend({
        expectedVersion: z.number().int().positive(),
        archived: z.boolean().optional(),
    })
    .strict();
const propertyFields = z.object({
    name: label,
    address: z.string().trim().max(500).optional(),
    description: z.string().trim().max(2000).optional(),
    defaultKind: unitKind,
    defaultMonthlyRent: positiveMoney,
    unitLabelPrefix: prefix,
    unitNumberStart: startNumber,
});
export const updatePropertySchema = propertyFields
    .partial()
    .extend({
        expectedVersion: z.number().int().positive(),
        archived: z.boolean().optional(),
    })
    .strict();
const unitOverride = unitFields
    .partial()
    .extend({ name: z.string().trim().max(120).optional() })
    .strict();
const batchFields = {
    unitCount: z.number().int().min(1).max(500),
    units: z.array(unitOverride).max(500).optional(),
};
const matchingRows = (d: { unitCount: number; units?: unknown[] }) =>
    !d.units || d.units.length === d.unitCount;
export const propertyPreviewSchema = propertyFields
    .extend({
        defaultKind: unitKind.default('APARTMENT'),
        unitLabelPrefix: prefix.default('Unit '),
        unitNumberStart: startNumber.default(1),
        ...batchFields,
    })
    .strict()
    .refine(matchingRows, 'The number of unit rows must match the unit count');
export const createPropertySchema = propertyPreviewSchema.safeExtend({
    requestId: z.string().uuid(),
    previewToken: z.string().regex(/^[a-f0-9]{64}$/),
});
export const batchPreviewSchema = z
    .object({
        ...batchFields,
        defaultKind: unitKind.optional(),
        defaultMonthlyRent: positiveMoney.optional(),
        unitLabelPrefix: prefix.optional(),
        unitNumberStart: startNumber.optional(),
    })
    .strict()
    .refine(matchingRows, 'The number of unit rows must match the unit count');
export const addUnitsSchema = batchPreviewSchema.safeExtend({
    requestId: z.string().uuid(),
    previewToken: z.string().regex(/^[a-f0-9]{64}$/),
    expectedVersion: z.number().int().positive(),
});
export type PropertyPreviewInput = z.input<typeof propertyPreviewSchema>;
export type CreatePropertyInput = z.input<typeof createPropertySchema>;
export type BatchPreviewInput = z.infer<typeof batchPreviewSchema>;
export type AddUnitsInput = z.infer<typeof addUnitsSchema>;
export const tenancySchema = z
    .object({
        unitId: z.string().uuid(),
        tenantName: z.string().trim().min(1).max(120),
        contactId: z.string().uuid().optional(),
        startDate: dateOnly,
        endDate: dateOnly.optional(),
        monthlyRent: positiveMoney,
        firstPeriodAmount: money.optional(),
        finalPeriodAmount: money.optional(),
        dueDay: z.number().int().min(1).max(31),
        notes: z.string().trim().max(2000).optional(),
    })
    .refine((d) => !d.endDate || d.endDate > d.startDate, 'End date must be after the start date');
export const inviteSchema = z.object({
    contactId: z.string().uuid(),
    expectedVersion: z.number().int().positive(),
});
export const endTenancySchema = z.object({
    endDate: dateOnly,
    finalPeriodAmount: money.optional(),
    reason: z.string().trim().min(3).max(500),
    expectedVersion: z.number().int().positive(),
});
export const periodUpdateSchema = z.object({
    amount: money,
    dueDate: dateOnly,
    reason: z.string().trim().min(3).max(500),
    expectedVersion: z.number().int().positive(),
});
export const generateSchema = z.object({ through: dateOnly });
export const paymentSchema = z
    .object({
        requestId: z.string().uuid(),
        cashbookId: z.string().uuid(),
        accountId: z.string().uuid(),
        entryDate: z.string().datetime(),
        categoryId: z.string().uuid().optional(),
        paymentModeId: z.string().uuid().optional(),
        allocations: z
            .array(z.object({ periodId: z.string().uuid(), amount: positiveMoney }))
            .min(1)
            .max(24),
    })
    .refine(
        (d) => new Set(d.allocations.map((a) => a.periodId)).size === d.allocations.length,
        'Choose each period only once',
    );
export type UnitInput = z.input<typeof unitSchema>;
export type TenancyInput = z.infer<typeof tenancySchema>;
export type PaymentInput = z.infer<typeof paymentSchema>;

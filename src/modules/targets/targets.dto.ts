import { z } from 'zod';

const decimal = z.string().trim().regex(/^\d+(\.\d{1,4})?$/, 'Enter an amount with up to 4 decimal places');
const amount = decimal.refine((value) => Number(value) > 0, 'The target must be more than zero');
const positive = decimal.refine((value) => Number(value) > 0, 'Enter an amount more than zero');

const isoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Use a date like 2026-12-31');

const workingDays = z.array(z.number().int().min(1).max(7)).min(1, 'Pick at least one day').max(7)
    .refine((days) => new Set(days).size === days.length, 'Each day only once');

export const periodSchema = z.discriminatedUnion('kind', [
    z.object({
        kind: z.literal('preset'),
        preset: z.enum([
            'THIS_WEEK', 'NEXT_WEEK', 'THIS_MONTH', 'NEXT_MONTH', 'THIS_QUARTER', 'NEXT_QUARTER', 'THIS_YEAR', 'NEXT_YEAR',
        ]),
    }),
    z.object({ kind: z.literal('custom'), startDate: isoDate, endDate: isoDate }),
]);

export const createTargetSchema = z.object({
    name: z.string().trim().min(1, 'Give the target a name').max(120),
    /** BOOKS counts posted entries; MANUAL counts amounts recorded against the target. Fixed once set. */
    source: z.enum(['BOOKS', 'MANUAL']).default('BOOKS'),
    /** Books only. */
    metric: z.enum(['MONEY_IN', 'NET']).default('MONEY_IN'),
    amount,
    period: periodSchema,
    /** ISO weekdays that count. All seven (the default) means every calendar day. */
    workingDays: workingDays.default([1, 2, 3, 4, 5, 6, 7]),
    /** Books only. Empty means every book in the workspace. */
    cashbookIds: z.array(z.string().uuid()).max(200).default([]),
    /** A person's own target, counted from the entries they record. */
    assigneeId: z.string().uuid().nullable().default(null),
    /** Already raised before tracking began; on a book target, money made outside these books. */
    openingAmount: decimal.default('0'),
    /** The day the opening amount is in hand from. Defaults to today, kept within the period. */
    openingDate: isoDate.optional(),
    /** Start the next period when this one ends; how often follows from the period. */
    repeats: z.boolean().default(false),
    alertsEnabled: z.boolean().default(true),
    emailAlerts: z.boolean().default(false),
    /** Hand-recorded targets only: an evening nudge on a counted day with nothing recorded. */
    remindToRecord: z.boolean().default(false),
});

export const updateTargetSchema = z.object({
    name: z.string().trim().min(1).max(120).optional(),
    metric: z.enum(['MONEY_IN', 'NET']).optional(),
    amount: amount.optional(),
    period: periodSchema.optional(),
    workingDays: workingDays.optional(),
    cashbookIds: z.array(z.string().uuid()).max(200).optional(),
    assigneeId: z.string().uuid().nullable().optional(),
    openingAmount: decimal.optional(),
    openingDate: isoDate.optional(),
    repeats: z.boolean().optional(),
    alertsEnabled: z.boolean().optional(),
    emailAlerts: z.boolean().optional(),
    remindToRecord: z.boolean().optional(),
}).strict().refine((dto) => Object.keys(dto).length > 0, 'Nothing to change');

export const targetListQuerySchema = z.object({
    /** current = running or not yet started; ended = period over; archived; all. */
    status: z.enum(['current', 'ended', 'archived', 'all']).default('current'),
    /** "me" = targets assigned to the viewer. */
    assignee: z.union([z.literal('me'), z.literal('business'), z.string().uuid()]).optional(),
    limit: z.coerce.number().int().min(1).max(100).default(50),
});

const note = z.string().trim().max(280, 'Keep the note under 280 characters');

export const createContributionSchema = z.object({
    date: isoDate,
    kind: z.enum(['ADDITION', 'WITHDRAWAL']).default('ADDITION'),
    amount: positive,
    note: note.nullable().optional(),
});

export const updateContributionSchema = z.object({
    date: isoDate.optional(),
    kind: z.enum(['ADDITION', 'WITHDRAWAL']).optional(),
    amount: positive.optional(),
    note: note.nullable().optional(),
}).strict().refine((dto) => Object.keys(dto).length > 0, 'Nothing to change');

export const contributionListQuerySchema = z.object({
    limit: z.coerce.number().int().min(1).max(200).default(50),
    /** The id of the last record of the previous page. */
    cursor: z.string().uuid().optional(),
});

export type CreateContributionDto = z.infer<typeof createContributionSchema>;
export type UpdateContributionDto = z.infer<typeof updateContributionSchema>;
export type ContributionListQuery = z.infer<typeof contributionListQuerySchema>;
export type CreateTargetDto = z.infer<typeof createTargetSchema>;
export type UpdateTargetDto = z.infer<typeof updateTargetSchema>;
export type TargetListQuery = z.infer<typeof targetListQuerySchema>;

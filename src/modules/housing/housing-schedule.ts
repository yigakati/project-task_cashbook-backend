import { DateTime } from 'luxon';
import { Decimal } from '@prisma/client/runtime/library';
import { AppError } from '../../core/errors/AppError';

export const isoDate = (date: Date) => date.toISOString().slice(0, 10);
export const dbDate = (date: string) => new Date(`${date}T00:00:00.000Z`);
export interface ScheduleTerms {
    startDate: Date;
    endDate: Date | null;
    monthlyRent: Decimal;
    firstPeriodAmount: Decimal | null;
    finalPeriodAmount: Decimal | null;
    dueDay: number;
}
/** Half-open dates [start,end). Always add months to the ORIGINAL anniversary,
 * so January 31 -> February 28 -> March 31 never drifts to March 28. */
export function monthlySchedule(terms: ScheduleTerms, through: string) {
    const anchor = DateTime.fromISO(isoDate(terms.startDate), { zone: 'UTC' });
    const end = terms.endDate ? isoDate(terms.endDate) : null;
    const result: { startDate: Date; endDate: Date; dueDate: Date; amount: Decimal }[] = [];
    for (let i = 0; i < 2400; i++) {
        const start = anchor.plus({ months: i });
        const from = start.toISODate()!;
        if (from > through || (end && from >= end)) break;
        const naturalEnd = anchor.plus({ months: i + 1 }).toISODate()!;
        const until = end && end < naturalEnd ? end : naturalEnd;
        const shortened = until < naturalEnd;
        if (shortened && terms.finalPeriodAmount === null) {
            throw new AppError(
                'Enter the agreed amount for the shortened final period',
                400,
                'FINAL_PERIOD_AMOUNT_REQUIRED',
            );
        }
        // A due day before this period starts means payment is due at move-in;
        // it must not silently place the due date a month after occupation.
        const due = start.set({ day: Math.min(terms.dueDay, start.daysInMonth!) });
        result.push({
            startDate: dbDate(from),
            endDate: dbDate(until),
            dueDate: dbDate(due < start ? from : due.toISODate()!),
            amount: shortened
                ? terms.finalPeriodAmount!
                : i === 0 && terms.firstPeriodAmount !== null
                  ? terms.firstPeriodAmount
                  : terms.monthlyRent,
        });
    }
    return result;
}

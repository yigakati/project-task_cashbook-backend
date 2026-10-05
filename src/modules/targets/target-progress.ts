import { Decimal } from '@prisma/client/runtime/library';
import { DateTime } from 'luxon';

/** yyyy-mm-dd, a business date in the workspace's timezone. */
export type BusinessDate = string;

export type TargetStatus = 'UPCOMING' | 'ACTIVE' | 'ACHIEVED' | 'ENDED';

export interface ProgressInput {
    amount: Decimal;
    /** Inclusive. */
    startDate: BusinessDate;
    /** Inclusive. */
    endDate: BusinessDate;
    /** ISO weekdays that count: 1 = Monday … 7 = Sunday. */
    workingDays: number[];
    today: BusinessDate;
    /** What each day contributed, measured the way the target measures. Days with nothing are absent. */
    daily: Map<BusinessDate, Decimal>;
    /**
     * Raised before tracking began ("I already have 20M"), counted as in hand
     * at the start of `date`. Excluded from the daily figures — it is not one
     * day's takings — but part of every total.
     */
    opening?: { amount: Decimal; date: BusinessDate };
    /**
     * First day whose takings are known. Earlier days of a target recorded by
     * hand from partway through are unknown, not zero: they get no bar and
     * don't drag down the average. Defaults to the start date.
     */
    trackedFrom?: BusinessDate;
}

export interface DayPoint {
    date: BusinessDate;
    isWorkingDay: boolean;
    /** Null for days that have not happened yet, or before tracking began. */
    actual: string | null;
    /** The opening amount, on the day it counts from. */
    opening: string | null;
    /** Running total through this day; null in the future. */
    cumulative: string | null;
    /** Where an even pace would have put you by the end of this day. */
    expectedCumulative: string;
    /** What this day needed, given everything recorded before it. Null in the future or on a rest day. */
    needed: string | null;
}

export interface Progress {
    status: TargetStatus;
    achieved: string;
    remaining: string;
    /** 0–100+, one decimal place. */
    percent: number;
    /** The plan as first laid out: target ÷ working days. */
    plannedPerDay: string;

    totalWorkingDays: number;
    /** Working days fully behind us (before today). */
    workingDaysElapsed: number;
    /** Of those, the ones whose takings are known (from `trackedFrom`). */
    workingDaysTracked: number;
    /** Working days from today to the end, today included if it counts. */
    workingDaysLeft: number;
    isWorkingDayToday: boolean;

    /**
     * What today needs, fixed for the whole day: what was still missing when
     * the day began, shared over the working days left. Recording a sale
     * shows progress against it rather than shrinking it. Null outside the
     * period; 0 on a rest day.
     */
    todayTarget: string | null;
    todayAchieved: string;
    /** What is still needed today to stay on plan. */
    todayRemaining: string | null;
    /** If nothing more comes in today, what each remaining working day needs. */
    neededPerDayFromTomorrow: string | null;

    /** Where an even pace would have put you by the end of yesterday. */
    expectedToDate: string;
    /** achieved − expectedToDate: positive is ahead of pace. */
    paceDifference: string;
    /** The average of completed tracked working days, carried to the end of the period. */
    projectedTotal: string | null;
}

const ZERO = new Decimal(0);
const money = (value: Decimal) => value.toDecimalPlaces(2, Decimal.ROUND_HALF_UP).toFixed(2);
const parse = (date: BusinessDate) => DateTime.fromISO(date, { zone: 'utc' });
const fmt = (dt: DateTime) => dt.toISODate() as BusinessDate;

export function eachDate(start: BusinessDate, end: BusinessDate): BusinessDate[] {
    const out: BusinessDate[] = [];
    for (let d = parse(start), last = parse(end); d <= last; d = d.plus({ days: 1 })) out.push(fmt(d));
    return out;
}

export function isoWeekday(date: BusinessDate): number {
    return parse(date).weekday;
}

/** Working days in [from, to], both inclusive. */
export function countWorkingDays(from: BusinessDate, to: BusinessDate, workingDays: number[]): number {
    if (from > to) return 0;
    const days = new Set(workingDays);
    let count = 0;
    for (const date of eachDate(from, to)) if (days.has(isoWeekday(date))) count += 1;
    return count;
}

export const addDays = (date: BusinessDate, days: number) => fmt(parse(date).plus({ days }));

/**
 * Where a target stands on a given day.
 *
 * Pure: everything comes in through the arguments, so the arithmetic is
 * tested exhaustively without a database.
 */
export function computeProgress(input: ProgressInput): Progress {
    const { amount, startDate, endDate, workingDays, today, daily } = input;
    const working = new Set(workingDays);
    const totalWorkingDays = countWorkingDays(startDate, endDate, workingDays);
    const plannedPerDay = totalWorkingDays > 0 ? amount.div(totalWorkingDays) : amount;
    const opening = input.opening?.amount ?? ZERO;
    const trackedFrom = input.trackedFrom && input.trackedFrom > startDate ? input.trackedFrom : startDate;

    // Everything counted happened inside the period and no later than today.
    const lastCounted = today < endDate ? today : endDate;
    let recordedBeforeToday = ZERO;
    let todayAchieved = ZERO;
    for (const [date, value] of daily) {
        if (date < startDate || date > lastCounted) continue;
        if (date === today) todayAchieved = todayAchieved.add(value);
        else recordedBeforeToday = recordedBeforeToday.add(value);
    }
    // The opening amount is in hand from the start of its day — never part of
    // "today", so recording it can't look like a day's takings.
    const achievedBeforeToday = recordedBeforeToday.add(opening);
    const achieved = achievedBeforeToday.add(todayAchieved);
    const remaining = Decimal.max(ZERO, amount.sub(achieved));
    const percent = Math.round(achieved.div(amount).mul(1000).toNumber()) / 10;

    const base = {
        achieved: money(achieved),
        remaining: money(remaining),
        percent,
        plannedPerDay: money(plannedPerDay),
        totalWorkingDays,
        todayAchieved: money(todayAchieved),
    };

    if (today < startDate) {
        return {
            ...base,
            status: 'UPCOMING',
            workingDaysElapsed: 0,
            workingDaysTracked: 0,
            workingDaysLeft: totalWorkingDays,
            isWorkingDayToday: false,
            todayTarget: null,
            todayRemaining: null,
            neededPerDayFromTomorrow: null,
            expectedToDate: money(ZERO),
            paceDifference: money(ZERO),
            projectedTotal: null,
        };
    }

    if (today > endDate) {
        return {
            ...base,
            status: achieved.gte(amount) ? 'ACHIEVED' : 'ENDED',
            workingDaysElapsed: totalWorkingDays,
            workingDaysTracked: countWorkingDays(trackedFrom, endDate, workingDays),
            workingDaysLeft: 0,
            isWorkingDayToday: false,
            todayTarget: null,
            todayRemaining: null,
            neededPerDayFromTomorrow: null,
            expectedToDate: money(amount),
            paceDifference: money(achieved.sub(amount)),
            projectedTotal: money(achieved),
        };
    }

    const isWorkingDayToday = working.has(isoWeekday(today));
    const workingDaysElapsed = countWorkingDays(startDate, addDays(today, -1), workingDays);
    const workingDaysTracked = countWorkingDays(trackedFrom, addDays(today, -1), workingDays);
    const workingDaysLeft = countWorkingDays(today, endDate, workingDays);
    const workingDaysAfterToday = workingDaysLeft - (isWorkingDayToday ? 1 : 0);

    const missingAtStartOfDay = Decimal.max(ZERO, amount.sub(achievedBeforeToday));
    const todayTarget = isWorkingDayToday && workingDaysLeft > 0
        ? missingAtStartOfDay.div(workingDaysLeft)
        : ZERO;
    const todayRemaining = Decimal.max(ZERO, todayTarget.sub(todayAchieved));
    const neededPerDayFromTomorrow = workingDaysAfterToday > 0 ? remaining.div(workingDaysAfterToday) : null;

    const expectedToDate = totalWorkingDays > 0
        ? amount.mul(workingDaysElapsed).div(totalWorkingDays)
        : ZERO;
    // What's in hand, plus the average tracked day carried over the days left.
    // The opening amount is not a day's takings, so it stays out of the average.
    const projectedTotal = workingDaysTracked > 0
        ? achievedBeforeToday.add(recordedBeforeToday.div(workingDaysTracked).mul(workingDaysLeft))
        : null;

    return {
        ...base,
        status: achieved.gte(amount) ? 'ACHIEVED' : 'ACTIVE',
        workingDaysElapsed,
        workingDaysTracked,
        workingDaysLeft,
        isWorkingDayToday,
        todayTarget: money(todayTarget),
        todayRemaining: money(todayRemaining),
        neededPerDayFromTomorrow: neededPerDayFromTomorrow ? money(neededPerDayFromTomorrow) : null,
        expectedToDate: money(expectedToDate),
        paceDifference: money(achieved.sub(expectedToDate)),
        projectedTotal: projectedTotal ? money(projectedTotal) : null,
    };
}

/**
 * Every day of the period, for the chart: what came in, the running total, the
 * even-pace line, and what each day needed given everything before it.
 */
export function dailySeries(input: ProgressInput): DayPoint[] {
    const { amount, startDate, endDate, workingDays, today, daily, opening } = input;
    const working = new Set(workingDays);
    const totalWorkingDays = countWorkingDays(startDate, endDate, workingDays);
    const trackedFrom = input.trackedFrom && input.trackedFrom > startDate ? input.trackedFrom : startDate;

    const dates = eachDate(startDate, endDate);
    // Working days from each date to the end, today included — computed once
    // from the back rather than recounted for every point.
    const leftFrom = new Map<BusinessDate, number>();
    let left = 0;
    for (let i = dates.length - 1; i >= 0; i--) {
        if (working.has(isoWeekday(dates[i]))) left += 1;
        leftFrom.set(dates[i], left);
    }

    const points: DayPoint[] = [];
    let cumulative = ZERO;
    let elapsedWorking = 0;
    for (const date of dates) {
        const isWorkingDay = working.has(isoWeekday(date));
        if (isWorkingDay) elapsedWorking += 1;
        const expected = totalWorkingDays > 0 ? amount.mul(elapsedWorking).div(totalWorkingDays) : ZERO;
        const happened = date <= today;
        const known = happened && date >= trackedFrom;

        const openingToday = opening && opening.date === date ? opening.amount : null;
        if (openingToday) cumulative = cumulative.add(openingToday);

        let needed: string | null = null;
        if (known && isWorkingDay) {
            needed = money(Decimal.max(ZERO, amount.sub(cumulative)).div(leftFrom.get(date) ?? 1));
        }

        const actual = known ? daily.get(date) ?? ZERO : null;
        if (actual) cumulative = cumulative.add(actual);

        points.push({
            date,
            isWorkingDay,
            actual: actual ? money(actual) : null,
            opening: openingToday ? money(openingToday) : null,
            cumulative: known ? money(cumulative) : null,
            expectedCumulative: money(expected),
            needed,
        });
    }
    return points;
}

/** ISO week key, e.g. "2026-W40" — for at-most-weekly alerts. */
export function isoWeekKey(date: BusinessDate): string {
    const dt = parse(date);
    return `${dt.weekYear}-W${String(dt.weekNumber).padStart(2, '0')}`;
}

/** How often a repeating target comes round: a number of months, or of days. */
export type Cadence = { unit: 'months' | 'days'; count: number };

/** Longest month-based cadence recognised: the five-year cap on a period. */
const MAX_CADENCE_MONTHS = 60;

/**
 * The cadence a period implies when it repeats — so a repeat can never
 * disagree with its period (a year that "repeats monthly").
 *
 * A period that runs a whole number of months from its start day (1 Jan –
 * 31 Mar, 15 Jan – 14 Feb, Jul – Jun for a financial year) repeats by months,
 * so every period starts on the same day of the month. Anything else — a week,
 * a fortnight, 45 days — repeats by its own length in days. Month cadences
 * need a start day of 28 or earlier, the days every month has; later starts
 * would drift as months get shorter.
 */
export function cadenceOf(startDate: BusinessDate, endDate: BusinessDate): Cadence {
    const start = parse(startDate);
    const end = parse(endDate);
    if (start.day <= 28) {
        for (let months = 1; months <= MAX_CADENCE_MONTHS; months++) {
            const candidate = start.plus({ months }).minus({ days: 1 });
            if (candidate.equals(end)) return { unit: 'months', count: months };
            if (candidate > end) break;
        }
    }
    return { unit: 'days', count: Math.round(end.diff(start, 'days').days) + 1 };
}

/** The next period of a repeating target: same cadence, starting the day after this one ends. */
export function nextPeriod(startDate: BusinessDate, endDate: BusinessDate): { startDate: BusinessDate; endDate: BusinessDate } {
    const cadence = cadenceOf(startDate, endDate);
    const start = parse(endDate).plus({ days: 1 });
    const end = cadence.unit === 'months'
        ? start.plus({ months: cadence.count }).minus({ days: 1 })
        : start.plus({ days: cadence.count - 1 });
    return { startDate: fmt(start), endDate: fmt(end) };
}

/** Calendar presets, resolved against the workspace's "today". Weeks run Monday to Sunday. */
export type PeriodPreset =
    | 'THIS_WEEK' | 'NEXT_WEEK'
    | 'THIS_MONTH' | 'NEXT_MONTH'
    | 'THIS_QUARTER' | 'NEXT_QUARTER'
    | 'THIS_YEAR' | 'NEXT_YEAR';

export function resolvePreset(preset: PeriodPreset, today: BusinessDate): { startDate: BusinessDate; endDate: BusinessDate } {
    const t = parse(today);
    switch (preset) {
        case 'THIS_WEEK':
            return { startDate: fmt(t.startOf('week')), endDate: fmt(t.endOf('week')) };
        case 'NEXT_WEEK': {
            const n = t.plus({ weeks: 1 });
            return { startDate: fmt(n.startOf('week')), endDate: fmt(n.endOf('week')) };
        }
        case 'THIS_MONTH':
            return { startDate: fmt(t.startOf('month')), endDate: fmt(t.endOf('month')) };
        case 'NEXT_MONTH': {
            const n = t.plus({ months: 1 });
            return { startDate: fmt(n.startOf('month')), endDate: fmt(n.endOf('month')) };
        }
        case 'THIS_QUARTER':
            return { startDate: fmt(t.startOf('quarter')), endDate: fmt(t.endOf('quarter')) };
        case 'NEXT_QUARTER': {
            const n = t.plus({ months: 3 });
            return { startDate: fmt(n.startOf('quarter')), endDate: fmt(n.endOf('quarter')) };
        }
        case 'THIS_YEAR':
            return { startDate: fmt(t.startOf('year')), endDate: fmt(t.endOf('year')) };
        case 'NEXT_YEAR': {
            const n = t.plus({ years: 1 });
            return { startDate: fmt(n.startOf('year')), endDate: fmt(n.endOf('year')) };
        }
    }
}

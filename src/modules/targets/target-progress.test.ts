/**
 * The arithmetic behind a target, with no database: the daily need, how a
 * slow or strong day moves it, rest days, pace and projection.
 */
import { describe, expect, it } from 'vitest';
import { Decimal } from '@prisma/client/runtime/library';
import {
    cadenceOf,
    computeProgress,
    countWorkingDays,
    dailySeries,
    isoWeekKey,
    nextPeriod,
    resolvePreset,
    type ProgressInput,
} from './target-progress';

const EVERY_DAY = [1, 2, 3, 4, 5, 6, 7];
const MON_SAT = [1, 2, 3, 4, 5, 6];

const input = (over: Partial<ProgressInput> = {}): ProgressInput => ({
    amount: new Decimal('1000'),
    startDate: '2026-06-01', // a Monday
    endDate: '2026-06-10',   // ten days
    workingDays: EVERY_DAY,
    today: '2026-06-01',
    daily: new Map(),
    ...over,
});

const days = (entries: Record<string, string>) =>
    new Map(Object.entries(entries).map(([d, v]) => [d, new Decimal(v)]));

describe('target progress', () => {
    it('spreads the target evenly at the start', () => {
        const p = computeProgress(input());
        expect(p.status).toBe('ACTIVE');
        expect(p.totalWorkingDays).toBe(10);
        expect(p.plannedPerDay).toBe('100.00');
        expect(p.todayTarget).toBe('100.00');
        expect(p.workingDaysLeft).toBe(10);
    });

    it('raises the daily need after a missed day', () => {
        // Day 1 brought nothing: 1000 over the 9 days left.
        const p = computeProgress(input({ today: '2026-06-02' }));
        expect(p.todayTarget).toBe('111.11');
        expect(p.paceDifference).toBe('-100.00');
    });

    it('lowers the daily need after a strong day', () => {
        const p = computeProgress(input({ today: '2026-06-02', daily: days({ '2026-06-01': '280' }) }));
        // 720 left over 9 days.
        expect(p.todayTarget).toBe('80.00');
        expect(p.paceDifference).toBe('180.00');
    });

    it("keeps today's figure fixed as today's sales come in", () => {
        const before = computeProgress(input({ today: '2026-06-02' }));
        const after = computeProgress(input({ today: '2026-06-02', daily: days({ '2026-06-02': '50' }) }));

        expect(after.todayTarget).toBe(before.todayTarget);
        expect(after.todayAchieved).toBe('50.00');
        expect(after.todayRemaining).toBe('61.11');
        // ...while the outlook for the rest of the period does move.
        expect(after.neededPerDayFromTomorrow).toBe('118.75'); // (1000 − 50) / 8
    });

    it('gives rest days no share, so open days carry the target', () => {
        // Mon 1 – Sun 14 June, closed Sundays: 12 trading days.
        const p = computeProgress(input({ endDate: '2026-06-14', workingDays: MON_SAT, amount: new Decimal('1200') }));
        expect(p.totalWorkingDays).toBe(12);
        expect(p.plannedPerDay).toBe('100.00');

        const sunday = computeProgress(input({
            endDate: '2026-06-14', workingDays: MON_SAT, amount: new Decimal('1200'), today: '2026-06-07',
            daily: days({ '2026-06-01': '600' }),
        }));
        expect(sunday.isWorkingDayToday).toBe(false);
        expect(sunday.todayTarget).toBe('0.00');
        // 600 left over Mon–Sat of the second week.
        expect(sunday.neededPerDayFromTomorrow).toBe('100.00');
    });

    it('measures pace against completed days, and projects from them', () => {
        const p = computeProgress(input({
            today: '2026-06-05', // days 1–4 complete
            daily: days({ '2026-06-01': '50', '2026-06-02': '50', '2026-06-03': '50', '2026-06-04': '50' }),
        }));
        expect(p.workingDaysElapsed).toBe(4);
        expect(p.expectedToDate).toBe('400.00');
        expect(p.paceDifference).toBe('-200.00');
        expect(p.projectedTotal).toBe('500.00'); // 50 a day for 10 days
    });

    it('is achieved as soon as the total reaches the target, and needs nothing more', () => {
        const p = computeProgress(input({ today: '2026-06-04', daily: days({ '2026-06-02': '1200' }) }));
        expect(p.status).toBe('ACHIEVED');
        expect(p.remaining).toBe('0.00');
        expect(p.todayTarget).toBe('0.00');
        expect(p.percent).toBe(120);
    });

    it('ignores anything outside the period', () => {
        const p = computeProgress(input({
            today: '2026-06-03',
            daily: days({ '2026-05-31': '999', '2026-06-01': '100', '2026-06-04': '999' }),
        }));
        expect(p.achieved).toBe('100.00');
    });

    it('lets a net target go backwards', () => {
        const p = computeProgress(input({ today: '2026-06-02', daily: days({ '2026-06-01': '-200' }) }));
        expect(p.achieved).toBe('-200.00');
        expect(p.remaining).toBe('1200.00');
        expect(p.todayTarget).toBe('133.33'); // 1200 / 9
    });

    it('reports upcoming and ended periods without daily figures', () => {
        expect(computeProgress(input({ today: '2026-05-20' }))).toMatchObject({ status: 'UPCOMING', todayTarget: null });
        expect(computeProgress(input({ today: '2026-06-20', daily: days({ '2026-06-01': '300' }) })))
            .toMatchObject({ status: 'ENDED', todayTarget: null, achieved: '300.00' });
    });

    it('charts every day, with the need each day faced', () => {
        const series = dailySeries(input({ today: '2026-06-02', daily: days({ '2026-06-01': '300' }) }));
        expect(series).toHaveLength(10);
        expect(series[0]).toMatchObject({ actual: '300.00', cumulative: '300.00', expectedCumulative: '100.00', needed: '100.00' });
        expect(series[1]).toMatchObject({ actual: '0.00', needed: '77.78' }); // 700 / 9
        expect(series[2]).toMatchObject({ actual: null, cumulative: null, needed: null });
        expect(series[9].expectedCumulative).toBe('1000.00');
    });
});

describe('periods', () => {
    it('counts working days inclusively', () => {
        expect(countWorkingDays('2026-06-01', '2026-06-07', MON_SAT)).toBe(6);
        expect(countWorkingDays('2026-06-07', '2026-06-01', MON_SAT)).toBe(0);
    });

    it('resolves calendar presets', () => {
        expect(resolvePreset('THIS_YEAR', '2026-10-04')).toEqual({ startDate: '2026-01-01', endDate: '2026-12-31' });
        expect(resolvePreset('THIS_QUARTER', '2026-10-04')).toEqual({ startDate: '2026-10-01', endDate: '2026-12-31' });
        expect(resolvePreset('NEXT_MONTH', '2026-12-15')).toEqual({ startDate: '2027-01-01', endDate: '2027-01-31' });
    });

    it('resolves weeks Monday to Sunday', () => {
        expect(resolvePreset('THIS_WEEK', '2026-10-04')).toEqual({ startDate: '2026-09-28', endDate: '2026-10-04' });
        expect(resolvePreset('NEXT_WEEK', '2026-10-04')).toEqual({ startDate: '2026-10-05', endDate: '2026-10-11' });
    });

    it('takes the repeat from the period itself', () => {
        expect(cadenceOf('2026-01-01', '2026-01-31')).toEqual({ unit: 'months', count: 1 });
        expect(cadenceOf('2026-02-01', '2026-02-28')).toEqual({ unit: 'months', count: 1 });
        expect(cadenceOf('2026-10-01', '2026-12-31')).toEqual({ unit: 'months', count: 3 });
        expect(cadenceOf('2026-01-01', '2026-12-31')).toEqual({ unit: 'months', count: 12 });
        // A financial year, and a month that runs from the 15th.
        expect(cadenceOf('2026-07-01', '2027-06-30')).toEqual({ unit: 'months', count: 12 });
        expect(cadenceOf('2026-01-15', '2026-02-14')).toEqual({ unit: 'months', count: 1 });
        // Weeks and odd lengths repeat by days.
        expect(cadenceOf('2026-09-28', '2026-10-04')).toEqual({ unit: 'days', count: 7 });
        expect(cadenceOf('2026-10-01', '2026-11-14')).toEqual({ unit: 'days', count: 45 });
        // Starting on the 29th–31st would drift through short months, so it counts days.
        expect(cadenceOf('2026-01-31', '2026-02-27')).toEqual({ unit: 'days', count: 28 });
    });

    it('rolls a period over to the next one of the same shape', () => {
        expect(nextPeriod('2026-01-01', '2026-01-31')).toEqual({ startDate: '2026-02-01', endDate: '2026-02-28' });
        expect(nextPeriod('2026-02-01', '2026-02-28')).toEqual({ startDate: '2026-03-01', endDate: '2026-03-31' });
        expect(nextPeriod('2026-01-01', '2026-03-31')).toEqual({ startDate: '2026-04-01', endDate: '2026-06-30' });
        expect(nextPeriod('2026-01-01', '2026-12-31')).toEqual({ startDate: '2027-01-01', endDate: '2027-12-31' });
        expect(nextPeriod('2026-01-15', '2026-02-14')).toEqual({ startDate: '2026-02-15', endDate: '2026-03-14' });
        expect(nextPeriod('2026-09-28', '2026-10-04')).toEqual({ startDate: '2026-10-05', endDate: '2026-10-11' });
    });

    it('keys weeks for at-most-weekly alerts', () => {
        expect(isoWeekKey('2026-10-04')).toBe('2026-W40');
    });
});

describe('starting partway, with money already raised', () => {
    // Six months from 4 Aug, 50M, set up on 4 Oct with 20M already raised.
    const halfYear = (over: Partial<ProgressInput> = {}) => input({
        amount: new Decimal('50000000'),
        startDate: '2026-08-04',
        endDate: '2027-02-03',
        today: '2026-10-04',
        opening: { amount: new Decimal('20000000'), date: '2026-10-04' },
        trackedFrom: '2026-10-04',
        ...over,
    });

    it('spreads only what is left over the days left', () => {
        const p = computeProgress(halfYear());
        expect(p.achieved).toBe('20000000.00');
        expect(p.remaining).toBe('30000000.00');
        expect(p.workingDaysLeft).toBe(123);
        // 30M over 123 days, not 50M over 184: the opening counts as in hand.
        expect(p.todayTarget).toBe('243902.44');
        expect(p.todayAchieved).toBe('0.00');
    });

    it('says how far ahead or behind an even pace that puts you', () => {
        const p = computeProgress(halfYear());
        // An even pace would have 61 of 184 days done: 16,576,086.96.
        expect(p.expectedToDate).toBe('16576086.96');
        expect(p.paceDifference).toBe('3423913.04');
    });

    it("doesn't project from the opening amount as if it were one day's takings", () => {
        expect(computeProgress(halfYear()).projectedTotal).toBeNull();
        const next = computeProgress(halfYear({ today: '2026-10-05', daily: days({ '2026-10-04': '250000' }) }));
        expect(next.workingDaysTracked).toBe(1);
        // 20.25M in hand + 250k a day over the 122 days left.
        expect(next.projectedTotal).toBe('50750000.00');
    });

    it('leaves days before tracking began blank on the chart, and starts the total at the opening', () => {
        const series = dailySeries(halfYear({ today: '2026-10-05', daily: days({ '2026-10-04': '250000' }) }));
        const before = series.find((p) => p.date === '2026-10-03');
        expect(before?.actual).toBeNull();
        expect(before?.cumulative).toBeNull();
        expect(before?.needed).toBeNull();
        const first = series.find((p) => p.date === '2026-10-04');
        expect(first?.opening).toBe('20000000.00');
        expect(first?.actual).toBe('250000.00');
        expect(first?.needed).toBe('243902.44');
        expect(first?.cumulative).toBe('20250000.00');
    });

    it('lowers the need when money is taken out and raises it after', () => {
        const p = computeProgress(halfYear({ today: '2026-10-05', daily: days({ '2026-10-04': '-1000000' }) }));
        expect(p.achieved).toBe('19000000.00');
        // 31M over the 122 days left.
        expect(p.todayTarget).toBe('254098.36');
    });
});

/**
 * Leave, overtime, flags and work reports.
 *
 * The two properties worth the most here:
 *
 *   Approved leave is materialised one row per working day, and the unique on
 *   (workspace, user, date) is what makes double-booking impossible even when
 *   two approvals land together. An overlap check in a service cannot promise
 *   that, because the check and the write are separate statements.
 *
 *   Overtime is measured whether or not it is counted. A workspace that does
 *   not track overtime still records the minutes, so an approval weeks later
 *   can turn them into counted time rather than finding nothing to count.
 */
import { beforeEach, describe, expect, it, vi, afterEach } from 'vitest';
import { WorkspaceRole } from '@prisma/client';
import { resetDatabase, testPrisma } from '../setup';
import { resolveService } from '../container';
import { LeaveService } from '../../modules/attendance/leave.service';
import { PeopleOpsService } from '../../modules/attendance/people-ops.service';
import { AttendanceRollupService } from '../../modules/attendance/rollup.service';
import { TimeTrackingService } from '../../modules/time-tracking/time-tracking.service';
import { addWorkspaceMember, createUser, createWorkspace } from '../factories';
import { clearClockCache, toDateColumn } from '../../core/time/workspace-clock';

const leave = () => resolveService(LeaveService);
const peopleOps = () => resolveService(PeopleOpsService);
const rollup = () => resolveService(AttendanceRollupService);

// 2026-03-09 is a Monday; 03-14 and 03-15 are the weekend.
const MON = '2026-03-09';
const TUE = '2026-03-10';
const WED = '2026-03-11';
const FRI = '2026-03-13';
const NEXT_MON = '2026-03-16';

async function fixture() {
    const owner = await createUser();
    const workspace = await createWorkspace(owner.id);
    await testPrisma.attendanceSettings.create({ data: { workspaceId: workspace.id } });
    await testPrisma.workSchedule.create({
        data: {
            workspaceId: workspace.id,
            workingDays: [1, 2, 3, 4, 5],
            startTime: '09:00',
            endTime: '17:00',
            expectedMinutesPerDay: 480,
            effectiveFrom: toDateColumn('2026-01-01'),
        },
    });
    const annual = await testPrisma.leaveType.create({
        data: { workspaceId: workspace.id, name: 'Annual leave', code: 'ANNUAL' },
    });

    const member = await createUser();
    await addWorkspaceMember(workspace.id, member.id, WorkspaceRole.MEMBER);
    const hr = await createUser();
    await addWorkspaceMember(workspace.id, hr.id, WorkspaceRole.HR);

    return { owner, workspace, member, hr, annual };
}

beforeEach(async () => {
    // Lock the time so lateFixture is reliably "late" (e.g. 15:00 UTC = 18:00 Kampala, 
    // which is 18 hours after 00:01 local time).
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-03-09T15:00:00Z'));

    await resetDatabase();
    clearClockCache();
});

describe('requesting leave', () => {
    it('counts only working days', async () => {
        // Friday to the following Monday is two days, not four — the weekend is
        // not leave, it is days nobody was expected.
        const f = await fixture();

        const request = await leave().requestLeave(f.workspace.id, f.member.id, {
            leaveTypeId: f.annual.id,
            startDate: FRI,
            endDate: NEXT_MON,
            reason: 'Long weekend',
        } as any);

        expect(Number(request.totalDays)).toBe(2);
    });

    it('counts half-days as halves', async () => {
        const f = await fixture();

        const request = await leave().requestLeave(f.workspace.id, f.member.id, {
            leaveTypeId: f.annual.id,
            startDate: MON,
            endDate: WED,
            startPortion: 'SECOND_HALF',
            reason: 'Appointment then away',
        } as any);

        expect(Number(request.totalDays)).toBe(2.5);
    });

    it('refuses a range made entirely of days off', async () => {
        const f = await fixture();

        await expect(
            leave().requestLeave(f.workspace.id, f.member.id, {
                leaveTypeId: f.annual.id,
                startDate: '2026-03-14', // Saturday
                endDate: '2026-03-15',   // Sunday
                reason: 'Weekend',
            } as any),
        ).rejects.toMatchObject({ code: 'NO_WORKING_DAYS' });
    });

    it('skips a holiday inside the range', async () => {
        const f = await fixture();
        await testPrisma.holiday.create({
            data: { workspaceId: f.workspace.id, date: toDateColumn(TUE), name: 'Public holiday' },
        });

        const request = await leave().requestLeave(f.workspace.id, f.member.id, {
            leaveTypeId: f.annual.id,
            startDate: MON,
            endDate: WED,
            reason: 'Away',
        } as any);

        expect(Number(request.totalDays)).toBe(2);
    });
});

describe('deciding leave', () => {
    async function pending() {
        const f = await fixture();
        const request = await leave().requestLeave(f.workspace.id, f.member.id, {
            leaveTypeId: f.annual.id, startDate: MON, endDate: WED, reason: 'Away',
        } as any);
        return { ...f, request };
    }

    it('materialises one row per working day on approval', async () => {
        const { workspace, hr, request } = await pending();

        await leave().reviewLeave(request.id, workspace.id, hr.id, { approve: true } as any);

        const days = await testPrisma.leaveDay.findMany({
            select: { date: true },
            orderBy: { date: 'asc' },
        });
        expect(days).toHaveLength(3);
        expect(days.map((day: { date: Date }) => day.date.toISOString().slice(0, 10)))
            .toEqual([MON, TUE, WED]);
    });

    it('materialises nothing when declined', async () => {
        const { workspace, hr, request } = await pending();

        await leave().reviewLeave(request.id, workspace.id, hr.id, {
            approve: false, reviewNote: 'Too many people out that week',
        } as any);

        expect(await testPrisma.leaveDay.count()).toBe(0);
    });

    it('requires a reason to decline', async () => {
        const { workspace, hr, request } = await pending();

        await expect(
            leave().reviewLeave(request.id, workspace.id, hr.id, { approve: false } as any),
        ).rejects.toMatchObject({ code: 'REVIEW_NOTE_REQUIRED' });
    });

    it('refuses a plain member as the decider', async () => {
        const { workspace, member, request } = await pending();

        await expect(
            leave().reviewLeave(request.id, workspace.id, member.id, { approve: true } as any),
        ).rejects.toMatchObject({ statusCode: 403 });
    });

    it('lets exactly one of two simultaneous decisions through', async () => {
        const { workspace, owner, hr, request } = await pending();

        const results = await Promise.allSettled([
            leave().reviewLeave(request.id, workspace.id, hr.id, { approve: true } as any),
            leave().reviewLeave(request.id, workspace.id, owner.id, {
                approve: false, reviewNote: 'no',
            } as any),
        ]);

        expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
        const decided = await testPrisma.leaveRequest.findUniqueOrThrow({ where: { id: request.id } });
        // The materialised days agree with whichever decision won.
        expect(await testPrisma.leaveDay.count())
            .toBe(decided.status === 'APPROVED' ? 3 : 0);
    });
});

describe('leave cannot be double-booked', () => {
    it('rejects a second approval covering the same day, and rolls back entirely', async () => {
        const f = await fixture();
        const first = await leave().requestLeave(f.workspace.id, f.member.id, {
            leaveTypeId: f.annual.id, startDate: MON, endDate: TUE, reason: 'A',
        } as any);
        await leave().reviewLeave(first.id, f.workspace.id, f.hr.id, { approve: true } as any);

        // Filed before the first was approved, so the pre-check passed.
        const second = await testPrisma.leaveRequest.create({
            data: {
                workspaceId: f.workspace.id,
                userId: f.member.id,
                leaveTypeId: f.annual.id,
                startDate: toDateColumn(TUE),
                endDate: toDateColumn(WED),
                totalDays: 2,
                reason: 'B',
            },
        });

        await expect(
            leave().reviewLeave(second.id, f.workspace.id, f.hr.id, { approve: true } as any),
        ).rejects.toMatchObject({ statusCode: 409 });

        // All or nothing: Wednesday was not booked either.
        expect(await testPrisma.leaveDay.count()).toBe(2);
        expect(
            (await testPrisma.leaveRequest.findUniqueOrThrow({ where: { id: second.id } })).status,
        ).toBe('PENDING');
    });

    it('frees the dates again when approved leave is cancelled', async () => {
        const f = await fixture();
        const request = await leave().requestLeave(f.workspace.id, f.member.id, {
            leaveTypeId: f.annual.id, startDate: MON, endDate: TUE, reason: 'A',
        } as any);
        await leave().reviewLeave(request.id, f.workspace.id, f.hr.id, { approve: true } as any);

        await leave().cancelApprovedLeave(request.id, f.workspace.id, f.member.id);

        expect(await testPrisma.leaveDay.count()).toBe(0);
        // And the dates can be booked again.
        await expect(
            leave().requestLeave(f.workspace.id, f.member.id, {
                leaveTypeId: f.annual.id, startDate: MON, endDate: TUE, reason: 'Retry',
            } as any),
        ).resolves.toBeTruthy();
    });
});

describe('leave shows up in the rollup', () => {
    it('reports ON_LEAVE rather than ABSENT', async () => {
        const f = await fixture();
        const request = await leave().requestLeave(f.workspace.id, f.member.id, {
            leaveTypeId: f.annual.id, startDate: TUE, endDate: TUE, reason: 'Away',
        } as any);
        await leave().reviewLeave(request.id, f.workspace.id, f.hr.id, { approve: true } as any);

        await rollup().recomputeDay(f.workspace.id, TUE);

        const day = await testPrisma.attendanceDay.findFirstOrThrow({
            where: { userId: f.member.id },
        });
        expect(day.status).toBe('ON_LEAVE');
    });

    it('does not raise an ABSENT flag for a leave day', async () => {
        const f = await fixture();
        const request = await leave().requestLeave(f.workspace.id, f.member.id, {
            leaveTypeId: f.annual.id, startDate: TUE, endDate: TUE, reason: 'Away',
        } as any);
        await leave().reviewLeave(request.id, f.workspace.id, f.hr.id, { approve: true } as any);

        await rollup().recomputeDay(f.workspace.id, TUE);

        // Scoped to the member: HR is a tracked member too and was genuinely
        // absent that day, so a workspace-wide count would be about them.
        expect(await testPrisma.attendanceFlag.count({
            where: { type: 'ABSENT', userId: f.member.id },
        })).toBe(0);
    });
});

describe('overtime', () => {
    it('refuses a second live request for the same day', async () => {
        const f = await fixture();
        await peopleOps().requestOvertime(f.workspace.id, f.member.id, {
            businessDate: TUE, requestedMinutes: 120, reason: 'Deadline',
        } as any);

        await expect(
            peopleOps().requestOvertime(f.workspace.id, f.member.id, {
                businessDate: TUE, requestedMinutes: 60, reason: 'Again',
            } as any),
        ).rejects.toMatchObject({ statusCode: 409 });
    });

    it('lets an approver grant less than was asked for', async () => {
        const f = await fixture();
        const request = await peopleOps().requestOvertime(f.workspace.id, f.member.id, {
            businessDate: TUE, requestedMinutes: 180, reason: 'Deadline',
        } as any);

        const decided = await peopleOps().reviewOvertime(
            request.id, f.workspace.id, f.hr.id, { approve: true, approvedMinutes: 90 } as any,
        );

        expect(decided.approvedMinutes).toBe(90);
    });

    it('never grants more than was asked for', async () => {
        const f = await fixture();
        const request = await peopleOps().requestOvertime(f.workspace.id, f.member.id, {
            businessDate: TUE, requestedMinutes: 60, reason: 'Deadline',
        } as any);

        const decided = await peopleOps().reviewOvertime(
            request.id, f.workspace.id, f.hr.id, { approve: true, approvedMinutes: 600 } as any,
        );

        expect(decided.approvedMinutes).toBe(60);
    });

    it('measures overtime even when the workspace does not count it', async () => {
        // The whole point of keeping raw and counted apart: an approval weeks
        // later has something to turn into counted time.
        const f = await fixture();
        await testPrisma.workSession.create({
            data: {
                workspaceId: f.workspace.id,
                userId: f.member.id,
                clockIn: new Date(`${TUE}T06:00:00.000Z`),
                clockOut: new Date(`${TUE}T16:00:00.000Z`),
                businessDate: toDateColumn(TUE),
                status: 'CLOSED',
                totalMinutes: 600,
                workedMinutes: 600,
                rawOvertimeMinutes: 120,
                countedOvertimeMinutes: 0,
            },
        });

        await rollup().recomputeDay(f.workspace.id, TUE);
        let day = await testPrisma.attendanceDay.findFirstOrThrow({ where: { userId: f.member.id } });
        expect(day.rawOvertimeMinutes).toBe(120);
        expect(day.countedOvertimeMinutes).toBe(0);

        // Approve it retroactively, recompute, and the minutes now count.
        const request = await peopleOps().requestOvertime(f.workspace.id, f.member.id, {
            businessDate: TUE, type: 'RETROACTIVE', requestedMinutes: 120, reason: 'Deadline',
        } as any);
        await peopleOps().reviewOvertime(request.id, f.workspace.id, f.hr.id, { approve: true } as any);
        await rollup().recomputeDay(f.workspace.id, TUE);

        day = await testPrisma.attendanceDay.findFirstOrThrow({ where: { userId: f.member.id } });
        expect(day.countedOvertimeMinutes).toBe(120);
    });
});

describe('attendance flags', () => {
    it('raises ABSENT once, however many times the day is recomputed', async () => {
        const f = await fixture();

        await rollup().recomputeDay(f.workspace.id, TUE);
        await rollup().recomputeDay(f.workspace.id, TUE);
        await rollup().recomputeDay(f.workspace.id, TUE);

        expect(await testPrisma.attendanceFlag.count({
            where: { type: 'ABSENT', userId: f.member.id },
        })).toBe(1);
    });

    it('is waivable by an owner, with a reason on the record', async () => {
        const f = await fixture();
        await rollup().recomputeDay(f.workspace.id, TUE);
        const flag = await testPrisma.attendanceFlag.findFirstOrThrow();

        const waived = await peopleOps().waiveFlag(flag.id, f.workspace.id, f.owner.id, {
            reason: 'Approved absence agreed verbally',
        } as any);

        expect(waived.status).toBe('WAIVED');
        expect(waived.waiverReason).toBe('Approved absence agreed verbally');
        expect(waived.waivedById).toBe(f.owner.id);
    });

    it('is NOT waivable by HR — they own the policy', async () => {
        const f = await fixture();
        await rollup().recomputeDay(f.workspace.id, TUE);
        const flag = await testPrisma.attendanceFlag.findFirstOrThrow();

        await expect(
            peopleOps().waiveFlag(flag.id, f.workspace.id, f.hr.id, { reason: 'x' } as any),
        ).rejects.toMatchObject({ statusCode: 403 });
    });

    it('does not resurrect a waived flag on the next recompute', async () => {
        const f = await fixture();
        await rollup().recomputeDay(f.workspace.id, TUE);
        const flag = await testPrisma.attendanceFlag.findFirstOrThrow();
        await peopleOps().waiveFlag(flag.id, f.workspace.id, f.owner.id, { reason: 'Agreed' } as any);

        await rollup().recomputeDay(f.workspace.id, TUE);

        const flags = await testPrisma.attendanceFlag.findMany({
            where: { type: 'ABSENT', id: flag.id },
        });
        expect(flags).toHaveLength(1);
        expect(flags[0].status).toBe('WAIVED');
    });

    it('refuses a waiver with no reason, at the database', async () => {
        const f = await fixture();
        await rollup().recomputeDay(f.workspace.id, TUE);
        const flag = await testPrisma.attendanceFlag.findFirstOrThrow();

        await expect(
            testPrisma.attendanceFlag.update({
                where: { id: flag.id },
                data: { status: 'WAIVED', waivedAt: new Date() },
            }),
        ).rejects.toThrow(/attendance_flags_waived_consistently/);
    });
});

describe('work reports', () => {
    it('is auto-approved when the author could approve reports anyway', async () => {
        // Asking HR to rubber-stamp their own is theatre — but it is recorded
        // as auto-approved rather than silently, so the queue is honest.
        const f = await fixture();

        const report = await peopleOps().submitWorkReport(f.workspace.id, f.hr.id, {
            period: 'DAILY', periodStart: TUE, summary: 'Ran payroll',
        } as any);

        expect(report.status).toBe('APPROVED');
        expect(report.autoApproved).toBe(true);
    });

    it('waits for review when a member submits it', async () => {
        const f = await fixture();

        const report = await peopleOps().submitWorkReport(f.workspace.id, f.member.id, {
            period: 'DAILY', periodStart: TUE, summary: 'Fitted the panels',
        } as any);

        expect(report.status).toBe('PENDING');
        expect(report.autoApproved).toBe(false);
    });

    it('replaces rather than duplicating when resubmitted for the same period', async () => {
        const f = await fixture();
        await peopleOps().submitWorkReport(f.workspace.id, f.member.id, {
            period: 'DAILY', periodStart: TUE, summary: 'First draft',
        } as any);

        const second = await peopleOps().submitWorkReport(f.workspace.id, f.member.id, {
            period: 'DAILY', periodStart: TUE, summary: 'Corrected',
        } as any);

        expect(await testPrisma.workReport.count()).toBe(1);
        expect(second.summary).toBe('Corrected');
    });

    it('re-opens a report that was sent back', async () => {
        const f = await fixture();
        const report = await peopleOps().submitWorkReport(f.workspace.id, f.member.id, {
            period: 'DAILY', periodStart: TUE, summary: 'Thin',
        } as any);
        await peopleOps().reviewWorkReport(report.id, f.workspace.id, f.hr.id, {
            approve: false, reviewNote: 'Say what you actually did',
        } as any);

        const resubmitted = await peopleOps().submitWorkReport(f.workspace.id, f.member.id, {
            period: 'DAILY', periodStart: TUE, summary: 'Fitted the panels and tested them',
        } as any);

        expect(resubmitted.status).toBe('PENDING');
        expect(resubmitted.reviewNote).toBeNull();
    });

    it('snapshots the hours at submission', async () => {
        // So editing a time entry weeks later cannot change what was approved.
        const f = await fixture();
        await testPrisma.workSession.create({
            data: {
                workspaceId: f.workspace.id,
                userId: f.member.id,
                clockIn: new Date(`${TUE}T06:00:00.000Z`),
                clockOut: new Date(`${TUE}T14:00:00.000Z`),
                businessDate: toDateColumn(TUE),
                status: 'CLOSED',
                totalMinutes: 480,
                workedMinutes: 480,
            },
        });
        await rollup().recomputeDay(f.workspace.id, TUE);

        const report = await peopleOps().submitWorkReport(f.workspace.id, f.member.id, {
            period: 'DAILY', periodStart: TUE, summary: 'Full day',
        } as any);

        expect((report.metrics as any).workedMinutes).toBe(480);
    });

    it('lets exactly one of two simultaneous reviews through', async () => {
        const f = await fixture();
        const report = await peopleOps().submitWorkReport(f.workspace.id, f.member.id, {
            period: 'DAILY', periodStart: TUE, summary: 'Done',
        } as any);

        const results = await Promise.allSettled([
            peopleOps().reviewWorkReport(report.id, f.workspace.id, f.hr.id, { approve: true } as any),
            peopleOps().reviewWorkReport(report.id, f.workspace.id, f.owner.id, {
                approve: false, reviewNote: 'no',
            } as any),
        ]);

        expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    });
});

describe('flags are raised where they are earned, not only overnight', () => {
    /** A workspace whose shift started well before now, so arriving is late. */
    async function lateFixture() {
        const owner = await createUser();
        const workspace = await createWorkspace(owner.id);
        await testPrisma.attendanceSettings.create({ data: { workspaceId: workspace.id } });
        const member = await createUser();
        await addWorkspaceMember(workspace.id, member.id, WorkspaceRole.MEMBER);

        // Kampala is UTC+3, so 00:00 local is 21:00 the previous UTC day —
        // whatever the wall clock says now, a shift starting at 00:01 local
        // began hours ago.
        await testPrisma.workSchedule.create({
            data: {
                workspaceId: workspace.id,
                workingDays: [1, 2, 3, 4, 5, 6, 7],
                startTime: '00:01',
                endTime: '23:59',
                graceMinutes: 0,
                expectedMinutesPerDay: 480,
                effectiveFrom: toDateColumn('2026-01-01'),
            },
        });
        return { owner, workspace, member };
    }

    it('raises LATE_IN at clock-in, not at the nightly rollup', async () => {
        const f = await lateFixture();

        const session = await resolveService(TimeTrackingService)
            .clockIn(f.workspace.id, f.member.id, {});

        const flag = await testPrisma.attendanceFlag.findFirstOrThrow({
            where: { userId: f.member.id, type: 'LATE_IN' },
        });
        expect(flag.minutes).toBeGreaterThan(0);
        expect(session.clockOut).toBeNull();
    });

    it('measures lateness from the shift start plus grace, not the clock-in window', async () => {
        // The two used to be different numbers. Grace of 60 minutes must move
        // the figure by exactly 60.
        const f = await lateFixture();
        await testPrisma.workSchedule.updateMany({
            where: { workspaceId: f.workspace.id },
            data: { graceMinutes: 60 },
        });

        await resolveService(TimeTrackingService).clockIn(f.workspace.id, f.member.id, {});

        const flag = await testPrisma.attendanceFlag.findFirstOrThrow({
            where: { userId: f.member.id, type: 'LATE_IN' },
        });
        const withoutGrace = await testPrisma.workSession.findFirstOrThrow({
            where: { userId: f.member.id },
            select: { clockIn: true, scheduledStartUtc: true },
        });
        const rawLate = Math.floor(
            (withoutGrace.clockIn.getTime() - withoutGrace.scheduledStartUtc!.getTime()) / 60_000,
        );
        expect(flag.minutes).toBe(rawLate - 60);
    });

    it('does not flag a day nobody was expected on', async () => {
        const f = await lateFixture();
        await testPrisma.workSchedule.updateMany({
            where: { workspaceId: f.workspace.id },
            data: { workingDays: [] },
        });

        await resolveService(TimeTrackingService).clockIn(f.workspace.id, f.member.id, {});

        expect(await testPrisma.attendanceFlag.count({ where: { type: 'LATE_IN' } })).toBe(0);
    });

    it('raises EARLY_OUT at clock-out', async () => {
        const f = await lateFixture();
        // Earliest permitted clock-out is 23:58 local, so leaving now is early.
        await testPrisma.workSchedule.updateMany({
            where: { workspaceId: f.workspace.id },
            data: { clockOutWindowStart: '23:58' },
        });
        await resolveService(TimeTrackingService).clockIn(f.workspace.id, f.member.id, {});

        await resolveService(TimeTrackingService).clockOut(f.workspace.id, f.member.id, {
            earlyOutReason: 'Site closed',
        } as any);

        const flag = await testPrisma.attendanceFlag.findFirstOrThrow({
            where: { userId: f.member.id, type: 'EARLY_OUT' },
        });
        expect(flag.minutes).toBeGreaterThan(0);
        expect(flag.sessionId).not.toBeNull();
    });

    it('honours a workspace that has turned flags off', async () => {
        const f = await lateFixture();
        await testPrisma.attendanceSettings.update({
            where: { workspaceId: f.workspace.id },
            data: { flagsEnabled: false },
        });

        await resolveService(TimeTrackingService).clockIn(f.workspace.id, f.member.id, {});

        expect(await testPrisma.attendanceFlag.count()).toBe(0);
    });
});

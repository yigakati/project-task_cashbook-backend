/**
 * The attendance jobs, driven directly rather than through a timer.
 *
 * The behaviour that matters is what auto-close *credits*. Closing a forgotten
 * session at the moment the job happens to run would hand somebody a sixteen
 * hour day for a missed tap — and over-crediting is far harder to unpick than
 * under-crediting, because nobody audits hours that look generous.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { WorkspaceRole } from '@prisma/client';
import { resetDatabase, testPrisma } from '../setup';
import { __attendanceJobs } from '../../jobs/attendanceScheduler';
import { addWorkspaceMember, createUser, createWorkspace } from '../factories';
import { clearClockCache, toDateColumn } from '../../core/time/workspace-clock';

const { autoCloseForgottenSessions, sendWrapUpReminders } = __attendanceJobs;

async function fixture() {
    const owner = await createUser();
    const workspace = await createWorkspace(owner.id);
    await testPrisma.attendanceSettings.create({ data: { workspaceId: workspace.id } });
    const member = await createUser();
    await addWorkspaceMember(workspace.id, member.id, WorkspaceRole.MEMBER);
    return { owner, workspace, member };
}

/** An open session whose scheduled end is `hoursAgo` in the past. */
async function forgottenSession(
    workspaceId: string,
    userId: string,
    hoursAgo: number,
    workedHours = 8,
) {
    const scheduledEnd = new Date(Date.now() - hoursAgo * 3600_000);
    const clockIn = new Date(scheduledEnd.getTime() - workedHours * 3600_000);
    return testPrisma.workSession.create({
        data: {
            workspaceId,
            userId,
            clockIn,
            businessDate: toDateColumn(clockIn.toISOString().slice(0, 10)),
            status: 'OPEN',
            presenceStatus: 'WORKING',
            presenceChangedAt: clockIn,
            scheduledEndUtc: scheduledEnd,
            scheduledMinutes: workedHours * 60,
        },
    });
}

beforeEach(async () => {
    await resetDatabase();
    clearClockCache();
});

describe('auto-close', () => {
    it('leaves a session alone that is only just past its end', async () => {
        // Somebody working an hour late is not a forgotten clock-out.
        const f = await fixture();
        const session = await forgottenSession(f.workspace.id, f.member.id, 1);

        await autoCloseForgottenSessions();

        const after = await testPrisma.workSession.findUniqueOrThrow({ where: { id: session.id } });
        expect(after.clockOut).toBeNull();
        expect(after.status).toBe('OPEN');
    });

    it('closes one long past its end', async () => {
        const f = await fixture();
        const session = await forgottenSession(f.workspace.id, f.member.id, 6);

        await autoCloseForgottenSessions();

        const after = await testPrisma.workSession.findUniqueOrThrow({ where: { id: session.id } });
        expect(after.clockOut).not.toBeNull();
        expect(after.status).toBe('AUTO_CLOSED');
        expect(after.closureReason).toBe('FORGOTTEN_CLOCK_OUT');
    });

    it('credits the scheduled end, not the moment the job ran', async () => {
        // The assertion this whole job exists for: 8 hours, not 14.
        const f = await fixture();
        const session = await forgottenSession(f.workspace.id, f.member.id, 6, 8);

        await autoCloseForgottenSessions();

        const after = await testPrisma.workSession.findUniqueOrThrow({ where: { id: session.id } });
        expect(after.totalMinutes).toBe(480);
        expect(after.clockOut!.getTime()).toBe(session.scheduledEndUtc!.getTime());
    });

    it('clears presence and closes the open interval', async () => {
        const f = await fixture();
        const session = await forgottenSession(f.workspace.id, f.member.id, 6);
        await testPrisma.workSessionPresence.create({
            data: {
                sessionId: session.id,
                workspaceId: f.workspace.id,
                userId: f.member.id,
                status: 'WORKING',
                startedAt: session.clockIn,
            },
        });

        await autoCloseForgottenSessions();

        const after = await testPrisma.workSession.findUniqueOrThrow({ where: { id: session.id } });
        expect(after.presenceStatus).toBeNull();
        expect(await testPrisma.workSessionPresence.count({ where: { endedAt: null } })).toBe(0);
    });

    it('raises MISSED_CLOCK_OUT, once', async () => {
        const f = await fixture();
        await forgottenSession(f.workspace.id, f.member.id, 6);

        await autoCloseForgottenSessions();
        await autoCloseForgottenSessions();

        expect(await testPrisma.attendanceFlag.count({ where: { type: 'MISSED_CLOCK_OUT' } })).toBe(1);
    });

    it('does not overwrite a session the person closed themselves', async () => {
        // The race the conditional UPDATE exists for.
        const f = await fixture();
        const session = await forgottenSession(f.workspace.id, f.member.id, 6);
        const realClockOut = new Date();
        await testPrisma.workSession.update({
            where: { id: session.id },
            data: {
                clockOut: realClockOut,
                totalMinutes: 999,
                status: 'CLOSED',
                presenceStatus: null,
            },
        });

        await autoCloseForgottenSessions();

        const after = await testPrisma.workSession.findUniqueOrThrow({ where: { id: session.id } });
        expect(after.status).toBe('CLOSED');
        expect(after.totalMinutes).toBe(999);
        expect(after.clockOut!.getTime()).toBe(realClockOut.getTime());
    });

    it('closes a break that began after the session’s credited end at its own start', async () => {
        // The production incident: a lunch tap a few seconds PAST the
        // scheduled end, on a session somebody then forgot to clock out.
        // Ending that break at the credited end would write ended_at <
        // started_at — the work_session_presence_ordered CHECK rejects it,
        // and the tick died on this row every five minutes for weeks.
        const f = await fixture();
        const session = await forgottenSession(f.workspace.id, f.member.id, 6);
        const lateBreakStart = new Date(session.scheduledEndUtc!.getTime() + 14_000);
        await testPrisma.workSessionPresence.create({
            data: {
                sessionId: session.id,
                workspaceId: f.workspace.id,
                userId: f.member.id,
                status: 'LUNCH',
                startedAt: lateBreakStart,
            },
        });

        await autoCloseForgottenSessions();

        // The session closed at its scheduled end as always…
        const after = await testPrisma.workSession.findUniqueOrThrow({ where: { id: session.id } });
        expect(after.status).toBe('AUTO_CLOSED');
        expect(after.clockOut!.getTime()).toBe(session.scheduledEndUtc!.getTime());

        // …and the late break closed at its own start — never before it.
        const breakRow = await testPrisma.workSessionPresence.findFirstOrThrow({
            where: { sessionId: session.id },
        });
        expect(breakRow.endedAt).not.toBeNull();
        expect(breakRow.endedAt!.getTime()).toBeGreaterThanOrEqual(breakRow.startedAt.getTime());
        expect(breakRow.endedAt!.getTime()).toBe(lateBreakStart.getTime());
    });

    it('keeps sweeping when one session’s data cannot be closed cleanly', async () => {
        // Two forgotten sessions; the first carries the incident’s poisoned
        // shape. Before the clamp + per-session error boundary, the throw
        // aborted the whole sweep and the second session stayed open forever.
        const f = await fixture();
        const poisoned = await forgottenSession(f.workspace.id, f.member.id, 6);
        await testPrisma.workSessionPresence.create({
            data: {
                sessionId: poisoned.id,
                workspaceId: f.workspace.id,
                userId: f.member.id,
                status: 'LUNCH',
                startedAt: new Date(poisoned.scheduledEndUtc!.getTime() + 60_000),
            },
        });
        const healthy = await forgottenSession(f.workspace.id, f.owner.id, 7);

        const closed = await autoCloseForgottenSessions();

        expect(closed).toBe(2);
        const second = await testPrisma.workSession.findUniqueOrThrow({ where: { id: healthy.id } });
        expect(second.status).toBe('AUTO_CLOSED');
    });

    it('falls back to a ceiling when there is no schedule to measure against', async () => {
        const f = await fixture();
        const clockIn = new Date(Date.now() - 20 * 3600_000);
        const session = await testPrisma.workSession.create({
            data: {
                workspaceId: f.workspace.id,
                userId: f.member.id,
                clockIn,
                businessDate: toDateColumn(clockIn.toISOString().slice(0, 10)),
                status: 'OPEN',
                presenceStatus: 'AVAILABLE',
            },
        });

        await autoCloseForgottenSessions();

        const after = await testPrisma.workSession.findUniqueOrThrow({ where: { id: session.id } });
        expect(after.status).toBe('AUTO_CLOSED');
        // Default day, not the twenty hours actually elapsed.
        expect(after.totalMinutes).toBe(480);
    });
});

describe('wrap-up reminders', () => {
    /** An open session ending `minutesFromNow` in the future. */
    async function endingSoon(workspaceId: string, userId: string, minutesFromNow: number) {
        const scheduledEnd = new Date(Date.now() + minutesFromNow * 60_000);
        const clockIn = new Date(scheduledEnd.getTime() - 8 * 3600_000);
        return testPrisma.workSession.create({
            data: {
                workspaceId,
                userId,
                clockIn,
                businessDate: toDateColumn(clockIn.toISOString().slice(0, 10)),
                status: 'OPEN',
                presenceStatus: 'WORKING',
                scheduledEndUtc: scheduledEnd,
            },
        });
    }

    it('nudges somebody inside the window', async () => {
        const f = await fixture();
        await endingSoon(f.workspace.id, f.member.id, 15); // default lead is 30

        expect(await sendWrapUpReminders()).toBe(1);
    });

    it('says nothing when the end is still far off', async () => {
        const f = await fixture();
        await endingSoon(f.workspace.id, f.member.id, 180);

        expect(await sendWrapUpReminders()).toBe(0);
    });

    it('says nothing once the day is already over', async () => {
        // A reminder to wrap up two hours after you should have left is noise.
        const f = await fixture();
        await endingSoon(f.workspace.id, f.member.id, -120);

        expect(await sendWrapUpReminders()).toBe(0);
    });

    it('respects a workspace that has turned reminders off', async () => {
        const f = await fixture();
        await testPrisma.attendanceSettings.update({
            where: { workspaceId: f.workspace.id },
            data: { wrapUpReminderMinutes: 0 },
        });
        await endingSoon(f.workspace.id, f.member.id, 15);

        expect(await sendWrapUpReminders()).toBe(0);
    });

    it('ignores sessions that have already ended', async () => {
        const f = await fixture();
        const session = await endingSoon(f.workspace.id, f.member.id, 15);
        await testPrisma.workSession.update({
            where: { id: session.id },
            data: {
                clockOut: new Date(),
                totalMinutes: 60,
                status: 'CLOSED',
                presenceStatus: null,
            },
        });

        expect(await sendWrapUpReminders()).toBe(0);
    });
});

describe('only one replica runs a tick', () => {
    it('lets the second caller through only after the first finishes', async () => {
        // The advisory lock is what stops N replicas each notifying the same
        // person. Without it every instance would run every job every 5 minutes.
        const { withTickLock } = __attendanceJobs;
        const order: string[] = [];

        let releaseFirst: () => void = () => { };
        const firstHeld = new Promise<void>((resolve) => { releaseFirst = resolve; });

        const first = withTickLock(async () => {
            order.push('first-start');
            await firstHeld;
            order.push('first-end');
        });

        // Give the first a moment to take the lock.
        await new Promise((resolve) => setTimeout(resolve, 50));
        const secondRan = await withTickLock(async () => {
            order.push('second-ran');
        });

        expect(secondRan).toBe(false);
        expect(order).not.toContain('second-ran');

        releaseFirst();
        expect(await first).toBe(true);

        // Once released, the lock is available again.
        expect(await withTickLock(async () => { order.push('third-ran'); })).toBe(true);
        expect(order).toContain('third-ran');
    });
});

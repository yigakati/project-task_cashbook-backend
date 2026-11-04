/**
 * The lockout, and the four things that now prevent it.
 *
 * Before migration 0008 this sequence bricked an account:
 *
 *   1. Clock in to workspace A.
 *   2. Let the configured clock-out window pass.
 *   3. enforceAttendanceTimeWindow(policy, 'clock out') now refuses forever, so
 *      the session can never be closed.
 *   4. The one-open-session rule is GLOBAL, so that single row also blocks
 *      clocking in to every other organisation the person belongs to.
 *   5. There was no admin remedy short of editing the database.
 *
 * Every test here is a regression test for one leg of that. The invariant they
 * jointly encode: an open session always has at least one legal exit available
 * to the person it belongs to.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resetDatabase, testPrisma } from '../setup';
import { resolveService } from '../container';
import { TimeTrackingService } from '../../modules/time-tracking/time-tracking.service';
import { MembersService } from '../../modules/members/members.service';
import {
    addWorkspaceMember,
    createOpenWorkSession,
    createUser,
    createWorkspace,
    getWorkSession,
} from '../factories';
import { WorkspaceRole } from '@prisma/client';
import { clearClockCache } from '../../core/time/workspace-clock';

const service = () => resolveService(TimeTrackingService);
afterEach(() => vi.useRealTimers());

beforeEach(async () => {
    await resetDatabase();
    // The clock cache is process-global and keyed by workspace id; ids are
    // fresh per test, but clearing keeps a rewritten timezone from being stale.
    clearClockCache();
});

describe('a clock-out is never refused', () => {
    it('succeeds even when the clock-out window has long passed', async () => {
        const user = await createUser();
        // 06:00-07:00 local is over by any realistic test run time, and used to
        // be the exact configuration that trapped the session.
        const workspace = await createWorkspace(user.id, {
            attendanceClockOutStart: '06:00',
        });
        const session = await createOpenWorkSession(workspace.id, user.id, {
            clockIn: new Date(Date.now() - 3 * 60 * 60 * 1000),
        });

        const closed = await service().clockOut(workspace.id, user.id, {});

        expect(closed.id).toBe(session.id);
        expect(closed.clockOut).not.toBeNull();
        expect(closed.status).toBe('CLOSED');
    });

    it('records how early the departure was instead of blocking it', async () => {
        // Keep the session on today's business date even around midnight.
        vi.useFakeTimers({ toFake: ['Date'] });
        vi.setSystemTime(new Date('2026-11-04T09:00:00.000Z'));
        const user = await createUser();
        // 23:59 local: any clock-out today is "early".
        const workspace = await createWorkspace(user.id, {
            attendanceClockOutStart: '23:59',
        });
        await createOpenWorkSession(workspace.id, user.id, {
            clockIn: new Date(Date.now() - 60 * 60 * 1000),
        });

        const closed = await service().clockOut(workspace.id, user.id, {
            earlyOutReason: 'Site closed early',
        });

        expect(closed.clockOut).not.toBeNull();
        expect(closed.earlyOutReason).toBe('Site closed early');

        const audit = await testPrisma.auditLog.findFirstOrThrow({
            where: { resourceId: closed.id, action: 'WORK_SESSION_CLOCKED_OUT' },
        });
        expect((audit.details as any).minutesEarly).toBeGreaterThan(0);
    });

    it('does not block a clock-out from outside the geofence', async () => {
        // GPS drifts badly indoors, and someone who has already left the site
        // would otherwise be unable to close their session at all.
        const user = await createUser();
        const workspace = await createWorkspace(user.id, {
            attendanceLatitude: 0.3476,
            attendanceLongitude: 32.5825,
            attendanceRadiusMeters: 100,
        });
        await createOpenWorkSession(workspace.id, user.id);

        const closed = await service().clockOut(workspace.id, user.id, {
            latitude: 1.5, // ~128 km away
            longitude: 33.5,
        });

        expect(closed.clockOut).not.toBeNull();
        expect(closed.clockOutWithinGeofence).toBe(false);
    });

    it('still refuses a clock-IN from outside the geofence', async () => {
        // The relaxation is one-directional: arriving off-site is a real
        // policy violation with a trivial remedy (go to the site).
        const user = await createUser();
        const workspace = await createWorkspace(user.id, {
            attendanceLatitude: 0.3476,
            attendanceLongitude: 32.5825,
            attendanceRadiusMeters: 100,
        });

        await expect(
            service().clockIn(workspace.id, user.id, { latitude: 1.5, longitude: 33.5 }),
        ).rejects.toMatchObject({ code: 'OUTSIDE_ATTENDANCE_LOCATION' });
    });
});

describe('a late arrival is recorded, not refused', () => {
    it('allows clocking in after the window by default', async () => {
        const user = await createUser();
        // A window that closed at 00:01 local — arriving now is outside it.
        const workspace = await createWorkspace(user.id, {
            attendanceClockInStart: '00:00',
            attendanceClockInEnd: '00:01',
        });

        const session = await service().clockIn(workspace.id, user.id, {});

        // The point: the session exists. The window is about permission to
        // clock in, and being outside it does not refuse the attendance.
        expect(session.id).toBeTruthy();
        expect(session.clockOut).toBeNull();
    });

    it('does not treat "outside the window" as "late"', async () => {
        // These were once the same number, which gave the system two
        // contradictory definitions of lateness. Lateness is measured against
        // the SHIFT START plus its grace period — a workspace with a clock-in
        // window but no schedule has nothing to be late for. The measurement
        // itself is covered in people-ops.test.ts.
        const user = await createUser();
        const workspace = await createWorkspace(user.id, {
            attendanceClockInStart: '00:00',
            attendanceClockInEnd: '00:01',
        });

        await service().clockIn(workspace.id, user.id, {});

        expect(await testPrisma.attendanceFlag.count({ where: { type: 'LATE_IN' } })).toBe(0);
    });

    it('refuses only when the owner has opted into a hard door', async () => {
        const user = await createUser();
        const workspace = await createWorkspace(user.id, {
            attendanceClockInStart: '00:00',
            attendanceClockInEnd: '00:01',
            enforceClockWindows: true,
        });

        await expect(service().clockIn(workspace.id, user.id, {})).rejects.toMatchObject({
            code: 'OUTSIDE_ATTENDANCE_TIME_WINDOW',
        });
    });
});

describe('the cross-organisation lockout', () => {
    it('names the other workspace so the user knows where to go', async () => {
        const user = await createUser();
        const orgA = await createWorkspace(user.id, { name: 'Acme Ltd' });
        const orgB = await createWorkspace(user.id, { name: 'Beta Ltd' });
        await createOpenWorkSession(orgA.id, user.id);

        await expect(service().clockIn(orgB.id, user.id, {})).rejects.toThrow(/Acme Ltd/);
    });

    it('lets the person close their own session from anywhere and then clock in', async () => {
        const user = await createUser();
        const orgA = await createWorkspace(user.id, { name: 'Acme Ltd' });
        const orgB = await createWorkspace(user.id, { name: 'Beta Ltd' });
        const stuck = await createOpenWorkSession(orgA.id, user.id, {
            clockIn: new Date(Date.now() - 2 * 60 * 60 * 1000),
        });

        const closed = await service().closeMyOpenSession(user.id);
        expect(closed.id).toBe(stuck.id);
        expect(closed.closureReason).toBe('USER_SWITCH');
        expect(closed.totalMinutes).toBe(120);

        // Now unblocked.
        const fresh = await service().clockIn(orgB.id, user.id, {});
        expect(fresh.workspaceId).toBe(orgB.id);
    });

    it('reaches a session in a workspace whose own policy would trap it', async () => {
        // The compound failure: org A refuses clock-out AND blocks org B. The
        // escape hatch is person-scoped precisely so it works here.
        const user = await createUser();
        const orgA = await createWorkspace(user.id, {
            name: 'Trap Ltd',
            attendanceClockOutStart: '23:59',
            enforceClockWindows: true,
        });
        const orgB = await createWorkspace(user.id, { name: 'Beta Ltd' });
        await createOpenWorkSession(orgA.id, user.id);

        await service().closeMyOpenSession(user.id);
        await expect(service().clockIn(orgB.id, user.id, {})).resolves.toBeTruthy();
    });

    it('404s rather than inventing a session when nothing is open', async () => {
        const user = await createUser();
        await createWorkspace(user.id);
        await expect(service().closeMyOpenSession(user.id)).rejects.toMatchObject({
            statusCode: 404,
        });
    });
});

describe('losing membership does not strand the person', () => {
    it('closes the open session when a member is removed', async () => {
        // Otherwise the row survives in a workspace they can no longer reach,
        // and the global rule blocks them everywhere else forever.
        const owner = await createUser();
        const member = await createUser();
        const workspace = await createWorkspace(owner.id);
        await addWorkspaceMember(workspace.id, member.id, WorkspaceRole.MEMBER);
        const session = await createOpenWorkSession(workspace.id, member.id, {
            clockIn: new Date(Date.now() - 30 * 60 * 1000),
        });

        await resolveService(MembersService).removeMember(workspace.id, member.id, owner.id);

        const after = await getWorkSession(session.id);
        expect(after.clockOut).not.toBeNull();
        expect(after.status).toBe('ADMIN_CLOSED');
        expect(after.closureReason).toBe('MEMBERSHIP_ENDED');
        expect(after.closedById).toBe(owner.id);
    });

    it('lets them clock in elsewhere afterwards', async () => {
        const owner = await createUser();
        const member = await createUser();
        const orgA = await createWorkspace(owner.id);
        const orgB = await createWorkspace(member.id);
        await addWorkspaceMember(orgA.id, member.id, WorkspaceRole.MEMBER);
        await createOpenWorkSession(orgA.id, member.id);

        await resolveService(MembersService).removeMember(orgA.id, member.id, owner.id);

        await expect(service().clockIn(orgB.id, member.id, {})).resolves.toBeTruthy();
    });
});

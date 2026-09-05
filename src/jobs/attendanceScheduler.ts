/**
 * Attendance jobs: wrap-up reminders, auto-close, and the daily close.
 *
 * Unlike deadlineScheduler and maintenanceScheduler — which are documented as
 * safe on every replica because they are idempotent and silent — these notify
 * people and write flags. Two replicas ticking together would mean two pings to
 * the same person.
 *
 * So each tick takes a Postgres advisory lock first. Whichever replica wins runs
 * it; the others return immediately rather than queueing, because a tick done
 * five minutes late behind the winner is just the same work twice. The lock is
 * transaction-scoped, so it releases on commit and also if the process dies —
 * a crash cannot wedge the schedule. See `withTickLock` for why session-scoped
 * would have been wrong with a connection pool.
 *
 * That plus the deterministic `groupKey` on every notification means a duplicate
 * run still cannot produce a duplicate message. Belt and braces, because the
 * failure mode here is spamming users.
 *
 * Every workspace is evaluated in its OWN zone, which is why one global tick
 * works for tenants on different continents.
 */
import { PrismaClient, WorkSessionStatus } from '@prisma/client';
import { getPrismaClient } from '../config/database';
import { clockFor } from '../core/time/workspace-clock';
import { resolveSchedule } from '../core/time/schedule-resolver';
import { notificationsQueue } from '../config/queues';
import { logger } from '../utils/logger';

const prisma: PrismaClient = getPrismaClient();

/** How often to sweep. Fine-grained enough for a 30-minute wrap-up warning. */
const TICK_MS = 5 * 60 * 1000;

/** A session open this much past its scheduled end is a forgotten tap. */
const AUTO_CLOSE_GRACE_MINUTES = 240;

/** Absolute ceiling for a session with no schedule to measure against. */
const MAX_SESSION_MINUTES = 16 * 60;

const dispatch = (data: Record<string, unknown>) =>
    notificationsQueue.add(data.type as string, data).catch(() => { });

/**
 * Nudge people to wrap up and file their daily report.
 *
 * Fires once per session thanks to the groupKey — the tick may see the same
 * session in the window several times, and the notification upsert collapses
 * them onto one row rather than pinging every five minutes.
 */
async function sendWrapUpReminders(): Promise<number> {
    const open = await prisma.workSession.findMany({
        where: { clockOut: null, scheduledEndUtc: { not: null } },
        select: {
            id: true, userId: true, workspaceId: true, scheduledEndUtc: true,
            workspace: { select: { attendanceSettings: { select: { wrapUpReminderMinutes: true } } } },
        },
        take: 500,
    });

    const now = Date.now();
    let sent = 0;

    for (const session of open) {
        const lead = session.workspace.attendanceSettings?.wrapUpReminderMinutes ?? 30;
        if (lead <= 0) continue;

        const endsAt = session.scheduledEndUtc!.getTime();
        const windowOpens = endsAt - lead * 60_000;
        // Only inside the window, and not once the day is already over — a
        // reminder to wrap up two hours after you should have left is noise.
        if (now < windowOpens || now > endsAt) continue;

        await dispatch({
            userId: session.userId,
            workspaceId: session.workspaceId,
            type: 'ATTENDANCE_WRAP_UP',
            title: 'Your day is nearly over',
            body: 'Wrap up and submit your daily report before you clock out.',
            entityType: 'WORK_SESSION',
            entityId: session.id,
            groupKey: `wrapup:${session.id}`,
        });
        sent += 1;
    }
    return sent;
}

/**
 * Close sessions somebody forgot to end.
 *
 * Credits the SCHEDULED end, not the moment the job runs. Crediting run time
 * would hand out a sixteen-hour day for a forgotten tap, and over-crediting is
 * much harder to unpick than under-crediting — the person can ask for a
 * correction, but nobody audits hours that look generous.
 *
 * Each session is closed in its own error boundary: one poisoned row must not
 * wedge the sweep (it once did — a break started after the session's
 * scheduled end kept the whole tick failing every five minutes for weeks).
 */
async function autoCloseForgottenSessions(): Promise<number> {
    const cutoff = new Date(Date.now() - AUTO_CLOSE_GRACE_MINUTES * 60_000);
    const hardCutoff = new Date(Date.now() - MAX_SESSION_MINUTES * 60_000);

    const stale = await prisma.workSession.findMany({
        where: {
            clockOut: null,
            OR: [
                { scheduledEndUtc: { not: null, lt: cutoff } },
                // No schedule to measure against, so fall back to a ceiling.
                { scheduledEndUtc: null, clockIn: { lt: hardCutoff } },
            ],
        },
        select: {
            id: true, userId: true, workspaceId: true, clockIn: true,
            scheduledEndUtc: true, scheduledMinutes: true, businessDate: true,
        },
        take: 200,
    });

    let closed = 0;
    for (const session of stale) {
        const creditedEnd = session.scheduledEndUtc
            ?? new Date(session.clockIn.getTime() + (session.scheduledMinutes ?? 480) * 60_000);
        const minutes = Math.max(
            0,
            Math.floor((creditedEnd.getTime() - session.clockIn.getTime()) / 60_000),
        );

        try {
            // Conditional on still being open. If the person clocked out a
            // second ago, rowCount is 0 and this becomes a no-op rather than
            // overwriting their real clock-out with an invented one.
            const claimed = await prisma.$transaction(async (tx) => {
                // A break can legitimately have started after the session's
                // scheduled end (a lunch tap a few seconds past the bell on a
                // day somebody then forgot to close). Ending it at the
                // credited end would put ended_at before started_at, which the
                // work_session_presence_ordered CHECK forbids — so the break
                // is ended no earlier than it began, closing as a zero-length
                // break: minimal invention, correctable. (Done through the
                // Prisma API rather than SQL GREATEST because these columns
                // are naive timestamps; a timestamptz comparison would drag
                // the session timezone into it and shift the stored value.)
                const openBreak = await tx.workSessionPresence.findFirst({
                    where: { sessionId: session.id, endedAt: null },
                    select: { id: true, startedAt: true },
                });
                if (openBreak) {
                    await tx.workSessionPresence.update({
                        where: { id: openBreak.id },
                        data: {
                            endedAt: openBreak.startedAt > creditedEnd
                                ? openBreak.startedAt
                                : creditedEnd,
                        },
                    });
                }
                const result = await tx.workSession.updateMany({
                    where: { id: session.id, clockOut: null },
                    data: {
                        clockOut: creditedEnd,
                        totalMinutes: minutes,
                        workedMinutes: minutes,
                        status: WorkSessionStatus.AUTO_CLOSED,
                        presenceStatus: null,
                        autoClosedAt: new Date(),
                        closureReason: 'FORGOTTEN_CLOCK_OUT',
                    },
                });
                if (result.count === 0) return false;

                await tx.attendanceFlag.createMany({
                    data: [{
                        workspaceId: session.workspaceId,
                        userId: session.userId,
                        businessDate: session.businessDate,
                        type: 'MISSED_CLOCK_OUT',
                        sessionId: session.id,
                    }],
                    skipDuplicates: true,
                });
                return true;
            });

            if (!claimed) continue;

            await dispatch({
                userId: session.userId,
                workspaceId: session.workspaceId,
                type: 'SESSION_AUTO_CLOSED',
                title: 'We closed your session for you',
                body: 'You did not clock out, so the day was closed at your scheduled end time. Ask for a correction if that is wrong.',
                entityType: 'WORK_SESSION',
                entityId: session.id,
                groupKey: `autoclose:${session.id}`,
            });
            closed += 1;
        } catch (error) {
            // The sweep must survive any single session's data oddities — a
            // wedged tick stops every other session from ever auto-closing.
            logger.error('[Attendance] Auto-close failed for one session; continuing', {
                sessionId: session.id,
                error: (error as Error).message,
            });
        }
    }
    return closed;
}

/**
 * Roll up yesterday, once each workspace's local day is properly over.
 *
 * "Yesterday" is per workspace, which is the whole reason this runs every five
 * minutes rather than once at midnight: a single global 00:00 is the middle of
 * the afternoon somewhere.
 */
async function closeCompletedDays(): Promise<number> {
    const workspaces = await prisma.workspace.findMany({
        where: { isActive: true },
        select: { id: true },
        take: 500,
    });

    // Imported lazily: the scheduler is started from server.ts before the
    // container is necessarily warm, and the rollup pulls in the whole
    // attendance graph.
    const { AttendanceRollupService } = await import('../modules/attendance/rollup.service');
    const rollup = new AttendanceRollupService(prisma);

    let processed = 0;
    for (const workspace of workspaces) {
        try {
            const clock = await clockFor(prisma, workspace.id);
            const today = clock.businessDate(new Date());
            const yesterday = clock.addLocalDays(today, -1);

            // Only once the day is genuinely finished — a couple of hours past
            // local midnight, so late clock-outs are already in.
            const localTime = clock.localTime(new Date());
            if (localTime < '02:00' || localTime > '02:30') continue;

            await rollup.recomputeDay(workspace.id, yesterday);
            processed += 1;
        } catch (error) {
            // One misconfigured workspace must not stop the rest.
            logger.error('[Attendance] Daily close failed', {
                workspaceId: workspace.id,
                error: (error as Error).message,
            });
        }
    }
    return processed;
}

/**
 * A stable 64-bit key for the advisory lock.
 *
 * Any constant works as long as every replica agrees and nothing else uses it.
 */
const TICK_LOCK_KEY = 8531002477311004n;

/**
 * A tick has to finish inside this, since the lock is held by a transaction.
 * Generous: the work is bounded by the `take:` limits, so a tick that runs for
 * minutes means something is wrong and releasing the lock is the right outcome.
 */
const TICK_TIMEOUT_MS = 10 * 60 * 1000;

/**
 * Run `work` only if this process wins the lock.
 *
 * The lock is transaction-scoped (`pg_try_advisory_xact_lock`) rather than
 * session-scoped, and that is not a detail:
 *
 *  - Prisma pools connections. A session-scoped lock taken on connection A can
 *    have its `pg_advisory_unlock` routed to connection B, which does not hold
 *    it — the unlock quietly fails and A keeps the lock for the life of the
 *    process. The scheduler would then never tick again, silently.
 *  - Session locks are re-entrant, so two overlapping ticks in the SAME process
 *    would both be granted it and the mutex would do nothing locally.
 *
 * A transaction lock has neither problem: it is taken and released on one
 * connection, and it releases on commit, rollback, or the process dying.
 *
 * `try_` rather than the blocking form because a replica that loses should skip
 * the tick, not run it five minutes late behind the winner.
 */
async function withTickLock(work: () => Promise<void>): Promise<boolean> {
    let ran = false;

    await prisma.$transaction(async (tx) => {
        const [row] = await tx.$queryRaw<Array<{ locked: boolean }>>`
            SELECT pg_try_advisory_xact_lock(${TICK_LOCK_KEY}::bigint) AS locked
        `;
        if (!row?.locked) return;

        ran = true;
        // The transaction exists only to hold the lock; the jobs themselves run
        // on their own connections and commit independently, so a slow tick
        // does not turn into one enormous transaction.
        await work();
    }, { timeout: TICK_TIMEOUT_MS, maxWait: 10_000 });

    return ran;
}

async function tick(): Promise<void> {
    try {
        const ran = await withTickLock(async () => {
            const [reminders, closed, days] = await Promise.all([
                sendWrapUpReminders(),
                autoCloseForgottenSessions(),
                closeCompletedDays(),
            ]);
            if (reminders || closed || days) {
                logger.info('[Attendance] Tick complete', { reminders, closed, days });
            }
        });
        if (!ran) {
            logger.debug('[Attendance] Another replica holds the tick lock; skipping');
        }
    } catch (error) {
        logger.error('[Attendance] Tick failed', { error: (error as Error).message });
    }
}

export function startAttendanceScheduler(): NodeJS.Timeout {
    logger.info('[Attendance] Starting attendance scheduler (interval: 5 min)');
    void tick();
    return setInterval(tick, TICK_MS);
}

/** Exported for tests, which drive them directly rather than waiting on a timer. */
export const __attendanceJobs = {
    withTickLock,
    sendWrapUpReminders,
    autoCloseForgottenSessions,
    closeCompletedDays,
};

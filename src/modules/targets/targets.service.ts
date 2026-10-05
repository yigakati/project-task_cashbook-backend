import { injectable, inject } from 'tsyringe';
import {
    NotificationEntityType,
    NotificationType,
    Prisma,
    PrismaClient,
    TargetContributionKind,
    TargetMetric,
    TargetSource,
    WorkspaceType,
} from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import { DateTime } from 'luxon';
import { config } from '../../config';
import { sendEmail } from '../../config/email';
import { AppError, AuthorizationError, NotFoundError } from '../../core/errors/AppError';
import { AuditAction, WorkspaceRole } from '../../core/types';
import { WorkspacePermission, hasWorkspacePermission } from '../../core/types/workspace-permissions';
import { clockFor, toDateColumn } from '../../core/time/workspace-clock';
import { NotificationsService } from '../notifications/notifications.service';
import { targetAlertEmailTemplate } from '../../utils/emailTemplates';
import { logger } from '../../utils/logger';
import {
    BusinessDate,
    Progress,
    ProgressInput,
    cadenceOf,
    computeProgress,
    countWorkingDays,
    dailySeries,
    eachDate,
    isoWeekKey,
    isoWeekday,
    nextPeriod,
    resolvePreset,
} from './target-progress';
import {
    ContributionListQuery,
    CreateContributionDto,
    CreateTargetDto,
    TargetListQuery,
    UpdateContributionDto,
    UpdateTargetDto,
} from './targets.dto';

/** The longest period a target can span. */
const MAX_PERIOD_DAYS = 5 * 366;
/** Don't call anyone behind until a few working days have actually passed. */
const MIN_DAYS_BEFORE_BEHIND_ALERT = 3;
/** "Behind" means at least this far under where an even pace would be. */
const BEHIND_THRESHOLD = new Decimal('0.10');
/** Successive periods created in one pass, if the server was down a long time. */
const MAX_ROLLOVERS = 36;
/** Local hour (workspace time) from which the "record today's amount" reminder goes. */
const REMINDER_HOUR = 19;

const TARGET_INCLUDE = {
    cashbooks: { select: { cashbook: { select: { id: true, name: true } } } },
    assignee: { select: { id: true, firstName: true, lastName: true } },
    createdBy: { select: { id: true, firstName: true, lastName: true } },
} satisfies Prisma.TargetInclude;

type TargetRow = Prisma.TargetGetPayload<{ include: typeof TARGET_INCLUDE }>;

const CONTRIBUTION_INCLUDE = {
    recordedBy: { select: { id: true, firstName: true, lastName: true } },
} satisfies Prisma.TargetContributionInclude;

export interface Viewer {
    userId: string;
    role: WorkspaceRole | null | undefined;
}

const dateOf = (column: Date): BusinessDate => column.toISOString().slice(0, 10);
const minDate = (a: BusinessDate, b: BusinessDate) => (a < b ? a : b);
const maxDate = (a: BusinessDate, b: BusinessDate) => (a > b ? a : b);
const formatAmount = (value: string | Decimal, currency: string) =>
    `${currency} ${Number(value).toLocaleString('en-US', { maximumFractionDigits: 2 })}`;

/**
 * Targets: a goal over a period, and what it takes per day to get there.
 *
 * A target counts one of two things, fixed when it is set:
 *  - BOOKS: posted entries, computed every time it is asked for and never
 *    stored, so it always matches the books — an entry backdated, reversed or
 *    moved to another book changes the figures at once.
 *  - MANUAL: amounts recorded by hand against the target (contributions),
 *    for goals the books don't hold — savings, a side income, a fundraiser.
 * Either can start with an opening amount: money already raised before
 * tracking began, so a target picked up partway shares out only what's left.
 *
 * Who sees what:
 *  - A business target (no assignee) spans every book it covers, so seeing it
 *    takes ACCESS_ALL_CASHBOOKS — a sub-accountant limited to some books would
 *    otherwise learn the totals of books they cannot open.
 *  - A person's own target is visible to them, and to those who can see all books.
 *  - Setting, changing and archiving targets takes MANAGE_TARGETS.
 *  - On a hand-recorded target, the person it is for and anyone with
 *    MANAGE_TARGETS can record; a record can be changed by whoever made it
 *    or by a manager.
 */
@injectable()
export class TargetsService {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    // ─── Reading ───────────────────────────────────────

    async list(workspaceId: string, viewer: Viewer, query: TargetListQuery) {
        const { today, timezone } = await this.workspaceToday(workspaceId);
        const todayColumn = toDateColumn(today);
        const seesAll = this.seesAll(viewer);

        // Someone who cannot see every book only ever sees their own targets;
        // no filter in the query can widen that.
        const assigneeFilter: Prisma.TargetWhereInput = !seesAll || query.assignee === 'me'
            ? { assigneeId: viewer.userId }
            : query.assignee === 'business'
                ? { assigneeId: null }
                : query.assignee
                    ? { assigneeId: query.assignee }
                    : {};

        const where: Prisma.TargetWhereInput = {
            workspaceId,
            ...assigneeFilter,
            ...(query.status === 'archived'
                ? { archivedAt: { not: null } }
                : query.status === 'all'
                    ? {}
                    : {
                        archivedAt: null,
                        endDate: query.status === 'current' ? { gte: todayColumn } : { lt: todayColumn },
                    }),
        };

        // The viewer's own first, then whatever ends soonest. Fetched as two
        // slices so the limit can never cut the viewer's own targets for others'.
        const orderBy: Prisma.TargetOrderByWithRelationInput[] = [
            { endDate: query.status === 'ended' ? 'desc' : 'asc' },
            { createdAt: 'desc' },
        ];
        const mine = await this.prisma.target.findMany({
            where: { AND: [where, { assigneeId: viewer.userId }] },
            include: TARGET_INCLUDE,
            orderBy,
            take: query.limit,
        });
        const others = mine.length < query.limit
            ? await this.prisma.target.findMany({
                where: { AND: [where, { OR: [{ assigneeId: null }, { assigneeId: { not: viewer.userId } }] }] },
                include: TARGET_INCLUDE,
                orderBy,
                take: query.limit - mine.length,
            })
            : [];

        const data = await Promise.all([...mine, ...others].map(async (row) => ({
            ...this.toView(row, viewer, today),
            progress: await this.progressFor(row, today, timezone),
        })));
        return { data, today, canManage: hasWorkspacePermission(viewer.role, WorkspacePermission.MANAGE_TARGETS) };
    }

    async get(workspaceId: string, targetId: string, viewer: Viewer) {
        const row = await this.findVisible(workspaceId, targetId, viewer);
        const { today, timezone } = await this.workspaceToday(workspaceId);
        const daily = await this.dailyTotals(row, today, timezone);
        const input = this.progressInput(row, today, daily);
        return {
            ...this.toView(row, viewer, today),
            today,
            progress: computeProgress(input),
            series: dailySeries(input),
        };
    }

    // ─── Writing ───────────────────────────────────────

    async create(workspaceId: string, actorId: string, dto: CreateTargetDto) {
        const workspace = await this.workspace(workspaceId);
        const { today } = await this.workspaceToday(workspaceId);
        const period = dto.period.kind === 'preset'
            ? resolvePreset(dto.period.preset, today)
            : { startDate: dto.period.startDate, endDate: dto.period.endDate };

        const workingDays = [...new Set(dto.workingDays)].sort();
        this.assertPeriod(period.startDate, period.endDate, workingDays);
        this.assertSourceFields(dto.source, dto);
        await this.assertAssignee(workspace, dto.assigneeId);
        const cashbookIds = await this.validCashbookIds(workspaceId, dto.cashbookIds);
        const amount = new Decimal(dto.amount);
        const opening = this.resolveOpening(new Decimal(dto.openingAmount), dto.openingDate, null, period, today, amount);

        const target = await this.prisma.$transaction(async (tx) => {
            const created = await tx.target.create({
                data: {
                    workspaceId,
                    name: dto.name,
                    source: dto.source as TargetSource,
                    metric: dto.metric as TargetMetric,
                    amount,
                    currency: workspace.defaultCurrency,
                    startDate: toDateColumn(period.startDate),
                    endDate: toDateColumn(period.endDate),
                    workingDays,
                    assigneeId: dto.assigneeId,
                    openingAmount: opening.amount,
                    openingDate: opening.date ? toDateColumn(opening.date) : null,
                    repeats: dto.repeats,
                    alertsEnabled: dto.alertsEnabled,
                    emailAlerts: dto.emailAlerts,
                    remindToRecord: dto.remindToRecord,
                    createdById: actorId,
                    cashbooks: { create: cashbookIds.map((cashbookId) => ({ cashbookId })) },
                },
            });
            await tx.auditLog.create({
                data: {
                    userId: actorId,
                    workspaceId,
                    action: AuditAction.TARGET_CREATED,
                    resource: 'target',
                    resourceId: created.id,
                    details: {
                        name: dto.name, source: dto.source, amount: dto.amount, openingAmount: dto.openingAmount, ...period,
                    } as Prisma.InputJsonValue,
                },
            });
            return created;
        });

        return this.get(workspaceId, target.id, { userId: actorId, role: WorkspaceRole.OWNER });
    }

    async update(workspaceId: string, targetId: string, actorId: string, dto: UpdateTargetDto) {
        const existing = await this.prisma.target.findFirst({ where: { id: targetId, workspaceId } });
        if (!existing) throw new NotFoundError('Target');
        const workspace = await this.workspace(workspaceId);
        const { today } = await this.workspaceToday(workspaceId);

        const period = dto.period
            ? dto.period.kind === 'preset'
                ? resolvePreset(dto.period.preset, today)
                : { startDate: dto.period.startDate, endDate: dto.period.endDate }
            : { startDate: dateOf(existing.startDate), endDate: dateOf(existing.endDate) };
        const workingDays = dto.workingDays ? [...new Set(dto.workingDays)].sort() : existing.workingDays;
        this.assertPeriod(period.startDate, period.endDate, workingDays);
        this.assertSourceFields(existing.source, dto);
        if (dto.assigneeId !== undefined) await this.assertAssignee(workspace, dto.assigneeId);
        const cashbookIds = dto.cashbookIds ? await this.validCashbookIds(workspaceId, dto.cashbookIds) : null;

        const amount = dto.amount !== undefined ? new Decimal(dto.amount) : new Decimal(existing.amount);
        const openingTouched = dto.openingAmount !== undefined || dto.openingDate !== undefined || dto.period !== undefined;
        const opening = this.resolveOpening(
            dto.openingAmount !== undefined ? new Decimal(dto.openingAmount) : new Decimal(existing.openingAmount),
            dto.openingDate,
            existing.openingDate ? dateOf(existing.openingDate) : null,
            period,
            today,
            amount,
        );
        if (existing.source === TargetSource.MANUAL && (openingTouched || dto.period)) {
            await this.assertRecordsFit(targetId, period, opening.amount.gt(0) ? opening.date : null);
        }

        // A changed goal is a new question: earlier "reached" and "behind"
        // alerts no longer apply to it.
        const goalChanged = dto.amount !== undefined || dto.period !== undefined || dto.metric !== undefined
            || dto.workingDays !== undefined || dto.cashbookIds !== undefined || dto.assigneeId !== undefined
            || dto.openingAmount !== undefined || dto.openingDate !== undefined;

        await this.prisma.$transaction(async (tx) => {
            await tx.target.update({
                where: { id: targetId },
                data: {
                    ...(dto.name !== undefined && { name: dto.name }),
                    ...(dto.metric !== undefined && { metric: dto.metric as TargetMetric }),
                    ...(dto.amount !== undefined && { amount }),
                    ...(dto.period && {
                        startDate: toDateColumn(period.startDate),
                        endDate: toDateColumn(period.endDate),
                    }),
                    ...(dto.workingDays && { workingDays }),
                    ...(dto.assigneeId !== undefined && { assigneeId: dto.assigneeId }),
                    ...(openingTouched && {
                        openingAmount: opening.amount,
                        openingDate: opening.date ? toDateColumn(opening.date) : null,
                    }),
                    ...(dto.repeats !== undefined && { repeats: dto.repeats }),
                    ...(dto.alertsEnabled !== undefined && { alertsEnabled: dto.alertsEnabled }),
                    ...(dto.emailAlerts !== undefined && { emailAlerts: dto.emailAlerts }),
                    ...(dto.remindToRecord !== undefined && { remindToRecord: dto.remindToRecord }),
                    ...(goalChanged && { achievedAt: null, lastBehindAlertWeek: null, endedNotifiedAt: null }),
                },
            });
            if (cashbookIds) {
                await tx.targetCashbook.deleteMany({ where: { targetId } });
                await tx.targetCashbook.createMany({ data: cashbookIds.map((cashbookId) => ({ targetId, cashbookId })) });
            }
            await tx.auditLog.create({
                data: {
                    userId: actorId,
                    workspaceId,
                    action: AuditAction.TARGET_UPDATED,
                    resource: 'target',
                    resourceId: targetId,
                    details: dto as unknown as Prisma.InputJsonValue,
                },
            });
        });

        return this.get(workspaceId, targetId, { userId: actorId, role: WorkspaceRole.OWNER });
    }

    async setArchived(workspaceId: string, targetId: string, actorId: string, archive: boolean) {
        const existing = await this.prisma.target.findFirst({ where: { id: targetId, workspaceId } });
        if (!existing) throw new NotFoundError('Target');

        if (Boolean(existing.archivedAt) !== archive) {
            await this.prisma.target.update({
                where: { id: targetId },
                data: { archivedAt: archive ? new Date() : null },
            });
            await this.prisma.auditLog.create({
                data: {
                    userId: actorId,
                    workspaceId,
                    action: archive ? AuditAction.TARGET_ARCHIVED : AuditAction.TARGET_RESTORED,
                    resource: 'target',
                    resourceId: targetId,
                },
            });
        }
        return this.get(workspaceId, targetId, { userId: actorId, role: WorkspaceRole.OWNER });
    }

    /** Targets hold no financial records, so a mistaken one can simply go. */
    async remove(workspaceId: string, targetId: string, actorId: string) {
        const existing = await this.prisma.target.findFirst({ where: { id: targetId, workspaceId } });
        if (!existing) throw new NotFoundError('Target');
        await this.prisma.target.delete({ where: { id: targetId } });
        await this.prisma.auditLog.create({
            data: {
                userId: actorId,
                workspaceId,
                action: AuditAction.TARGET_DELETED,
                resource: 'target',
                resourceId: targetId,
                details: { name: existing.name } as Prisma.InputJsonValue,
            },
        });
    }

    // ─── Hand-recorded amounts ─────────────────────────

    async listContributions(workspaceId: string, targetId: string, viewer: Viewer, query: ContributionListQuery) {
        const target = await this.findVisible(workspaceId, targetId, viewer);
        if (target.source !== TargetSource.MANUAL) return { data: [], nextCursor: null };

        const rows = await this.prisma.targetContribution.findMany({
            where: { targetId },
            include: CONTRIBUTION_INCLUDE,
            orderBy: [{ date: 'desc' }, { createdAt: 'desc' }, { id: 'desc' }],
            take: query.limit + 1,
            ...(query.cursor && { cursor: { id: query.cursor }, skip: 1 }),
        });
        const page = rows.slice(0, query.limit);
        return {
            data: page.map((row) => this.toContributionView(row, target, viewer)),
            nextCursor: rows.length > query.limit ? page[page.length - 1].id : null,
        };
    }

    async recordContribution(workspaceId: string, targetId: string, viewer: Viewer, dto: CreateContributionDto) {
        const target = await this.findVisible(workspaceId, targetId, viewer);
        this.assertCanRecord(target, viewer);
        const { today } = await this.workspaceToday(workspaceId);
        this.assertRecordDate(target, dto.date, today);

        const created = await this.prisma.$transaction(async (tx) => {
            await this.lockTarget(tx, targetId);
            const row = await tx.targetContribution.create({
                data: {
                    targetId,
                    date: toDateColumn(dto.date),
                    kind: dto.kind as TargetContributionKind,
                    amount: new Decimal(dto.amount),
                    note: dto.note || null,
                    recordedById: viewer.userId,
                },
                include: CONTRIBUTION_INCLUDE,
            });
            await this.assertNotOverdrawn(tx, target);
            await tx.auditLog.create({
                data: {
                    userId: viewer.userId,
                    workspaceId,
                    action: AuditAction.TARGET_CONTRIBUTION_RECORDED,
                    resource: 'target_contribution',
                    resourceId: row.id,
                    details: { targetId, date: dto.date, kind: dto.kind, amount: dto.amount } as Prisma.InputJsonValue,
                },
            });
            return row;
        });
        return this.toContributionView(created, target, viewer);
    }

    async updateContribution(
        workspaceId: string, targetId: string, contributionId: string, viewer: Viewer, dto: UpdateContributionDto,
    ) {
        const target = await this.findVisible(workspaceId, targetId, viewer);
        const existing = await this.editableContribution(target, contributionId, viewer);
        const { today } = await this.workspaceToday(workspaceId);
        if (dto.date !== undefined) this.assertRecordDate(target, dto.date, today);

        const updated = await this.prisma.$transaction(async (tx) => {
            await this.lockTarget(tx, targetId);
            const row = await tx.targetContribution.update({
                where: { id: existing.id },
                data: {
                    ...(dto.date !== undefined && { date: toDateColumn(dto.date) }),
                    ...(dto.kind !== undefined && { kind: dto.kind as TargetContributionKind }),
                    ...(dto.amount !== undefined && { amount: new Decimal(dto.amount) }),
                    ...(dto.note !== undefined && { note: dto.note || null }),
                },
                include: CONTRIBUTION_INCLUDE,
            });
            await this.assertNotOverdrawn(tx, target);
            await tx.auditLog.create({
                data: {
                    userId: viewer.userId,
                    workspaceId,
                    action: AuditAction.TARGET_CONTRIBUTION_UPDATED,
                    resource: 'target_contribution',
                    resourceId: row.id,
                    details: {
                        targetId,
                        before: {
                            date: dateOf(existing.date), kind: existing.kind, amount: existing.amount.toString(), note: existing.note,
                        },
                        after: dto,
                    } as unknown as Prisma.InputJsonValue,
                },
            });
            return row;
        });
        return this.toContributionView(updated, target, viewer);
    }

    async deleteContribution(workspaceId: string, targetId: string, contributionId: string, viewer: Viewer) {
        const target = await this.findVisible(workspaceId, targetId, viewer);
        const existing = await this.editableContribution(target, contributionId, viewer);

        await this.prisma.$transaction(async (tx) => {
            await this.lockTarget(tx, targetId);
            await tx.targetContribution.delete({ where: { id: existing.id } });
            await this.assertNotOverdrawn(tx, target);
            await tx.auditLog.create({
                data: {
                    userId: viewer.userId,
                    workspaceId,
                    action: AuditAction.TARGET_CONTRIBUTION_DELETED,
                    resource: 'target_contribution',
                    resourceId: existing.id,
                    details: {
                        targetId, date: dateOf(existing.date), kind: existing.kind, amount: existing.amount.toString(), note: existing.note,
                    } as Prisma.InputJsonValue,
                },
            });
        });
    }

    // ─── Scheduled: repeating periods, alerts and reminders ───

    /**
     * Start the next period of every repeating target whose period is over,
     * then send whatever alerts and reminders are due. Safe to run on every
     * replica: each step claims its work with a conditional update first.
     */
    async processScheduled(now = new Date()) {
        const rolled = await this.rollOver(now);
        const alerted = await this.sendAlerts(now);
        const reminded = await this.sendReminders(now);
        return { rolled, alerted, reminded };
    }

    async rollOver(now = new Date()): Promise<number> {
        const candidates = await this.prisma.target.findMany({
            where: {
                repeats: true,
                archivedAt: null,
                next: null,
                endDate: { lt: toDateColumn(new Date(now.getTime() + 86_400_000).toISOString().slice(0, 10)) },
            },
            include: { cashbooks: true },
        });

        let created = 0;
        for (let current of candidates) {
            const clock = await clockFor(this.prisma, current.workspaceId);
            const today = clock.businessDate(now);

            for (let i = 0; i < MAX_ROLLOVERS && dateOf(current.endDate) < today; i++) {
                // Same shape as the period before: a month follows a month, a week a week.
                const period = nextPeriod(dateOf(current.startDate), dateOf(current.endDate));
                try {
                    const next = await this.prisma.target.create({
                        data: {
                            workspaceId: current.workspaceId,
                            name: current.name,
                            source: current.source,
                            metric: current.metric,
                            amount: current.amount,
                            currency: current.currency,
                            startDate: toDateColumn(period.startDate),
                            endDate: toDateColumn(period.endDate),
                            workingDays: current.workingDays,
                            assigneeId: current.assigneeId,
                            // Each period starts from nothing: the opening amount belonged to the first.
                            repeats: true,
                            previousId: current.id,
                            alertsEnabled: current.alertsEnabled,
                            emailAlerts: current.emailAlerts,
                            remindToRecord: current.remindToRecord,
                            createdById: current.createdById,
                            cashbooks: { create: current.cashbooks.map((c) => ({ cashbookId: c.cashbookId })) },
                        },
                        include: { cashbooks: true },
                    });
                    created += 1;
                    current = next;
                } catch (error) {
                    // Another replica rolled this one over first (previousId is unique).
                    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') break;
                    throw error;
                }
            }
        }
        return created;
    }

    async sendAlerts(now = new Date()): Promise<number> {
        const targets = await this.prisma.target.findMany({
            where: { archivedAt: null, alertsEnabled: true, endedNotifiedAt: null, startDate: { lte: now } },
            include: TARGET_INCLUDE,
        });

        let sent = 0;
        for (const target of targets) {
            try {
                sent += await this.alertOne(target, now);
            } catch (error) {
                logger.error('[Targets] Alert check failed', { targetId: target.id, error: (error as Error).message });
            }
        }
        return sent;
    }

    private async alertOne(target: TargetRow, now: Date): Promise<number> {
        const { today, timezone } = await this.workspaceToday(target.workspaceId, now);
        const progress = await this.progressFor(target, today, timezone);
        const money = (value: string) => formatAmount(value, target.currency);
        const ended = today > dateOf(target.endDate);

        if (ended) {
            const claimed = await this.prisma.target.updateMany({
                where: { id: target.id, endedNotifiedAt: null },
                data: {
                    endedNotifiedAt: now,
                    ...(progress.status === 'ACHIEVED' && !target.achievedAt && { achievedAt: now }),
                },
            });
            if (claimed.count === 0) return 0;
            const hit = progress.status === 'ACHIEVED';
            return this.notify(target, NotificationType.TARGET_ENDED, `target:${target.id}:ended`, {
                title: hit ? `Target reached: ${target.name}` : `Target period ended: ${target.name}`,
                body: `${hit ? 'You reached' : 'The period ended at'} ${money(progress.achieved)} of `
                    + `${money(target.amount.toString())} (${progress.percent}%).`
                    + (target.repeats ? ' The next period has started.' : ''),
            }, true);
        }

        if (progress.status === 'ACHIEVED') {
            const claimed = await this.prisma.target.updateMany({
                where: { id: target.id, achievedAt: null },
                data: { achievedAt: now },
            });
            if (claimed.count === 0) return 0;
            return this.notify(target, NotificationType.TARGET_ACHIEVED, `target:${target.id}:achieved`, {
                title: `Target reached: ${target.name}`,
                body: `You've reached ${money(progress.achieved)} of ${money(target.amount.toString())} `
                    + `with ${progress.workingDaysLeft} working day${progress.workingDaysLeft === 1 ? '' : 's'} to spare.`,
            }, true);
        }

        const behind = new Decimal(progress.paceDifference).negated();
        const expected = new Decimal(progress.expectedToDate);
        // Counted from when tracking began: a target picked up partway gets a
        // few days of its own before being called behind.
        const isBehind = progress.status === 'ACTIVE'
            && progress.workingDaysTracked >= MIN_DAYS_BEFORE_BEHIND_ALERT
            && behind.gt(0)
            && behind.gte(expected.mul(BEHIND_THRESHOLD));
        if (!isBehind) return 0;

        const week = isoWeekKey(today);
        const claimed = await this.prisma.target.updateMany({
            where: { id: target.id, OR: [{ lastBehindAlertWeek: null }, { lastBehindAlertWeek: { not: week } }] },
            data: { lastBehindAlertWeek: week },
        });
        if (claimed.count === 0) return 0;

        const perDay = progress.todayTarget && progress.isWorkingDayToday
            ? progress.todayTarget
            : progress.neededPerDayFromTomorrow ?? progress.remaining;
        return this.notify(target, NotificationType.TARGET_BEHIND, `target:${target.id}:behind:${week}`, {
            title: `Behind pace: ${target.name}`,
            body: `You're ${money(behind.toFixed(2))} behind pace. To reach ${money(target.amount.toString())} `
                + `by ${dateOf(target.endDate)}, you now need about ${money(perDay)} per working day.`,
        }, false);
    }

    /**
     * The evening nudge for hand-recorded targets: on a counted day, from
     * REMINDER_HOUR workspace time, if nothing has been recorded today and the
     * target isn't reached yet. At most one a day per target.
     */
    async sendReminders(now = new Date()): Promise<number> {
        const candidates = await this.prisma.target.findMany({
            where: {
                source: TargetSource.MANUAL,
                remindToRecord: true,
                archivedAt: null,
                // A day either side covers every timezone; exact checks follow.
                startDate: { lte: new Date(now.getTime() + 86_400_000) },
                endDate: { gte: new Date(now.getTime() - 86_400_000) },
            },
            include: TARGET_INCLUDE,
        });

        let sent = 0;
        for (const target of candidates) {
            try {
                sent += await this.remindOne(target, now);
            } catch (error) {
                logger.error('[Targets] Reminder failed', { targetId: target.id, error: (error as Error).message });
            }
        }
        return sent;
    }

    private async remindOne(target: TargetRow, now: Date): Promise<number> {
        const { today, timezone } = await this.workspaceToday(target.workspaceId, now);
        if (DateTime.fromJSDate(now, { zone: timezone }).hour < REMINDER_HOUR) return 0;
        if (today < dateOf(target.startDate) || today > dateOf(target.endDate)) return 0;
        if (!target.workingDays.includes(isoWeekday(today))) return 0;
        if (target.lastReminderDate && dateOf(target.lastReminderDate) === today) return 0;

        const recordedToday = await this.prisma.targetContribution.count({
            where: { targetId: target.id, date: toDateColumn(today) },
        });
        if (recordedToday > 0) return 0;
        const progress = await this.progressFor(target, today, timezone);
        if (progress.status !== 'ACTIVE') return 0;

        const claimed = await this.prisma.target.updateMany({
            where: {
                id: target.id,
                OR: [{ lastReminderDate: null }, { lastReminderDate: { not: toDateColumn(today) } }],
            },
            data: { lastReminderDate: toDateColumn(today) },
        });
        if (claimed.count === 0) return 0;

        const money = (value: string) => formatAmount(value, target.currency);
        return this.notify(target, NotificationType.TARGET_REMINDER, `target:${target.id}:reminder:${today}`, {
            title: `Record today's amount: ${target.name}`,
            body: `Nothing is recorded for today yet. Today needs ${money(progress.todayTarget ?? '0')} `
                + `to stay on track for ${money(target.amount.toString())}.`,
        }, false);
    }

    /**
     * Tell the people a target concerns. A person's own target: them, and for
     * the outcome also whoever set it. A business target: whoever set it and
     * the workspace owner. Only people still in the workspace.
     */
    private async notify(
        target: TargetRow,
        type: NotificationType,
        groupKey: string,
        message: { title: string; body: string },
        includeSetter: boolean,
    ): Promise<number> {
        const workspace = await this.prisma.workspace.findUniqueOrThrow({
            where: { id: target.workspaceId },
            select: { ownerId: true },
        });
        const ids = new Set<string>();
        if (target.assigneeId) {
            ids.add(target.assigneeId);
            if (includeSetter) ids.add(target.createdById);
        } else {
            ids.add(target.createdById);
            ids.add(workspace.ownerId);
        }

        const recipients = await this.prisma.user.findMany({
            where: {
                id: { in: [...ids] },
                isActive: true,
                deletedAt: null,
                OR: [
                    { id: workspace.ownerId },
                    { workspaceMemberships: { some: { workspaceId: target.workspaceId } } },
                ],
            },
            select: { id: true, email: true, firstName: true },
        });

        for (const user of recipients) {
            NotificationsService.dispatch({
                type,
                userId: user.id,
                workspaceId: target.workspaceId,
                title: message.title,
                body: message.body,
                entityType: NotificationEntityType.TARGET,
                entityId: target.id,
                groupKey,
            });
            if (target.emailAlerts) {
                try {
                    await sendEmail({
                        to: user.email,
                        subject: message.title,
                        html: targetAlertEmailTemplate({
                            firstName: user.firstName,
                            ...message,
                            url: `${config.APP_URL.replace(/\/+$/, '')}/targets?open=${target.id}`,
                        }),
                    });
                } catch (error) {
                    logger.error('[Targets] Alert email failed', { targetId: target.id, error: (error as Error).message });
                }
            }
        }
        return recipients.length;
    }

    // ─── Internals ─────────────────────────────────────

    private seesAll(viewer: Viewer) {
        return hasWorkspacePermission(viewer.role, WorkspacePermission.ACCESS_ALL_CASHBOOKS);
    }

    private async findVisible(workspaceId: string, targetId: string, viewer: Viewer) {
        const row = await this.prisma.target.findFirst({
            where: { id: targetId, workspaceId },
            include: TARGET_INCLUDE,
        });
        // Not found and not allowed answer the same, so ids cannot be probed.
        if (!row || (!this.seesAll(viewer) && row.assigneeId !== viewer.userId)) {
            throw new NotFoundError('Target');
        }
        return row;
    }

    private async workspace(workspaceId: string) {
        const workspace = await this.prisma.workspace.findUnique({
            where: { id: workspaceId },
            select: { id: true, type: true, ownerId: true, defaultCurrency: true, isActive: true },
        });
        if (!workspace || !workspace.isActive) throw new NotFoundError('Workspace');
        return workspace;
    }

    private async workspaceToday(workspaceId: string, now = new Date()) {
        const [clock, workspace] = await Promise.all([
            clockFor(this.prisma, workspaceId),
            this.prisma.workspace.findUnique({ where: { id: workspaceId }, select: { timezone: true } }),
        ]);
        return { today: clock.businessDate(now), timezone: workspace?.timezone ?? 'Africa/Kampala' };
    }

    private assertPeriod(startDate: BusinessDate, endDate: BusinessDate, workingDays: number[]) {
        const days = eachDate(startDate, endDate).length;
        if (days === 0) throw new AppError('The end date must be on or after the start date.', 400, 'INVALID_PERIOD');
        if (days > MAX_PERIOD_DAYS) throw new AppError('A target can cover at most five years.', 400, 'INVALID_PERIOD');
        if (countWorkingDays(startDate, endDate, workingDays) === 0) {
            throw new AppError('None of the chosen days fall inside this period.', 400, 'NO_WORKING_DAYS');
        }
    }

    /** Fields that only make sense for one source are refused on the other, not silently dropped. */
    private assertSourceFields(
        source: TargetSource | 'BOOKS' | 'MANUAL',
        dto: { metric?: string; cashbookIds?: string[]; remindToRecord?: boolean },
    ) {
        if (source === TargetSource.MANUAL) {
            if (dto.metric === TargetMetric.NET) {
                throw new AppError('A target you record by hand counts what you record; money in vs net is for book targets.', 400, 'INVALID_SOURCE_FIELD');
            }
            if (dto.cashbookIds && dto.cashbookIds.length > 0) {
                throw new AppError("A target you record by hand isn't linked to any book.", 400, 'INVALID_SOURCE_FIELD');
            }
        } else if (dto.remindToRecord) {
            throw new AppError('Reminders are for targets you record by hand; book targets move as entries are recorded.', 400, 'INVALID_SOURCE_FIELD');
        }
    }

    /**
     * The opening amount and the day it is in hand from. The day defaults to
     * today (or keeps its earlier value), held within the period and never
     * after today — it's money already raised, not money expected.
     */
    private resolveOpening(
        amount: Decimal,
        requestedDate: BusinessDate | undefined,
        existingDate: BusinessDate | null,
        period: { startDate: BusinessDate; endDate: BusinessDate },
        today: BusinessDate,
        target: Decimal,
    ): { amount: Decimal; date: BusinessDate | null } {
        if (amount.lte(0)) return { amount: new Decimal(0), date: null };
        if (amount.gte(target)) {
            throw new AppError('The amount already raised covers the whole target. Set a bigger target, or leave it out.', 400, 'INVALID_OPENING');
        }
        const latest = minDate(period.endDate, maxDate(today, period.startDate));
        if (requestedDate) {
            if (requestedDate < period.startDate || requestedDate > latest) {
                throw new AppError('The "already raised" date must be inside the period and not after today.', 400, 'INVALID_OPENING');
            }
            return { amount, date: requestedDate };
        }
        return { amount, date: maxDate(period.startDate, minDate(existingDate ?? today, latest)) };
    }

    /** On a hand-recorded target, a new period or opening date mustn't strand earlier records. */
    private async assertRecordsFit(
        targetId: string,
        period: { startDate: BusinessDate; endDate: BusinessDate },
        openingDate: BusinessDate | null,
    ) {
        const from = openingDate ?? period.startDate;
        const outside = await this.prisma.targetContribution.count({
            where: {
                targetId,
                OR: [{ date: { lt: toDateColumn(from) } }, { date: { gt: toDateColumn(period.endDate) } }],
            },
        });
        if (outside > 0) {
            throw new AppError(
                `${outside} recorded amount${outside === 1 ? '' : 's'} would fall outside the period`
                + `${openingDate ? ' or before the "already raised" date' : ''}. Move or delete ${outside === 1 ? 'it' : 'them'} first.`,
                400,
                'RECORDS_OUTSIDE_PERIOD',
            );
        }
    }

    private canRecord(target: { source: TargetSource; archivedAt: Date | null; assigneeId: string | null }, viewer: Viewer) {
        return target.source === TargetSource.MANUAL
            && !target.archivedAt
            && (target.assigneeId === viewer.userId || hasWorkspacePermission(viewer.role, WorkspacePermission.MANAGE_TARGETS));
    }

    private assertCanRecord(target: TargetRow, viewer: Viewer) {
        if (target.source !== TargetSource.MANUAL) {
            throw new AppError('This target counts the books. Record an entry in a book instead.', 400, 'NOT_MANUAL_TARGET');
        }
        if (target.archivedAt) throw new AppError('Restore the target to record on it.', 400, 'TARGET_ARCHIVED');
        if (!this.canRecord(target, viewer)) {
            throw new AuthorizationError('Only the person this target is for, or a manager, can record on it.');
        }
    }

    /** The days a hand-recorded amount can be dated: inside the period, from the opening date, up to today. */
    private recordWindow(target: { startDate: Date; endDate: Date; openingAmount: Decimal; openingDate: Date | null }, today: BusinessDate) {
        const from = new Decimal(target.openingAmount).gt(0) && target.openingDate
            ? dateOf(target.openingDate)
            : dateOf(target.startDate);
        return { from, to: minDate(today, dateOf(target.endDate)) };
    }

    private assertRecordDate(target: TargetRow, date: BusinessDate, today: BusinessDate) {
        if (date > today) {
            throw new AppError("You can't record an amount for a day that hasn't happened yet.", 400, 'INVALID_RECORD_DATE');
        }
        if (today < dateOf(target.startDate)) {
            throw new AppError("This target's period hasn't started yet.", 400, 'INVALID_RECORD_DATE');
        }
        const window = this.recordWindow(target, today);
        if (date < window.from || date > window.to) {
            throw new AppError(
                window.from > dateOf(target.startDate)
                    ? `Pick a day from ${window.from} to ${window.to}. Earlier money is covered by the amount already raised.`
                    : `Pick a day from ${window.from} to ${window.to}.`,
                400,
                'INVALID_RECORD_DATE',
            );
        }
    }

    /** Serialises writes to one target's records, so two withdrawals can't both pass the balance check. */
    private async lockTarget(tx: Prisma.TransactionClient, targetId: string) {
        await tx.$queryRaw`SELECT id FROM targets WHERE id = ${targetId}::uuid FOR UPDATE`;
    }

    /** Money can only come out once it has gone in: the opening amount plus additions, less withdrawals, stays ≥ 0. */
    private async assertNotOverdrawn(tx: Prisma.TransactionClient, target: TargetRow) {
        const sums = await tx.targetContribution.groupBy({
            by: ['kind'],
            where: { targetId: target.id },
            _sum: { amount: true },
        });
        let balance = new Decimal(target.openingAmount);
        for (const row of sums) {
            const value = new Decimal(row._sum.amount ?? 0);
            balance = row.kind === TargetContributionKind.WITHDRAWAL ? balance.sub(value) : balance.add(value);
        }
        if (balance.lt(0)) {
            throw new AppError(
                `That would take out more than has been raised (${formatAmount(balance.add(0).abs().toFixed(2), target.currency)} too much).`,
                400,
                'TARGET_OVERDRAWN',
            );
        }
    }

    private async editableContribution(target: TargetRow, contributionId: string, viewer: Viewer) {
        const row = target.source === TargetSource.MANUAL
            ? await this.prisma.targetContribution.findFirst({ where: { id: contributionId, targetId: target.id } })
            : null;
        if (!row) throw new NotFoundError('Record');
        if (target.archivedAt) throw new AppError('Restore the target to change its records.', 400, 'TARGET_ARCHIVED');
        if (!this.canEditContribution(target, row.recordedById, viewer)) {
            throw new AuthorizationError('Only whoever recorded this, or a manager, can change it.');
        }
        return row;
    }

    private canEditContribution(target: TargetRow, recordedById: string, viewer: Viewer) {
        if (target.archivedAt) return false;
        if (hasWorkspacePermission(viewer.role, WorkspacePermission.MANAGE_TARGETS)) return true;
        return recordedById === viewer.userId && this.canRecord(target, viewer);
    }

    private toContributionView(row: Prisma.TargetContributionGetPayload<{ include: typeof CONTRIBUTION_INCLUDE }>, target: TargetRow, viewer: Viewer) {
        return {
            id: row.id,
            date: dateOf(row.date),
            kind: row.kind,
            amount: new Decimal(row.amount).toFixed(2),
            note: row.note,
            recordedBy: row.recordedBy,
            createdAt: row.createdAt,
            updatedAt: row.updatedAt,
            canEdit: this.canEditContribution(target, row.recordedById, viewer),
        };
    }

    private async assertAssignee(workspace: { id: string; type: WorkspaceType; ownerId: string }, assigneeId: string | null) {
        if (!assigneeId) return;
        if (workspace.type === WorkspaceType.PERSONAL) {
            throw new AppError('A personal workspace has only one person; leave the target unassigned.', 400, 'INVALID_ASSIGNEE');
        }
        if (assigneeId === workspace.ownerId) return;
        const member = await this.prisma.workspaceMember.findUnique({
            where: { workspaceId_userId: { workspaceId: workspace.id, userId: assigneeId } },
            select: { userId: true },
        });
        if (!member) throw new AppError('That person is not a member of this workspace.', 400, 'INVALID_ASSIGNEE');
    }

    private async validCashbookIds(workspaceId: string, ids: string[]) {
        const unique = [...new Set(ids)];
        if (unique.length === 0) return [];
        const found = await this.prisma.cashbook.findMany({
            where: { id: { in: unique }, workspaceId, isActive: true },
            select: { id: true },
        });
        if (found.length !== unique.length) {
            throw new AppError('One of the chosen books is not in this workspace.', 400, 'INVALID_CASHBOOK');
        }
        return unique;
    }

    /**
     * What each business day contributed, measured the way the target
     * measures it. Grouped by the day in the workspace's timezone — the same
     * day the entry shows on — and only posted entries: a reversal cancels
     * its original, as in the book's own totals.
     *
     * NET counts a charge on money received as money out, matching how the
     * book's totals and the entry list's summary treat it.
     */
    private async dailyTotals(target: TargetRow | Prisma.TargetGetPayload<object>, today: BusinessDate, timezone: string) {
        const start = dateOf(target.startDate);
        const end = dateOf(target.endDate);
        const last = today < end ? today : end;
        const daily = new Map<BusinessDate, Decimal>();
        if (last < start) return daily;

        if (target.source === TargetSource.MANUAL) {
            const rows = await this.prisma.targetContribution.groupBy({
                by: ['date', 'kind'],
                where: { targetId: target.id, date: { gte: toDateColumn(start), lte: toDateColumn(last) } },
                _sum: { amount: true },
            });
            for (const row of rows) {
                const day = dateOf(row.date);
                const value = new Decimal(row._sum.amount ?? 0);
                const signed = row.kind === TargetContributionKind.WITHDRAWAL ? value.negated() : value;
                daily.set(day, (daily.get(day) ?? new Decimal(0)).add(signed));
            }
            return daily;
        }

        const clock = await clockFor(this.prisma, target.workspaceId);
        const fromUtc = clock.businessDateRangeUtc(start).startUtc;
        const toUtc = clock.businessDateRangeUtc(last).endUtc;

        const scoped = await this.prisma.targetCashbook.findMany({
            where: { targetId: target.id },
            select: { cashbookId: true },
        });
        const cashbookIds = scoped.map((s) => s.cashbookId);

        const valueSql = target.metric === TargetMetric.NET
            ? Prisma.sql`CASE WHEN e.type = 'INCOME' THEN e.amount - COALESCE(e.charge_amount, 0)
                              ELSE -(e.amount + COALESCE(e.charge_amount, 0)) END`
            : Prisma.sql`CASE WHEN e.type = 'INCOME' THEN e.amount ELSE 0 END`;

        const rows = await this.prisma.$queryRaw<Array<{ day: Date; total: Prisma.Decimal | null }>>`
            SELECT (e.entry_date AT TIME ZONE 'UTC' AT TIME ZONE ${timezone})::date AS day,
                   SUM(${valueSql}) AS total
            FROM entries e
            JOIN cashbooks c ON c.id = e.cashbook_id
            WHERE c.workspace_id = ${target.workspaceId}::uuid
              AND e.status = 'POSTED'
              AND e.entry_date >= ${fromUtc}
              AND e.entry_date < ${toUtc}
              ${cashbookIds.length > 0 ? Prisma.sql`AND e.cashbook_id = ANY(${cashbookIds}::uuid[])` : Prisma.empty}
              ${target.assigneeId ? Prisma.sql`AND e.created_by_id = ${target.assigneeId}::uuid` : Prisma.empty}
            GROUP BY 1`;

        for (const row of rows) {
            daily.set(row.day.toISOString().slice(0, 10), new Decimal(row.total ?? 0));
        }
        return daily;
    }

    private progressInput(
        row: {
            amount: Decimal; startDate: Date; endDate: Date; workingDays: number[];
            source: TargetSource; openingAmount: Decimal; openingDate: Date | null;
        },
        today: BusinessDate,
        daily: Map<BusinessDate, Decimal>,
    ): ProgressInput {
        const opening = new Decimal(row.openingAmount);
        const openingDate = opening.gt(0) && row.openingDate ? dateOf(row.openingDate) : null;
        return {
            amount: new Decimal(row.amount),
            startDate: dateOf(row.startDate),
            endDate: dateOf(row.endDate),
            workingDays: row.workingDays,
            today,
            daily,
            ...(openingDate && { opening: { amount: opening, date: openingDate } }),
            // Days before a hand-recorded target's opening date are covered by
            // the opening amount, not known one by one. Books know every day.
            ...(openingDate && row.source === TargetSource.MANUAL && { trackedFrom: openingDate }),
        };
    }

    private async progressFor(row: TargetRow, today: BusinessDate, timezone: string): Promise<Progress> {
        const daily = await this.dailyTotals(row, today, timezone);
        return computeProgress(this.progressInput(row, today, daily));
    }

    private toView(row: TargetRow, viewer: Viewer, today: BusinessDate) {
        const opening = new Decimal(row.openingAmount);
        return {
            id: row.id,
            workspaceId: row.workspaceId,
            name: row.name,
            source: row.source,
            metric: row.metric,
            amount: new Decimal(row.amount).toFixed(2),
            currency: row.currency,
            startDate: dateOf(row.startDate),
            endDate: dateOf(row.endDate),
            workingDays: row.workingDays,
            openingAmount: opening.toFixed(2),
            openingDate: opening.gt(0) && row.openingDate ? dateOf(row.openingDate) : null,
            repeats: row.repeats,
            /** How often it comes round if it repeats — read from the period itself. */
            cadence: cadenceOf(dateOf(row.startDate), dateOf(row.endDate)),
            alertsEnabled: row.alertsEnabled,
            emailAlerts: row.emailAlerts,
            remindToRecord: row.remindToRecord,
            archivedAt: row.archivedAt,
            achievedAt: row.achievedAt,
            createdAt: row.createdAt,
            cashbooks: row.cashbooks.map((c) => c.cashbook),
            assignee: row.assignee,
            createdBy: row.createdBy,
            isMine: row.assigneeId === viewer.userId,
            canRecord: this.canRecord(row, viewer),
            /** Days a hand-recorded amount can be dated; null for book targets. */
            recordWindow: row.source === TargetSource.MANUAL ? this.recordWindow(row, today) : null,
        };
    }
}

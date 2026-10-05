import { injectable, inject } from 'tsyringe';
import { createHash, randomBytes } from 'node:crypto';
import bcrypt from 'bcryptjs';
import {
    AccountDeletionSource,
    AccountDeletionStatus,
    Prisma,
    PrismaClient,
} from '@prisma/client';
import { config, superAdminEmails } from '../../config';
import { getRedisClient } from '../../config/redis';
import { sendEmail } from '../../config/email';
import {
    AccountDeletionBlockedError,
    AccountDeletionBlocker,
    AppError,
    NotFoundError,
} from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';
import { StorageService } from '../files/storage.service';
import { logger } from '../../utils/logger';
import {
    accountDeletionBlockedEmailTemplate,
    accountDeletionCancelledEmailTemplate,
    accountDeletionCompletedEmailTemplate,
    accountDeletionScheduledEmailTemplate,
    accountDeletionVerifyEmailTemplate,
} from '../../utils/emailTemplates';

type Db = PrismaClient | Prisma.TransactionClient;

const S = AccountDeletionStatus;

/** A request still in play: at most one of these per person (partial unique index). */
export const OPEN_DELETION_STATUSES: AccountDeletionStatus[] = [
    S.PENDING_VERIFICATION, S.SCHEDULED, S.PROCESSING, S.BLOCKED,
];

/** How long an emailed confirmation link stays valid. */
export const VERIFICATION_TTL_HOURS = 24;
/** A second web request inside this window does not send another email. */
const RESEND_COOLDOWN_MS = 10 * 60 * 1000;
/** Due requests carried out per scheduler pass. */
const BATCH_SIZE = 10;

/**
 * The address an anonymised account is left with. `.invalid` is reserved
 * (RFC 2606), so it can never collide with a real address or receive mail,
 * and it frees the original address for a fresh sign-up.
 */
export const tombstoneEmail = (userId: string) => `deleted-${userId}@deleted.invalid`;

const hashToken = (token: string) => createHash('sha256').update(token).digest('hex');
const addDays = (date: Date, days: number) => new Date(date.getTime() + days * 86_400_000);
const appUrl = (path: string) => `${config.APP_URL.replace(/\/+$/, '')}${path}`;

export interface DeletionPlan {
    blockers: AccountDeletionBlocker[];
    /** Workspaces removed entirely: personal, sole-member, or already deleted. */
    workspacesToDelete: Array<{
        id: string; name: string; type: string; cashbooks: number; entries: number;
    }>;
    /** Businesses the person leaves; their records there stay with the business. */
    membershipsToLeave: Array<{ workspaceId: string; name: string; role: string }>;
}

export interface DeletionSummary {
    workspacesDeleted: number;
    entriesDeleted: number;
    filesDeleted: number;
    membershipsRemoved: number;
    sessionsEnded: number;
}

/**
 * Deleting an account.
 *
 * What happens, in order:
 *
 *  1. A request is made — in the app (password, or for an account without
 *     one, re-typing the email), on the website (confirmed through a link
 *     sent to the account's email), or by a superadmin for someone whose
 *     identity support has verified another way.
 *  2. It is SCHEDULED for ACCOUNT_DELETION_GRACE_DAYS later. Every session is
 *     ended at once. Signing in again during the grace period offers to cancel.
 *  3. When due, the scheduler carries it out:
 *       - every workspace only this person used is purged outright — books,
 *         ledger, wallets, invoices, stock and stored files;
 *       - they are removed from every business they belonged to;
 *       - sessions, login history, linked Google/OC identities and
 *         notifications are deleted;
 *       - the account row is anonymised in place ("Deleted user").
 *
 * Why anonymise rather than delete the row: other businesses' entries,
 * journals and HR records name whoever created them. Those records belong to
 * those businesses, and their books must not change because a former staff
 * member left. So the identity goes and the attribution stays.
 *
 * Kept: those business records, and the security audit log with IP addresses
 * and user agents stripped.
 *
 * Not possible: deleting a superadmin (managed through configuration), or
 * someone who still owns a business that has other members — ownership must
 * be transferred first, or that business would be orphaned.
 */
@injectable()
export class AccountDeletionService {
    constructor(
        @inject('PrismaClient') private prisma: PrismaClient,
        private storage: StorageService,
    ) { }

    // ─── What deleting would do ────────────────────────

    async plan(userId: string, db: Db = this.prisma): Promise<DeletionPlan> {
        const user = await db.user.findUnique({
            where: { id: userId },
            select: { id: true, email: true, isSuperAdmin: true, deletedAt: true },
        });
        if (!user || user.deletedAt) throw new NotFoundError('User');

        const [owned, memberships] = await Promise.all([
            db.workspace.findMany({
                where: { ownerId: userId },
                select: {
                    id: true, name: true, type: true, isActive: true,
                    _count: { select: { cashbooks: true } },
                    members: { where: { userId: { not: userId } }, select: { userId: true } },
                },
            }),
            db.workspaceMember.findMany({
                where: { userId, workspace: { ownerId: { not: userId }, isActive: true } },
                select: { role: true, workspace: { select: { id: true, name: true } } },
            }),
        ]);

        const blockers: AccountDeletionBlocker[] = [];
        if (user.isSuperAdmin || superAdminEmails().includes(user.email.toLowerCase())) {
            blockers.push({
                code: 'SUPER_ADMIN',
                message: 'Superadmin accounts cannot be deleted. Remove the address from SUPER_ADMIN_EMAILS first.',
            });
        }

        // A business that is still running and still has people in it cannot
        // lose its owner. One already deleted (inactive) has nobody relying on
        // it, so it is purged like any other workspace of theirs.
        const shared = owned.filter((w) => w.isActive && w.members.length > 0);
        if (shared.length > 0) {
            blockers.push({
                code: 'OWNS_SHARED_WORKSPACE',
                message: `Transfer ownership of ${shared.map((w) => `"${w.name}"`).join(', ')} to another member first — `
                    + 'other people still work in it.',
                workspaces: shared.map((w) => ({ id: w.id, name: w.name, otherMembers: w.members.length })),
            });
        }

        const purge = owned.filter((w) => !w.isActive || w.members.length === 0);
        const entryCounts = purge.length === 0 ? [] : await db.$queryRaw<Array<{ workspace_id: string; n: bigint }>>`
            SELECT c.workspace_id, COUNT(e.id)::bigint AS n
            FROM cashbooks c JOIN entries e ON e.cashbook_id = c.id
            WHERE c.workspace_id = ANY(${purge.map((w) => w.id)}::uuid[])
            GROUP BY c.workspace_id`;
        const entriesBy = new Map(entryCounts.map((r) => [r.workspace_id, Number(r.n)]));

        return {
            blockers,
            workspacesToDelete: purge.map((w) => ({
                id: w.id,
                name: w.name,
                type: w.type,
                cashbooks: w._count.cashbooks,
                entries: entriesBy.get(w.id) ?? 0,
            })),
            membershipsToLeave: memberships.map((m) => ({
                workspaceId: m.workspace.id, name: m.workspace.name, role: m.role,
            })),
        };
    }

    // ─── The person, signed in ─────────────────────────

    /** What the profile page shows: any request in play, and what deleting would do. */
    async getForUser(userId: string) {
        const [open, plan, user] = await Promise.all([
            this.findOpen(userId),
            this.plan(userId),
            this.prisma.user.findUniqueOrThrow({ where: { id: userId }, select: { passwordHash: true } }),
        ]);
        return {
            request: open ? this.toView(open) : null,
            plan,
            graceDays: config.ACCOUNT_DELETION_GRACE_DAYS,
            /** Which re-confirmation the form must ask for. */
            confirmWith: user.passwordHash ? 'password' : 'email',
        };
    }

    async requestFromApp(
        userId: string,
        dto: { password?: string; confirmEmail?: string; reason?: string },
        meta: { ipAddress?: string; userAgent?: string } = {},
    ) {
        const user = await this.prisma.user.findUnique({ where: { id: userId } });
        if (!user || user.deletedAt) throw new NotFoundError('User');

        // Re-confirm, because a session left open on a shared device should
        // not be enough to destroy an account. 400 rather than 401: a wrong
        // password here is not an expired session.
        if (user.passwordHash) {
            if (!dto.password || !(await bcrypt.compare(dto.password, user.passwordHash))) {
                throw new AppError('That password is not correct.', 400, 'INVALID_PASSWORD');
            }
        } else if (dto.confirmEmail?.trim().toLowerCase() !== user.email.toLowerCase()) {
            throw new AppError('Type your account email exactly to confirm.', 400, 'CONFIRMATION_MISMATCH');
        }

        const plan = await this.plan(userId);
        if (plan.blockers.length > 0) throw new AccountDeletionBlockedError(plan.blockers);

        return this.schedule(user, {
            source: AccountDeletionSource.IN_APP,
            reason: dto.reason,
            meta,
        });
    }

    async cancelFromApp(userId: string, meta: { ipAddress?: string; userAgent?: string } = {}) {
        const open = await this.findOpen(userId);
        if (!open) throw new NotFoundError('Pending account deletion');
        return this.cancel(open.id, { actorId: userId, meta });
    }

    // ─── The person, from the website ──────────────────

    /**
     * Ask for deletion without signing in.
     *
     * Always answers the same way, whether or not the address has an account:
     * otherwise this form would tell anyone which emails are registered.
     * Nothing is scheduled until the owner clicks the emailed link, so typing
     * someone else's address achieves nothing but an email they can ignore.
     */
    async requestFromWeb(dto: { email: string; reason?: string }): Promise<void> {
        const user = await this.prisma.user.findFirst({
            where: { email: { equals: dto.email.trim(), mode: 'insensitive' }, deletedAt: null, isActive: true },
        });
        if (!user) {
            logger.info('[AccountDeletion] Web request for an address with no active account');
            return;
        }

        const open = await this.findOpen(user.id);
        // Already scheduled, running or on hold: there is nothing to confirm.
        if (open && open.status !== S.PENDING_VERIFICATION) return;
        // A link was sent moments ago; do not let the form be used to flood an inbox.
        if (open && Date.now() - open.updatedAt.getTime() < RESEND_COOLDOWN_MS) return;

        const token = randomBytes(32).toString('base64url');
        const data = {
            verificationTokenHash: hashToken(token),
            verificationExpiresAt: new Date(Date.now() + VERIFICATION_TTL_HOURS * 3_600_000),
            reason: dto.reason?.trim() || null,
            contactEmail: user.email,
        };

        try {
            if (open) {
                await this.prisma.accountDeletionRequest.update({ where: { id: open.id }, data });
            } else {
                await this.prisma.accountDeletionRequest.create({
                    data: { ...data, userId: user.id, source: AccountDeletionSource.WEB, status: S.PENDING_VERIFICATION },
                });
            }
        } catch (error) {
            // Two submissions racing: the other one created the request.
            if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') return;
            throw error;
        }

        await this.prisma.auditLog.create({
            data: {
                userId: user.id,
                action: AuditAction.ACCOUNT_DELETION_REQUESTED,
                resource: 'account_deletion',
                resourceId: user.id,
                details: { source: 'WEB', stage: 'verification_sent' } as Prisma.InputJsonValue,
            },
        });

        await this.notify(user.email, 'Confirm your account deletion', accountDeletionVerifyEmailTemplate({
            firstName: user.firstName,
            confirmUrl: appUrl(`/delete-account/confirm?token=${encodeURIComponent(token)}`),
            expiresInHours: VERIFICATION_TTL_HOURS,
        }));
    }

    /** The emailed link: proves the requester controls the account's address. */
    async confirmFromWeb(token: string) {
        const request = await this.prisma.accountDeletionRequest.findUnique({
            where: { verificationTokenHash: hashToken(token) },
            include: { user: true },
        });
        if (!request || request.status !== S.PENDING_VERIFICATION || request.user.deletedAt) {
            throw new AppError('This link is not valid or has already been used.', 400, 'INVALID_TOKEN');
        }
        if (!request.verificationExpiresAt || request.verificationExpiresAt < new Date()) {
            await this.prisma.accountDeletionRequest.update({
                where: { id: request.id },
                data: { status: S.EXPIRED, verificationTokenHash: null },
            });
            throw new AppError('This link has expired. Request the deletion again.', 400, 'TOKEN_EXPIRED');
        }

        const plan = await this.plan(request.userId);
        if (plan.blockers.length > 0) {
            // Kept as BLOCKED rather than discarded: the person has proved who
            // they are, so support can pick it up once the blocker is cleared.
            const claimed = await this.prisma.accountDeletionRequest.updateMany({
                where: { id: request.id, status: S.PENDING_VERIFICATION },
                data: {
                    status: S.BLOCKED,
                    verifiedAt: new Date(),
                    verificationTokenHash: null,
                    blockers: plan.blockers as unknown as Prisma.InputJsonValue,
                },
            });
            if (claimed.count === 0) {
                throw new AppError('This link is not valid or has already been used.', 400, 'INVALID_TOKEN');
            }
            await this.audit(request.userId, AuditAction.ACCOUNT_DELETION_BLOCKED, request.id, { blockers: plan.blockers });
            await this.notify(request.user.email, 'Your account deletion is on hold', accountDeletionBlockedEmailTemplate({
                firstName: request.user.firstName,
                reasons: plan.blockers.map((b) => b.message),
                signInUrl: appUrl('/login'),
            }));
            return { status: S.BLOCKED, scheduledFor: null, blockers: plan.blockers };
        }

        const scheduledFor = addDays(new Date(), config.ACCOUNT_DELETION_GRACE_DAYS);
        const claimed = await this.prisma.$transaction(async (tx) => {
            const updated = await tx.accountDeletionRequest.updateMany({
                where: { id: request.id, status: S.PENDING_VERIFICATION },
                data: { status: S.SCHEDULED, scheduledFor, verifiedAt: new Date(), verificationTokenHash: null },
            });
            if (updated.count > 0) {
                await tx.refreshToken.updateMany({
                    where: { userId: request.userId, isRevoked: false },
                    data: { isRevoked: true },
                });
            }
            return updated.count;
        });
        if (claimed === 0) {
            throw new AppError('This link is not valid or has already been used.', 400, 'INVALID_TOKEN');
        }

        await this.audit(request.userId, AuditAction.ACCOUNT_DELETION_VERIFIED, request.id, { scheduledFor });
        await this.notify(request.user.email, 'Your account is scheduled for deletion', accountDeletionScheduledEmailTemplate({
            firstName: request.user.firstName,
            scheduledFor,
            signInUrl: appUrl('/login'),
        }));
        return { status: S.SCHEDULED, scheduledFor, blockers: [] as AccountDeletionBlocker[] };
    }

    // ─── Superadmin ────────────────────────────────────

    async list(params: { status?: AccountDeletionStatus; search?: string; page: number; limit: number }) {
        const search = params.search?.trim();
        const where: Prisma.AccountDeletionRequestWhereInput = {
            ...(params.status && { status: params.status }),
            ...(search && {
                OR: [
                    { contactEmail: { contains: search, mode: 'insensitive' } },
                    { user: { email: { contains: search, mode: 'insensitive' } } },
                    { user: { firstName: { contains: search, mode: 'insensitive' } } },
                    { user: { lastName: { contains: search, mode: 'insensitive' } } },
                ],
            }),
        };

        const [total, rows] = await Promise.all([
            this.prisma.accountDeletionRequest.count({ where }),
            this.prisma.accountDeletionRequest.findMany({
                where,
                orderBy: { createdAt: 'desc' },
                skip: (params.page - 1) * params.limit,
                take: params.limit,
                include: {
                    user: { select: { id: true, email: true, firstName: true, lastName: true, deletedAt: true } },
                    handledBy: { select: { firstName: true, lastName: true } },
                },
            }),
        ]);

        return {
            data: rows.map((r) => ({ ...this.toView(r), user: r.user, handledBy: r.handledBy })),
            total,
            page: params.page,
            limit: params.limit,
        };
    }

    /** How many requests need a superadmin's eye — for the badge on the tab. */
    async attentionCount() {
        return this.prisma.accountDeletionRequest.count({
            where: { status: { in: [S.BLOCKED, S.FAILED] } },
        });
    }

    async getForAdmin(id: string) {
        const request = await this.prisma.accountDeletionRequest.findUnique({
            where: { id },
            include: {
                user: { select: { id: true, email: true, firstName: true, lastName: true, deletedAt: true } },
                handledBy: { select: { firstName: true, lastName: true } },
            },
        });
        if (!request) throw new NotFoundError('Deletion request');

        const plan = request.user.deletedAt ? null : await this.plan(request.userId);
        return { ...this.toView(request), user: request.user, handledBy: request.handledBy, plan };
    }

    /**
     * Schedule a deletion on someone's behalf.
     *
     * For when support has confirmed who they are some other way — typically
     * someone who lost access to their email. Same grace period as any other
     * request, and they are emailed so they can still object.
     */
    async scheduleForUser(userId: string, actorId: string, dto: { reason?: string; note?: string }) {
        const user = await this.prisma.user.findUnique({ where: { id: userId } });
        if (!user || user.deletedAt) throw new NotFoundError('User');

        const plan = await this.plan(userId);
        if (plan.blockers.length > 0) throw new AccountDeletionBlockedError(plan.blockers);

        return this.schedule(user, {
            source: AccountDeletionSource.ADMIN,
            reason: dto.reason,
            note: dto.note,
            actorId,
        });
    }

    async cancelByAdmin(id: string, actorId: string, note?: string) {
        return this.cancel(id, { actorId, note, byAdmin: true });
    }

    /** Carry a request out now, skipping what is left of the grace period. */
    async processNow(id: string, actorId: string) {
        const request = await this.prisma.accountDeletionRequest.findUnique({ where: { id } });
        if (!request) throw new NotFoundError('Deletion request');
        if (!([S.SCHEDULED, S.BLOCKED, S.FAILED] as AccountDeletionStatus[]).includes(request.status)) {
            throw new AppError(
                `A ${request.status.toLowerCase().replace('_', ' ')} request cannot be processed.`,
                409,
                'INVALID_STATUS',
            );
        }
        await this.audit(request.userId, AuditAction.ACCOUNT_DELETION_FORCED, id, { actorId }, actorId);
        await this.execute(id, { actorId });
        return this.getForAdmin(id);
    }

    // ─── Carrying it out ───────────────────────────────

    /**
     * Run every request whose grace period is over. Called by the scheduler;
     * each request is claimed atomically, so overlapping runs on several
     * replicas never process the same one twice.
     */
    async processDue(now = new Date()): Promise<number> {
        // Links that were never used.
        await this.prisma.accountDeletionRequest.updateMany({
            where: { status: S.PENDING_VERIFICATION, verificationExpiresAt: { lt: now } },
            data: { status: S.EXPIRED, verificationTokenHash: null },
        });

        const due = await this.prisma.accountDeletionRequest.findMany({
            where: { status: S.SCHEDULED, scheduledFor: { lte: now } },
            orderBy: { scheduledFor: 'asc' },
            take: BATCH_SIZE,
            select: { id: true },
        });

        let processed = 0;
        for (const { id } of due) {
            try {
                if (await this.execute(id)) processed += 1;
            } catch (error) {
                // execute() has already recorded the failure; carry on with the rest.
                logger.error('[AccountDeletion] Request failed', { id, error: (error as Error).message });
            }
        }
        return processed;
    }

    /**
     * Delete one account. Returns false if the request could not be claimed
     * (already taken, cancelled, or not yet due).
     */
    async execute(requestId: string, opts: { actorId?: string } = {}): Promise<boolean> {
        const claimable: AccountDeletionStatus[] = opts.actorId ? [S.SCHEDULED, S.BLOCKED, S.FAILED] : [S.SCHEDULED];
        const claimed = await this.prisma.accountDeletionRequest.updateMany({
            where: {
                id: requestId,
                status: { in: claimable },
                ...(!opts.actorId && { scheduledFor: { lte: new Date() } }),
            },
            data: {
                status: S.PROCESSING,
                attempts: { increment: 1 },
                ...(opts.actorId && { handledById: opts.actorId }),
            },
        });
        if (claimed.count === 0) return false;

        const request = await this.prisma.accountDeletionRequest.findUniqueOrThrow({
            where: { id: requestId },
            include: { user: true },
        });
        const { user } = request;
        // Captured now: the account's own address is scrubbed below.
        const finalEmail = request.contactEmail ?? user.email;
        const firstName = user.firstName;

        try {
            const plan = await this.plan(user.id);
            if (plan.blockers.length > 0) {
                await this.prisma.accountDeletionRequest.update({
                    where: { id: requestId },
                    data: { status: S.BLOCKED, blockers: plan.blockers as unknown as Prisma.InputJsonValue },
                });
                await this.audit(user.id, AuditAction.ACCOUNT_DELETION_BLOCKED, requestId, { blockers: plan.blockers }, opts.actorId);
                await this.notify(finalEmail, 'Your account deletion is on hold', accountDeletionBlockedEmailTemplate({
                    firstName,
                    reasons: plan.blockers.map((b) => b.message),
                    signInUrl: appUrl('/login'),
                }));
                return true;
            }

            const workspaceIds = plan.workspacesToDelete.map((w) => w.id);
            // Read before the rows go; removed from storage after the commit.
            const objectKeys = await this.storedObjectKeys(workspaceIds);

            const summary = await this.prisma.$transaction(async (tx) => {
                const result: DeletionSummary = {
                    workspacesDeleted: workspaceIds.length,
                    entriesDeleted: plan.workspacesToDelete.reduce((sum, w) => sum + w.entries, 0),
                    filesDeleted: objectKeys.length,
                    membershipsRemoved: 0,
                    sessionsEnded: 0,
                };

                // The ledger is append-only; purging a whole workspace is the
                // one sanctioned exception, scoped to this transaction.
                await tx.$executeRawUnsafe(`SET LOCAL app.allow_ledger_maintenance = 'on'`);
                for (const workspaceId of workspaceIds) {
                    await purgeWorkspace(tx, workspaceId);
                }

                result.membershipsRemoved = (await tx.workspaceMember.deleteMany({ where: { userId: user.id } })).count;
                await tx.cashbookMember.deleteMany({ where: { userId: user.id } });
                await tx.projectMember.deleteMany({ where: { userId: user.id } });

                result.sessionsEnded = (await tx.refreshToken.deleteMany({ where: { userId: user.id } })).count;
                await tx.loginHistory.deleteMany({ where: { userId: user.id } });
                await tx.linkedIdentity.deleteMany({ where: { userId: user.id } });
                await tx.notification.deleteMany({ where: { userId: user.id } });
                await tx.pendingInvite.deleteMany({ where: { email: { equals: user.email, mode: 'insensitive' } } });
                // Contact cards other businesses keep for this person stay
                // theirs, but no longer point at a live account.
                await tx.contact.updateMany({ where: { userId: user.id }, data: { userId: null } });
                // Their own targets in other businesses can never move again.
                await tx.target.updateMany({
                    where: { assigneeId: user.id, archivedAt: null },
                    data: { archivedAt: new Date() },
                });
                await tx.referralAgent.updateMany({
                    where: { userId: user.id, isActive: true },
                    data: { isActive: false, revokedAt: new Date() },
                });
                // The security trail stays; where it was made from does not.
                await tx.auditLog.updateMany({
                    where: { userId: user.id },
                    data: { ipAddress: null, userAgent: null },
                });

                await tx.user.update({
                    where: { id: user.id },
                    data: {
                        email: tombstoneEmail(user.id),
                        firstName: 'Deleted',
                        lastName: 'user',
                        passwordHash: null,
                        providerId: null,
                        isActive: false,
                        isSuperAdmin: false,
                        emailVerified: false,
                        lastLoginAt: null,
                        deletedAt: new Date(),
                    },
                });

                await tx.accountDeletionRequest.update({
                    where: { id: requestId },
                    data: {
                        status: S.COMPLETED,
                        completedAt: new Date(),
                        summary: result as unknown as Prisma.InputJsonValue,
                        blockers: Prisma.DbNull,
                        failureReason: null,
                    },
                });
                // Any other open request for this person is now moot.
                await tx.accountDeletionRequest.updateMany({
                    where: { userId: user.id, id: { not: requestId }, status: { in: OPEN_DELETION_STATUSES } },
                    data: { status: S.CANCELLED, cancelledAt: new Date(), adminNote: 'Superseded by a completed deletion' },
                });
                await tx.auditLog.create({
                    data: {
                        userId: opts.actorId ?? null,
                        action: AuditAction.ACCOUNT_DELETION_COMPLETED,
                        resource: 'user',
                        resourceId: user.id,
                        details: { requestId, ...result } as unknown as Prisma.InputJsonValue,
                    },
                });

                return result;
            }, { timeout: 120_000, maxWait: 10_000 });

            // After the commit: none of this can be rolled back, so it must not
            // run unless the database work is final.
            await this.removeObjects(objectKeys);
            await this.clearCachedCodes(user.id);
            await this.notify(finalEmail, 'Your account has been deleted', accountDeletionCompletedEmailTemplate({ firstName }));
            await this.prisma.accountDeletionRequest.update({
                where: { id: requestId },
                data: { contactEmail: null },
            });

            logger.info('[AccountDeletion] Completed', { requestId, ...summary });
            return true;
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            await this.prisma.accountDeletionRequest.update({
                where: { id: requestId },
                data: { status: S.FAILED, failureReason: message.slice(0, 1000) },
            });
            await this.audit(user.id, AuditAction.ACCOUNT_DELETION_FAILED, requestId, { error: message.slice(0, 300) }, opts.actorId);
            logger.error('[AccountDeletion] Failed', { requestId, error: message });
            throw error;
        }
    }

    // ─── Internals ─────────────────────────────────────

    private async schedule(
        user: { id: string; email: string; firstName: string },
        opts: {
            source: AccountDeletionSource;
            reason?: string;
            note?: string;
            actorId?: string;
            meta?: { ipAddress?: string; userAgent?: string };
        },
    ) {
        const open = await this.findOpen(user.id);
        if (open?.status === S.SCHEDULED || open?.status === S.PROCESSING) return this.toView(open);

        const scheduledFor = addDays(new Date(), config.ACCOUNT_DELETION_GRACE_DAYS);
        let request;
        try {
            request = await this.prisma.$transaction(async (tx) => {
                // A web link still waiting, or a request on hold, is replaced.
                await tx.accountDeletionRequest.updateMany({
                    where: { userId: user.id, status: { in: [S.PENDING_VERIFICATION, S.BLOCKED] } },
                    data: {
                        status: S.CANCELLED,
                        cancelledAt: new Date(),
                        verificationTokenHash: null,
                        adminNote: 'Superseded by a newer request',
                    },
                });
                const created = await tx.accountDeletionRequest.create({
                    data: {
                        userId: user.id,
                        source: opts.source,
                        status: S.SCHEDULED,
                        reason: opts.reason?.trim() || null,
                        adminNote: opts.note?.trim() || null,
                        handledById: opts.actorId ?? null,
                        contactEmail: user.email,
                        verifiedAt: new Date(),
                        scheduledFor,
                    },
                });
                // Signed out everywhere at once: if this was not them, whoever
                // else had a session loses it now rather than in two weeks.
                await tx.refreshToken.updateMany({
                    where: { userId: user.id, isRevoked: false },
                    data: { isRevoked: true },
                });
                await tx.auditLog.create({
                    data: {
                        userId: opts.actorId ?? user.id,
                        action: AuditAction.ACCOUNT_DELETION_REQUESTED,
                        resource: 'account_deletion',
                        resourceId: user.id,
                        details: { source: opts.source, scheduledFor } as unknown as Prisma.InputJsonValue,
                        ipAddress: opts.meta?.ipAddress,
                        userAgent: opts.meta?.userAgent,
                    },
                });
                return created;
            });
        } catch (error) {
            // Two requests at once: the other one won; report it.
            if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
                const winner = await this.findOpen(user.id);
                if (winner) return this.toView(winner);
            }
            throw error;
        }

        await this.notify(user.email, 'Your account is scheduled for deletion', accountDeletionScheduledEmailTemplate({
            firstName: user.firstName,
            scheduledFor,
            signInUrl: appUrl('/login'),
        }));
        return this.toView(request);
    }

    private async cancel(
        id: string,
        opts: { actorId: string; note?: string; byAdmin?: boolean; meta?: { ipAddress?: string; userAgent?: string } },
    ) {
        const request = await this.prisma.accountDeletionRequest.findUnique({
            where: { id },
            include: { user: { select: { email: true, firstName: true } } },
        });
        if (!request) throw new NotFoundError('Deletion request');

        const cancellable: AccountDeletionStatus[] = [S.PENDING_VERIFICATION, S.SCHEDULED, S.BLOCKED, S.FAILED];
        const updated = await this.prisma.accountDeletionRequest.updateMany({
            where: { id, status: { in: cancellable } },
            data: {
                status: S.CANCELLED,
                cancelledAt: new Date(),
                verificationTokenHash: null,
                ...(opts.byAdmin && { handledById: opts.actorId }),
                ...(opts.note?.trim() && { adminNote: opts.note.trim() }),
            },
        });
        if (updated.count === 0) {
            throw new AppError(
                request.status === S.PROCESSING
                    ? 'This deletion is already being carried out and can no longer be cancelled.'
                    : `This request is already ${request.status.toLowerCase()}.`,
                409,
                'INVALID_STATUS',
            );
        }

        await this.prisma.auditLog.create({
            data: {
                userId: opts.actorId,
                action: AuditAction.ACCOUNT_DELETION_CANCELLED,
                resource: 'account_deletion',
                resourceId: request.userId,
                details: { requestId: id, byAdmin: !!opts.byAdmin } as Prisma.InputJsonValue,
                ipAddress: opts.meta?.ipAddress,
                userAgent: opts.meta?.userAgent,
            },
        });

        if (request.status !== S.PENDING_VERIFICATION) {
            await this.notify(
                request.contactEmail ?? request.user.email,
                'Account deletion cancelled',
                accountDeletionCancelledEmailTemplate({ firstName: request.user.firstName }),
            );
        }

        const after = await this.prisma.accountDeletionRequest.findUniqueOrThrow({ where: { id } });
        return this.toView(after);
    }

    private findOpen(userId: string) {
        return this.prisma.accountDeletionRequest.findFirst({
            where: { userId, status: { in: OPEN_DELETION_STATUSES } },
        });
    }

    /** Every stored file that belongs to the workspaces about to be purged. */
    private async storedObjectKeys(workspaceIds: string[]): Promise<string[]> {
        if (workspaceIds.length === 0) return [];
        const [attachments, logos] = await Promise.all([
            this.prisma.attachment.findMany({
                where: {
                    OR: [
                        { workspaceId: { in: workspaceIds } },
                        { cashbook: { workspaceId: { in: workspaceIds } } },
                    ],
                },
                select: { s3Key: true },
            }),
            this.prisma.invoiceSettings.findMany({
                where: { workspaceId: { in: workspaceIds }, logoKey: { not: null } },
                select: { logoKey: true },
            }),
        ]);
        return [...new Set([
            ...attachments.map((a) => a.s3Key),
            ...logos.map((l) => l.logoKey as string),
        ])];
    }

    /**
     * Best-effort: the rows are already gone, so a file that fails to delete
     * is orphaned rather than visible. Logged so it can be swept.
     */
    private async removeObjects(keys: string[]) {
        const results = await Promise.allSettled(keys.map((key) => this.storage.deleteObject(key)));
        const failed = results.filter((r) => r.status === 'rejected').length;
        if (failed > 0) logger.warn('[AccountDeletion] Some stored files could not be removed', { failed, total: keys.length });
    }

    /** One-time codes cached for this person (verification, password reset). */
    private async clearCachedCodes(userId: string) {
        try {
            await getRedisClient().del(`verification:${userId}`, `reset:${userId}`);
        } catch (error) {
            // They expire on their own within minutes; not worth failing over.
            logger.warn('[AccountDeletion] Could not clear cached codes', { error: (error as Error).message });
        }
    }

    private async notify(to: string, subject: string, html: string) {
        try {
            await sendEmail({ to, subject, html });
        } catch (error) {
            // The request itself has been recorded; a lost email must not undo it.
            logger.error('[AccountDeletion] Email failed', { subject, error: (error as Error).message });
        }
    }

    private audit(
        userId: string,
        action: AuditAction,
        requestId: string,
        details: Record<string, unknown>,
        actorId?: string,
    ) {
        return this.prisma.auditLog.create({
            data: {
                userId: actorId ?? userId,
                action,
                resource: 'account_deletion',
                resourceId: userId,
                details: { requestId, ...details } as unknown as Prisma.InputJsonValue,
            },
        });
    }

    /** Never sends the token hash or a stale contact address to a client. */
    private toView(r: {
        id: string; userId: string; source: AccountDeletionSource; status: AccountDeletionStatus;
        reason: string | null; scheduledFor: Date | null; verifiedAt: Date | null; cancelledAt: Date | null;
        completedAt: Date | null; adminNote: string | null; blockers: Prisma.JsonValue; summary: Prisma.JsonValue;
        failureReason: string | null; attempts: number; createdAt: Date; updatedAt: Date;
    }) {
        return {
            id: r.id,
            userId: r.userId,
            source: r.source,
            status: r.status,
            reason: r.reason,
            scheduledFor: r.scheduledFor,
            verifiedAt: r.verifiedAt,
            cancelledAt: r.cancelledAt,
            completedAt: r.completedAt,
            adminNote: r.adminNote,
            blockers: (r.blockers as AccountDeletionBlocker[] | null) ?? [],
            summary: r.summary as DeletionSummary | null,
            failureReason: r.failureReason,
            attempts: r.attempts,
            createdAt: r.createdAt,
            updatedAt: r.updatedAt,
        };
    }
}

/**
 * Order workspace tables so that whatever restricts a table is deleted first.
 *
 * Read from the database's own foreign keys, so it follows the schema as it
 * changes. A restricting key from a table WITHOUT a workspace_id (an invoice
 * line, say) is attributed to the workspace table it cascades from, since
 * deleting that parent is what removes it. Cycles cannot be ordered; they are
 * appended and left to the retry loop in purgeWorkspace.
 */
async function orderForPurge(tx: Prisma.TransactionClient, tables: string[]): Promise<string[]> {
    const fks = await tx.$queryRaw<Array<{ child: string; parent: string; action: string }>>`
        SELECT cl.relname AS child, pl.relname AS parent, con.confdeltype::text AS action
        FROM pg_constraint con
        JOIN pg_class cl ON cl.oid = con.conrelid
        JOIN pg_class pl ON pl.oid = con.confrelid
        JOIN pg_namespace n ON n.oid = cl.relnamespace
        WHERE con.contype = 'f' AND n.nspname = current_schema()`;

    const inScope = new Set(tables);
    // Which workspace tables' deletion removes rows of this table.
    const owners = (table: string, seen = new Set<string>()): string[] => {
        if (inScope.has(table)) return [table];
        if (seen.has(table)) return [];
        seen.add(table);
        return fks
            .filter((fk) => fk.child === table && fk.action === 'c')
            .flatMap((fk) => owners(fk.parent, seen));
    };

    // before.get(p) = tables that must be emptied before p.
    const before = new Map<string, Set<string>>(tables.map((t) => [t, new Set<string>()]));
    for (const fk of fks) {
        // 'a' NO ACTION and 'r' RESTRICT refuse the delete; cascade and
        // set-null take care of themselves.
        if ((fk.action !== 'a' && fk.action !== 'r') || !inScope.has(fk.parent)) continue;
        for (const owner of owners(fk.child)) {
            if (owner !== fk.parent) before.get(fk.parent)!.add(owner);
        }
    }

    const ordered: string[] = [];
    const placed = new Set<string>();
    let progress = true;
    while (progress && ordered.length < tables.length) {
        progress = false;
        for (const table of tables) {
            if (placed.has(table)) continue;
            if ([...before.get(table)!].every((dep) => placed.has(dep))) {
                ordered.push(table);
                placed.add(table);
                progress = true;
            }
        }
    }
    return [...ordered, ...tables.filter((t) => !placed.has(t))];
}

/** Postgres: a row is still referenced (23503 foreign key, 23001 RESTRICT). */
const STILL_REFERENCED = new Set(['23503', '23001']);

/**
 * Remove a workspace and everything in it.
 *
 * Three stages, inside the caller's transaction (which must have
 * app.allow_ledger_maintenance on):
 *
 *  1. Peer-link settlements anywhere that cite this workspace's entries. The
 *     other business keeps its own entry; it loses only this side's record.
 *  2. The ledger: lines, then journals — reversals before what they reverse,
 *     because a reversal must keep its link (je_reversal_consistent). Then
 *     the self- and cross-references inside the chart of accounts, which
 *     would otherwise stop a delete part-way.
 *  3. Every other table that carries this workspace's id, repeated until no
 *     more rows can go, then the workspace row (which cascades the rest).
 *
 * Stage 3 is deliberately generic. Some tables hold a workspace_id without a
 * cascading foreign key to workspaces (account transfers, for one), and
 * several restrict each other; listing them by hand would quietly break the
 * next time a table is added. Each delete runs in a savepoint: one that is
 * refused because something still points at its rows is rolled back and
 * retried on the next pass, after whatever pointed at it has gone. A pass
 * that removes nothing ends the loop; anything still left then fails the
 * final delete loudly, rolling back the whole deletion for a retry.
 */
export async function purgeWorkspace(tx: Prisma.TransactionClient, workspaceId: string) {
    await tx.$executeRaw`
        DELETE FROM peer_link_settlements
        WHERE entry_id IN (
            SELECT e.id FROM entries e JOIN cashbooks c ON c.id = e.cashbook_id
            WHERE c.workspace_id = ${workspaceId}::uuid
        )`;

    await tx.$executeRaw`DELETE FROM journal_lines WHERE workspace_id = ${workspaceId}::uuid`;
    // A journal is reversed at most once (the link is unique), so chains are
    // linear and peeling off the unreversed ones each pass terminates.
    for (;;) {
        const removed = await tx.$executeRaw`
            DELETE FROM journal_entries je
            WHERE je.workspace_id = ${workspaceId}::uuid
              AND NOT EXISTS (
                  SELECT 1 FROM journal_entries r WHERE r.reverses_journal_entry_id = je.id
              )`;
        if (removed === 0) break;
    }
    await tx.$executeRaw`UPDATE cashbooks SET cash_ledger_account_id = NULL WHERE workspace_id = ${workspaceId}::uuid`;
    await tx.$executeRaw`UPDATE accounts SET ledger_account_id = NULL WHERE workspace_id = ${workspaceId}::uuid`;
    await tx.$executeRaw`UPDATE ledger_accounts SET parent_id = NULL WHERE workspace_id = ${workspaceId}::uuid`;

    const tables = (await tx.$queryRaw<Array<{ table_name: string }>>`
        SELECT c.table_name
        FROM information_schema.columns c
        JOIN information_schema.tables t
          ON t.table_schema = c.table_schema AND t.table_name = c.table_name
        WHERE c.table_schema = current_schema()
          AND c.column_name = 'workspace_id'
          AND t.table_type = 'BASE TABLE'
        ORDER BY c.table_name`).map((row) => row.table_name);

    let remaining = await orderForPurge(tx, tables);
    while (remaining.length > 0) {
        const refused: string[] = [];
        for (const table of remaining) {
            // Table names come from the catalog, never from input.
            await tx.$executeRawUnsafe('SAVEPOINT purge_step');
            try {
                await tx.$executeRawUnsafe(`DELETE FROM "${table}" WHERE workspace_id = $1::uuid`, workspaceId);
                await tx.$executeRawUnsafe('RELEASE SAVEPOINT purge_step');
            } catch (error) {
                await tx.$executeRawUnsafe('ROLLBACK TO SAVEPOINT purge_step');
                const code = (error as { meta?: { code?: string } }).meta?.code;
                if (!code || !STILL_REFERENCED.has(code)) throw error;
                refused.push(table);
            }
        }
        if (refused.length === remaining.length) break; // no progress this pass
        remaining = refused;
    }

    await tx.$executeRaw`DELETE FROM workspaces WHERE id = ${workspaceId}::uuid`;
}

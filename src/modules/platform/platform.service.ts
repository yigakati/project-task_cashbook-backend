/**
 * Platform (superadmin) operations.
 *
 * Replaces the old /admin controller, which talked to Prisma directly, had no
 * service or repository, and wrote no audit rows for any of its four actions.
 */
import { injectable, inject } from 'tsyringe';
import { PrismaClient, ReferralStatus } from '@prisma/client';
import { superAdminEmails } from '../../config';
import { AppError, NotFoundError } from '../../core/errors/AppError';
import { AuditAction, FeatureKey, WorkspaceType } from '../../core/types';
import { logger } from '../../utils/logger';
import { generateUniqueReferralCode } from '../referrals/referrals.helpers';

export interface SuperAdminReconciliation {
    promoted: string[];
    demoted: string[];
    configured: string[];
}

@injectable()
export class PlatformService {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    /**
     * Make the database agree with SUPER_ADMIN_EMAILS.
     *
     * Promotes every listed user and demotes every unlisted one, so the env var
     * is genuinely the source of truth. Previously the flag was set only at
     * signup, which meant adding an address did nothing for an existing account
     * and removing one did nothing at all.
     *
     * Runs on boot and after each successful login.
     */
    async reconcileSuperAdmins(): Promise<SuperAdminReconciliation> {
        const configured = superAdminEmails();

        const [shouldBe, currentlyAre] = await Promise.all([
            configured.length > 0
                ? this.prisma.user.findMany({
                    where: { email: { in: configured, mode: 'insensitive' } },
                    select: { id: true, email: true, isSuperAdmin: true },
                })
                : Promise.resolve([]),
            this.prisma.user.findMany({
                where: { isSuperAdmin: true },
                select: { id: true, email: true },
            }),
        ]);

        const toPromote = shouldBe.filter((u) => !u.isSuperAdmin);
        const shouldBeIds = new Set(shouldBe.map((u) => u.id));
        const toDemote = currentlyAre.filter((u) => !shouldBeIds.has(u.id));

        if (toPromote.length > 0) {
            await this.prisma.user.updateMany({
                where: { id: { in: toPromote.map((u) => u.id) } },
                data: { isSuperAdmin: true },
            });
        }

        if (toDemote.length > 0) {
            await this.prisma.user.updateMany({
                where: { id: { in: toDemote.map((u) => u.id) } },
                data: { isSuperAdmin: false },
            });
        }

        const result: SuperAdminReconciliation = {
            promoted: toPromote.map((u) => u.email),
            demoted: toDemote.map((u) => u.email),
            configured,
        };

        if (result.promoted.length > 0 || result.demoted.length > 0) {
            logger.info('Reconciled platform superadmins', result);
        }

        return result;
    }

    /**
     * Configured addresses alongside whether an account exists for each.
     * A configured address with no account is a common misconfiguration worth
     * surfacing rather than silently ignoring.
     */
    async listSuperAdmins() {
        const configured = superAdminEmails();
        const users = await this.prisma.user.findMany({
            where: {
                OR: [
                    { isSuperAdmin: true },
                    ...(configured.length > 0
                        ? [{ email: { in: configured, mode: 'insensitive' as const } }]
                        : []),
                ],
            },
            select: {
                id: true, email: true, firstName: true, lastName: true,
                isSuperAdmin: true, isActive: true, lastLoginAt: true,
            },
            orderBy: { email: 'asc' },
        });

        const byEmail = new Map(users.map((u) => [u.email.toLowerCase(), u]));

        return {
            /** Managed by env var; not editable through the API. */
            source: 'SUPER_ADMIN_EMAILS',
            configured: configured.map((email) => ({
                email,
                user: byEmail.get(email) ?? null,
                status: byEmail.get(email) ? 'ACTIVE' : 'NO_ACCOUNT',
            })),
            /** Flagged in the database but absent from the env var — a stale grant. */
            unmanaged: users.filter(
                (u) => u.isSuperAdmin && !configured.includes(u.email.toLowerCase()),
            ),
        };
    }

    async getStats() {
        const [users, activeUsers, workspaces, cashbooks, entries, journals, reversedEntries] =
            await Promise.all([
                this.prisma.user.count({ where: { deletedAt: null } }),
                this.prisma.user.count({ where: { isActive: true, deletedAt: null } }),
                this.prisma.workspace.count({ where: { isActive: true } }),
                this.prisma.cashbook.count({ where: { isActive: true } }),
                this.prisma.entry.count({ where: { status: 'POSTED' } }),
                this.prisma.journalEntry.count(),
                this.prisma.entry.count({ where: { status: 'REVERSED' } }),
            ]);

        return {
            users: { total: users, active: activeUsers },
            workspaces,
            cashbooks,
            entries: { posted: entries, reversed: reversedEntries },
            ledger: { journalEntries: journals },
        };
    }

    async listUsers(params: { page: number; limit: number; search?: string }) {
        const skip = (params.page - 1) * params.limit;
        // Deleted accounts are anonymised tombstones, not users; they are
        // visible under Account deletions instead.
        const where = {
            deletedAt: null,
            ...(params.search && {
                OR: [
                    { email: { contains: params.search, mode: 'insensitive' as const } },
                    { firstName: { contains: params.search, mode: 'insensitive' as const } },
                    { lastName: { contains: params.search, mode: 'insensitive' as const } },
                ],
            }),
        };

        const [total, data] = await Promise.all([
            this.prisma.user.count({ where }),
            this.prisma.user.findMany({
                where,
                select: {
                    id: true, email: true, firstName: true, lastName: true,
                    isActive: true, isSuperAdmin: true, emailVerified: true,
                    provider: true, lastLoginAt: true, createdAt: true,
                    // So the "make agent" action can show the current state
                    // rather than inviting a second, pointless click.
                    referralAgent: { select: { id: true, code: true, isActive: true } },
                    _count: { select: { ownedWorkspaces: true, workspaceMemberships: true } },
                },
                orderBy: { createdAt: 'desc' },
                skip,
                take: params.limit,
            }),
        ]);

        return { data, total, page: params.page, limit: params.limit };
    }

    async toggleUserStatus(targetUserId: string, actorUserId: string) {
        if (targetUserId === actorUserId) {
            throw new AppError(
                'You cannot deactivate your own account',
                400,
                'SELF_DEACTIVATION',
            );
        }

        const user = await this.prisma.user.findUnique({
            where: { id: targetUserId },
            select: { id: true, email: true, isActive: true, isSuperAdmin: true },
        });
        if (!user) throw new AppError('User not found', 404, 'NOT_FOUND');

        const updated = await this.prisma.user.update({
            where: { id: targetUserId },
            data: { isActive: !user.isActive },
            select: { id: true, email: true, isActive: true },
        });

        await this.prisma.auditLog.create({
            data: {
                userId: actorUserId,
                action: updated.isActive
                    ? AuditAction.ADMIN_USER_ACTIVATED
                    : AuditAction.ADMIN_USER_SUSPENDED,
                resource: 'user',
                resourceId: targetUserId,
                details: { email: user.email, isActive: updated.isActive } as never,
            },
        });

        return updated;
    }

    async listWorkspaces(params: { page: number; limit: number; search?: string }) {
        const skip = (params.page - 1) * params.limit;
        const where = params.search
            ? { name: { contains: params.search, mode: 'insensitive' as const } }
            : {};

        const [total, data] = await Promise.all([
            this.prisma.workspace.count({ where }),
            this.prisma.workspace.findMany({
                where,
                select: {
                    id: true, name: true, type: true, defaultCurrency: true,
                    isActive: true, createdAt: true,
                    revenueBasis: true, inventoryValuation: true,
                    features: { select: { feature: true, enabledAt: true } },
                    owner: { select: { id: true, email: true, firstName: true, lastName: true } },
                    _count: {
                        select: { members: true, cashbooks: true, accounts: true, journalEntries: true },
                    },
                },
                orderBy: { createdAt: 'desc' },
                skip,
                take: params.limit,
            }),
        ]);

        return { data, total, page: params.page, limit: params.limit };
    }

    /**
     * Unlock or lock a module for one organisation.
     *
     * The first mutation this module has ever had on a workspace —
     * ADMIN_WORKSPACE_ACTION was defined and never emitted until now.
     *
     * Enabling only unlocks the module; it does not configure it. The org still
     * has to choose which book ticket money lands in and which category it
     * counts as, because that is a chart-of-accounts decision nobody outside the
     * organisation is in a position to make. Disabling is non-destructive: the
     * sales, days and tickets stay exactly where they are and the entries they
     * posted are untouched — the desk simply stops answering.
     */
    async setWorkspaceFeature(params: {
        workspaceId: string;
        feature: FeatureKey;
        enabled: boolean;
        actorId: string;
    }) {
        const workspace = await this.prisma.workspace.findUnique({
            where: { id: params.workspaceId },
            select: { id: true, name: true, type: true },
        });
        if (!workspace) throw new NotFoundError('Workspace');

        /*
         * Business workspaces only — for the modules that genuinely need one.
         *
         * A personal workspace is one person's own books: it has no staff to
         * tag, no attendants, no shifts to reconcile, and `requireTicketing`
         * refuses everyone but the owner in one anyway. Unlocking a gate desk
         * there produces a module that cannot be staffed and a nav entry that
         * leads nowhere.
         *
         * MANUAL_CONTACTS is deliberately not in this set: a personal
         * workspace keeps contacts like any other, so the grant has to be
         * available there too.
         *
         * Enforced here rather than only hiding the button, because a hidden
         * button is not a restriction — this endpoint is reachable directly.
         * Disabling is always allowed, so a flag set before this rule existed
         * can still be cleared.
         */
        const businessOnly: FeatureKey[] = [FeatureKey.TICKETING];
        if (params.enabled
            && businessOnly.includes(params.feature)
            && workspace.type !== WorkspaceType.BUSINESS) {
            throw new AppError(
                `${params.feature} is a business module and cannot be enabled for a personal workspace.`,
                400,
                'PERSONAL_WORKSPACE_UNSUPPORTED',
            );
        }

        if (params.enabled) {
            await this.prisma.workspaceFeature.upsert({
                where: {
                    workspaceId_feature: {
                        workspaceId: params.workspaceId,
                        feature: params.feature,
                    },
                },
                // Already on stays on, with its original grant intact: re-enabling
                // should not rewrite who first turned it on.
                update: {},
                create: {
                    workspaceId: params.workspaceId,
                    feature: params.feature,
                    enabledById: params.actorId,
                },
            });
        } else {
            await this.prisma.workspaceFeature.deleteMany({
                where: { workspaceId: params.workspaceId, feature: params.feature },
            });
        }

        await this.prisma.auditLog.create({
            data: {
                userId: params.actorId,
                workspaceId: params.workspaceId,
                action: params.enabled
                    ? AuditAction.WORKSPACE_FEATURE_ENABLED
                    : AuditAction.WORKSPACE_FEATURE_DISABLED,
                resource: 'workspace_feature',
                resourceId: params.workspaceId,
                details: {
                    feature: params.feature,
                    workspaceName: workspace.name,
                    platformAction: AuditAction.ADMIN_WORKSPACE_ACTION,
                } as any,
            },
        });

        const features = await this.prisma.workspaceFeature.findMany({
            where: { workspaceId: params.workspaceId },
            select: { feature: true, enabledAt: true },
        });

        return { workspaceId: params.workspaceId, features };
    }


    // ─── Referral agents ───────────────────────────────

    /**
     * Appoint someone a referral agent, or revoke them.
     *
     * Appointing mints a code on first appointment and reuses it forever
     * after: an agent whose code changed between one poster and the next would
     * lose every referral still in flight against the old one.
     */
    async setReferralAgent(params: {
        targetUserId: string;
        actorId: string;
        isActive: boolean;
        notes?: string;
    }) {
        const user = await this.prisma.user.findUnique({
            where: { id: params.targetUserId },
            select: {
                id: true, email: true, firstName: true, lastName: true,
                isActive: true, isSuperAdmin: true,
            },
        });
        if (!user) throw new NotFoundError('User');

        if (params.isActive && !user.isActive) {
            throw new AppError(
                'This account is deactivated and cannot be appointed a referral agent.',
                400,
                'USER_INACTIVE',
            );
        }

        /*
         * Superadmins are not eligible.
         *
         * They can appoint agents, read every agent's figures, and reach the
         * accounts behind them — so crediting referrals to themselves is
         * marking their own homework. Keeping the two roles apart costs
         * nothing and removes the question entirely.
         *
         * Revoking stays allowed, so somebody promoted to superadmin after
         * being appointed can still be cleaned up.
         */
        if (params.isActive && user.isSuperAdmin) {
            throw new AppError(
                'Superadmins cannot be referral agents.',
                400,
                'SUPERADMIN_INELIGIBLE',
            );
        }

        const existing = await this.prisma.referralAgent.findUnique({
            where: { userId: params.targetUserId },
        });

        const agent = existing
            ? await this.prisma.referralAgent.update({
                where: { userId: params.targetUserId },
                data: {
                    isActive: params.isActive,
                    revokedAt: params.isActive ? null : new Date(),
                    ...(params.notes !== undefined ? { notes: params.notes } : {}),
                },
            })
            : await this.prisma.referralAgent.create({
                data: {
                    userId: params.targetUserId,
                    code: await generateUniqueReferralCode(this.prisma),
                    isActive: params.isActive,
                    appointedById: params.actorId,
                    notes: params.notes,
                    revokedAt: params.isActive ? null : new Date(),
                },
            });

        await this.prisma.auditLog.create({
            data: {
                userId: params.actorId,
                action: params.isActive
                    ? AuditAction.REFERRAL_AGENT_APPOINTED
                    : AuditAction.REFERRAL_AGENT_REVOKED,
                resource: 'referral_agent',
                resourceId: agent.id,
                details: {
                    targetUserId: user.id,
                    targetEmail: user.email,
                    code: agent.code,
                    platformAction: AuditAction.ADMIN_WORKSPACE_ACTION,
                } as any,
            },
        });

        return agent;
    }

    async listReferralAgents(params: { page: number; limit: number; search?: string }) {
        const skip = (params.page - 1) * params.limit;
        const where = params.search
            ? {
                OR: [
                    { code: { contains: params.search, mode: 'insensitive' as const } },
                    { user: { email: { contains: params.search, mode: 'insensitive' as const } } },
                    { user: { firstName: { contains: params.search, mode: 'insensitive' as const } } },
                    { user: { lastName: { contains: params.search, mode: 'insensitive' as const } } },
                ],
            }
            : {};

        const [total, agents] = await Promise.all([
            this.prisma.referralAgent.count({ where }),
            this.prisma.referralAgent.findMany({
                where,
                select: {
                    id: true, code: true, isActive: true, appointedAt: true,
                    revokedAt: true, notes: true,
                    user: { select: { id: true, email: true, firstName: true, lastName: true } },
                    _count: { select: { referrals: true } },
                },
                orderBy: { appointedAt: 'desc' },
                skip,
                take: params.limit,
            }),
        ]);

        // Verified is the number that means anything — a signup whose address
        // was never confirmed is not evidence of a person.
        const verifiedCounts = await this.prisma.referral.groupBy({
            by: ['agentId'],
            where: {
                agentId: { in: agents.map((a) => a.id) },
                status: ReferralStatus.VERIFIED,
            },
            _count: { _all: true },
        });
        const verifiedByAgent = new Map(
            verifiedCounts.map((row) => [row.agentId, row._count._all]),
        );

        const data = agents.map((a) => ({
            ...a,
            totals: {
                all: a._count.referrals,
                verified: verifiedByAgent.get(a.id) ?? 0,
            },
        }));

        return { data, total, page: params.page, limit: params.limit };
    }

    async listAgentReferrals(agentId: string, params: { page: number; limit: number }) {
        const agent = await this.prisma.referralAgent.findUnique({
            where: { id: agentId },
            select: { id: true, code: true, user: { select: { email: true, firstName: true, lastName: true } } },
        });
        if (!agent) throw new NotFoundError('Referral agent');

        const skip = (params.page - 1) * params.limit;
        const [total, data] = await Promise.all([
            this.prisma.referral.count({ where: { agentId } }),
            this.prisma.referral.findMany({
                where: { agentId },
                select: {
                    id: true, status: true, source: true, signupMethod: true,
                    attributedAt: true, verifiedAt: true,
                    referredUser: {
                        select: {
                            id: true, email: true, firstName: true, lastName: true,
                            emailVerified: true, createdAt: true,
                        },
                    },
                },
                orderBy: { attributedAt: 'desc' },
                skip,
                take: params.limit,
            }),
        ]);

        return { agent, data, total, page: params.page, limit: params.limit };
    }

    /** Platform-wide audit trail. The old admin module had no way to read this. */
    async listAuditLogs(params: {
        page: number; limit: number; action?: string; workspaceId?: string;
    }) {
        const skip = (params.page - 1) * params.limit;
        const where = {
            ...(params.action ? { action: params.action } : {}),
            ...(params.workspaceId ? { workspaceId: params.workspaceId } : {}),
        };

        const [total, data] = await Promise.all([
            this.prisma.auditLog.count({ where }),
            this.prisma.auditLog.findMany({
                where,
                include: {
                    user: { select: { id: true, email: true, firstName: true, lastName: true } },
                    workspace: { select: { id: true, name: true } },
                },
                orderBy: { createdAt: 'desc' },
                skip,
                take: params.limit,
            }),
        ]);

        return { data, total, page: params.page, limit: params.limit };
    }
}

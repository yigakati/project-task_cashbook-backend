import { Response, NextFunction } from 'express';
import { getPrismaClient } from '../config/database';
import {
    AuthorizationError,
    NotFoundError,
} from '../core/errors/AppError';
import {
    AuthenticatedRequest,
    AuditAction,
    WorkspaceRole,
    CashbookRole,
    WorkspaceType,
    StaffTag,
} from '../core/types';
import { CashbookPermission, hasPermission } from '../core/types/permissions';
import {
    WorkspacePermission,
    hasWorkspacePermission,
} from '../core/types/workspace-permissions';
import { ticketDeskCapabilities, isTicketingEnabled } from '../core/authz/ticketing-access';
import { logger } from '../utils/logger';

const prisma = getPrismaClient();

// ─── Log Permission Failures ───────────────────────────
async function logPermissionDenied(
    userId: string,
    action: string,
    resource: string,
    resourceId?: string,
    details?: Record<string, any>
): Promise<void> {
    try {
        await prisma.auditLog.create({
            data: {
                userId,
                action: AuditAction.PERMISSION_DENIED,
                resource,
                resourceId,
                details: {
                    attemptedAction: action,
                    ...details,
                } as any,
            },
        });
    } catch (error) {
        logger.error('Failed to log permission denial', { error });
    }
}

// ─── Super Admin Guard ─────────────────────────────────
/**
 * Re-reads isSuperAdmin and isActive from the database on every request.
 *
 * The JWT carries an isSuperAdmin claim, but trusting it means a revoked
 * superadmin keeps platform access until their access token expires — and a
 * deactivated account keeps it too. For the most privileged surface in the
 * product, one extra query is the right trade.
 */
export function requireSuperAdmin() {
    return async (req: AuthenticatedRequest, _res: Response, next: NextFunction): Promise<void> => {
        try {
            const userId = req.user?.userId;
            if (!userId) {
                throw new AuthorizationError('Super admin access required');
            }

            const user = await prisma.user.findUnique({
                where: { id: userId },
                select: { isSuperAdmin: true, isActive: true },
            });

            if (!user?.isSuperAdmin || !user.isActive) {
                await logPermissionDenied(userId, 'SUPER_ADMIN_ACCESS', 'system');
                throw new AuthorizationError('Super admin access required');
            }

            next();
        } catch (error) {
            next(error);
        }
    };
}

// ─── Workspace Membership Guard ────────────────────────
/**
 * @param requirement A WorkspacePermission (preferred) or, for routes not yet
 *   migrated, a raw role array. The permission form is what the matrix in
 *   core/types/workspace-permissions.ts exists to serve.
 */
/**
 * `anyOf` — the caller needs at least ONE of these permissions.
 *
 * Member management is why this exists: the route is reachable through two
 * different grants (MANAGE_MEMBERS for owner/admin/HR, the narrower
 * MANAGE_SUB_ACCOUNTANTS for accountants), and which roles each may then hand
 * out is decided in members.service, not here. Expressing that as a single
 * required permission forced one of the two groups out at the door.
 */
export interface AnyOfPermissions {
    anyOf: WorkspacePermission[];
}

const isAnyOf = (r: unknown): r is AnyOfPermissions =>
    typeof r === 'object' && r !== null && Array.isArray((r as AnyOfPermissions).anyOf);

export function requireWorkspaceMember(
    requirement?: WorkspacePermission | WorkspaceRole[] | AnyOfPermissions,
) {
    const requiredPermission =
        typeof requirement === 'string' ? (requirement as WorkspacePermission) : undefined;
    const anyOfPermissions = isAnyOf(requirement) ? requirement.anyOf : undefined;
    const allowedRoles = Array.isArray(requirement) ? requirement : undefined;

    return async (req: AuthenticatedRequest, _res: Response, next: NextFunction): Promise<void> => {
        try {
            const workspaceId = req.params.workspaceId as string;
            const userId = req.user.userId;

            if (!workspaceId) {
                throw new AuthorizationError('Workspace ID is required');
            }

            // Check if workspace exists
            const workspace = await prisma.workspace.findUnique({
                where: { id: workspaceId },
            });

            if (!workspace || !workspace.isActive) {
                throw new NotFoundError('Workspace');
            }

            // Personal workspace: owner-only bypass
            if (workspace.type === WorkspaceType.PERSONAL) {
                if (workspace.ownerId !== userId) {
                    await logPermissionDenied(userId, 'WORKSPACE_ACCESS', 'workspace', workspaceId);
                    throw new AuthorizationError('Access denied to this workspace');
                }
                (req as any).workspace = workspace;
                (req as any).workspaceRole = WorkspaceRole.OWNER;
                next();
                return;
            }

            // Business workspace: check membership
            const membership = await prisma.workspaceMember.findUnique({
                where: {
                    workspaceId_userId: { workspaceId, userId },
                },
            });

            // Also allow workspace owner
            if (!membership && workspace.ownerId !== userId) {
                await logPermissionDenied(userId, 'WORKSPACE_ACCESS', 'workspace', workspaceId);
                throw new AuthorizationError('You are not a member of this workspace');
            }

            const userRole = workspace.ownerId === userId
                ? WorkspaceRole.OWNER
                : (membership!.role as WorkspaceRole);

            if (allowedRoles && !allowedRoles.includes(userRole)) {
                await logPermissionDenied(userId, 'WORKSPACE_ROLE_CHECK', 'workspace', workspaceId, {
                    requiredRoles: allowedRoles,
                    userRole,
                });
                throw new AuthorizationError('Insufficient workspace role');
            }

            if (requiredPermission && !hasWorkspacePermission(userRole, requiredPermission)) {
                await logPermissionDenied(userId, requiredPermission, 'workspace', workspaceId, {
                    userRole,
                });
                throw new AuthorizationError(
                    `You do not have the '${requiredPermission}' permission in this workspace`,
                );
            }

            if (anyOfPermissions
                && !anyOfPermissions.some((p) => hasWorkspacePermission(userRole, p))) {
                await logPermissionDenied(
                    userId, anyOfPermissions.join('|'), 'workspace', workspaceId, { userRole },
                );
                throw new AuthorizationError(
                    `You do not have any of the '${anyOfPermissions.join("', '")}' permissions in this workspace`,
                );
            }

            (req as any).workspace = workspace;
            (req as any).workspaceRole = userRole;
            next();
        } catch (error) {
            next(error);
        }
    };
}

export function requireBusinessWorkspace() {
    return async (req: AuthenticatedRequest, _res: Response, next: NextFunction): Promise<void> => {
        try {
            const workspace = (req as any).workspace;
            const workspaceId = req.params.workspaceId as string;
            const resolvedWorkspace = workspace ?? await prisma.workspace.findUnique({
                where: { id: workspaceId },
                select: { id: true, type: true, isActive: true },
            });

            if (!resolvedWorkspace || !resolvedWorkspace.isActive) {
                throw new NotFoundError('Workspace');
            }

            if (resolvedWorkspace.type !== WorkspaceType.BUSINESS) {
                throw new AuthorizationError('Developer integrations are available for business workspaces only');
            }

            next();
        } catch (error) {
            next(error);
        }
    };
}

// ─── Ticket Desk Guard ─────────────────────────────────
/**
 * Ticketing routes, which are gated on two things the other guards do not check.
 *
 * First the module must exist for this organisation at all — a superadmin
 * unlocks it per org. A workspace without the feature gets a 404 rather than a
 * 403, deliberately: an org that was never granted ticketing should not be able
 * to discover that other orgs have it.
 *
 * Second, authority comes from `ticketDeskCapabilities(role, staffTag)` rather
 * than from the role matrix alone, because a ticket attendant is a plain MEMBER
 * carrying the TICKETING staff tag. See core/authz/ticketing-access.ts for why
 * that lives outside the matrix.
 *
 * Row-level authority — may you void THIS sale, on THIS day — stays in the
 * service, following the same split the tasks module documents: routes gate the
 * module, services gate the row.
 */
export function requireTicketing(
    requiredPermission?: WorkspacePermission,
    options: { reportDisabled?: boolean } = {},
) {
    return async (req: AuthenticatedRequest, _res: Response, next: NextFunction): Promise<void> => {
        try {
            const workspaceId = req.params.workspaceId as string;
            const userId = req.user.userId;

            if (!workspaceId) {
                throw new AuthorizationError('Workspace ID is required');
            }

            const workspace = await prisma.workspace.findUnique({
                where: { id: workspaceId },
            });

            if (!workspace || !workspace.isActive) {
                throw new NotFoundError('Workspace');
            }

            const enabled = await isTicketingEnabled(prisma, workspaceId);
            // Hidden as a 404 everywhere except where the caller is asking
            // precisely "is it on here?" — the /access route. Membership is
            // still checked below either way, so that answer is never given
            // about a workspace the caller does not belong to.
            if (!enabled && !options.reportDisabled) {
                throw new NotFoundError('Ticketing');
            }

            // A personal workspace has no staff to tag and no gate to run, but
            // the owner is still the owner if somebody unlocked the feature.
            let userRole: WorkspaceRole;
            let staffTag: StaffTag | null = null;

            if (workspace.ownerId === userId) {
                userRole = WorkspaceRole.OWNER;
            } else if (workspace.type === WorkspaceType.PERSONAL) {
                await logPermissionDenied(userId, 'TICKETING_ACCESS', 'workspace', workspaceId);
                throw new AuthorizationError('Access denied to this workspace');
            } else {
                const membership = await prisma.workspaceMember.findUnique({
                    where: { workspaceId_userId: { workspaceId, userId } },
                    select: { role: true, staffTag: true },
                });

                if (!membership) {
                    await logPermissionDenied(userId, 'TICKETING_ACCESS', 'workspace', workspaceId);
                    throw new AuthorizationError('You are not a member of this workspace');
                }

                userRole = membership.role as WorkspaceRole;
                staffTag = (membership.staffTag as StaffTag | null) ?? null;
            }

            // No module, no desk: nothing to hold capabilities at.
            const capabilities = enabled
                ? ticketDeskCapabilities(userRole, staffTag)
                : new Set<WorkspacePermission>();

            if (requiredPermission && !capabilities.has(requiredPermission)) {
                await logPermissionDenied(userId, requiredPermission, 'ticketing', workspaceId, {
                    userRole,
                    staffTag,
                });
                throw new AuthorizationError(
                    `You do not have the '${requiredPermission}' permission at the ticket desk`,
                );
            }

            (req as any).workspace = workspace;
            (req as any).workspaceRole = userRole;
            (req as any).staffTag = staffTag;
            (req as any).ticketCapabilities = capabilities;
            (req as any).ticketingEnabled = enabled;
            next();
        } catch (error) {
            next(error);
        }
    };
}

// ─── Cashbook Membership Guard ─────────────────────────
export function requireCashbookMember(requiredPermission?: CashbookPermission) {
    return async (req: AuthenticatedRequest, _res: Response, next: NextFunction): Promise<void> => {
        try {
            const cashbookId = req.params.cashbookId as string;
            const userId = req.user.userId;

            if (!cashbookId) {
                throw new AuthorizationError('Cashbook ID is required');
            }

            const cashbook = await prisma.cashbook.findUnique({
                where: { id: cashbookId },
            });

            if (!cashbook || !cashbook.isActive) {
                throw new NotFoundError('Cashbook');
            }

            // Look up the workspace separately to check type
            const workspace = await prisma.workspace.findUnique({
                where: { id: cashbook.workspaceId },
            });

            // Personal workspace: owner bypass
            if (workspace && workspace.type === WorkspaceType.PERSONAL) {
                if (workspace.ownerId !== userId) {
                    await logPermissionDenied(userId, 'CASHBOOK_ACCESS', 'cashbook', cashbookId);
                    throw new AuthorizationError('Access denied to this cashbook');
                }
                (req as any).cashbook = cashbook;
                (req as any).cashbookRole = CashbookRole.PRIMARY_ADMIN;
                next();
                return;
            }

            // Business workspace: check cashbook membership
            const cbMembership = await prisma.cashbookMember.findUnique({
                where: {
                    cashbookId_userId: { cashbookId, userId },
                },
            });

            // Org roles with ACCESS_ALL_CASHBOOKS reach every book implicitly.
            // Without this, a workspace OWNER could be locked out of a book
            // created by a MEMBER, because the creator becomes its PRIMARY_ADMIN
            // and nothing added the owner as a member.
            let orgRole: WorkspaceRole | null = null;
            if (workspace) {
                if (workspace.ownerId === userId) {
                    orgRole = WorkspaceRole.OWNER;
                } else {
                    const wsMembership = await prisma.workspaceMember.findUnique({
                        where: { workspaceId_userId: { workspaceId: workspace.id, userId } },
                        select: { role: true },
                    });
                    orgRole = (wsMembership?.role as WorkspaceRole) ?? null;
                }
            }

            const hasOrgWideAccess = hasWorkspacePermission(
                orgRole,
                WorkspacePermission.ACCESS_ALL_CASHBOOKS,
            );

            if (!cbMembership && !hasOrgWideAccess) {
                await logPermissionDenied(userId, 'CASHBOOK_ACCESS', 'cashbook', cashbookId);
                throw new AuthorizationError('You do not have access to this cashbook');
            }

            const userRole = cbMembership
                ? (cbMembership.role as CashbookRole)
                : CashbookRole.PRIMARY_ADMIN;

            if (requiredPermission && !hasPermission(userRole, requiredPermission)) {
                await logPermissionDenied(userId, requiredPermission, 'cashbook', cashbookId, {
                    userRole,
                });
                throw new AuthorizationError(
                    `You do not have the '${requiredPermission}' permission for this cashbook`
                );
            }

            (req as any).cashbook = cashbook;
            (req as any).cashbookRole = userRole;
            (req as any).workspaceId = cashbook.workspaceId;
            // Downstream services need the org role too, e.g. to decide whether
            // a sub-accountant may see this book at all.
            (req as any).workspaceRole = orgRole;
            next();
        } catch (error) {
            next(error);
        }
    };
}

// ─── Entry-derived Cashbook Guard ──────────────────────
/**
 * Guard a route that identifies an entry but not its cashbook.
 *
 * Resolves the entry's cashbook, then delegates to `requireCashbookMember` so
 * the same permission matrix applies. Exists because `GET /files/entries/:entryId`
 * carries no cashbookId and was consequently reachable by any authenticated
 * user, for any entry in any workspace.
 */
export function requireEntryAccess(requiredPermission?: CashbookPermission) {
    return async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
        try {
            const entryId = req.params.entryId as string;
            if (!entryId) {
                throw new AuthorizationError('Entry ID is required');
            }

            const entry = await prisma.entry.findUnique({
                where: { id: entryId },
                select: { cashbookId: true },
            });

            if (!entry) {
                throw new NotFoundError('Entry');
            }

            // requireCashbookMember reads cashbookId off params.
            req.params.cashbookId = entry.cashbookId;
            return requireCashbookMember(requiredPermission)(req, res, next);
        } catch (error) {
            next(error);
        }
    };
}

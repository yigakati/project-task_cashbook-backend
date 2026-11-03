import { Prisma } from '@prisma/client';
import { AuthorizationError, NotFoundError } from '../../core/errors/AppError';
import {
    WorkspacePermission,
    hasWorkspacePermission,
} from '../../core/types/workspace-permissions';
import { CashbookPermission, hasPermission } from '../../core/types/permissions';
import { CashbookRole, WorkspaceRole } from '../../core/types';

export async function housingWorkspace(
    tx: Prisma.TransactionClient,
    workspaceId: string,
    userId: string,
    write = false,
) {
    if (!(await tx.user.findFirst({ where: { id: userId, isActive: true, deletedAt: null } })))
        throw new NotFoundError('User');
    const workspace = await tx.workspace.findUnique({
        where: { id: workspaceId },
        include: { members: { where: { userId } } },
    });
    if (!workspace?.isActive) throw new NotFoundError('Workspace');
    const role =
        workspace.ownerId === userId
            ? WorkspaceRole.OWNER
            : workspace.type === 'PERSONAL'
              ? null
              : (workspace.members[0]?.role as WorkspaceRole | undefined);
    if (
        !hasWorkspacePermission(
            role,
            write ? WorkspacePermission.MANAGE_INVENTORY : WorkspacePermission.VIEW_INVENTORY,
        )
    ) {
        throw new AuthorizationError('You cannot manage rentals in this workspace');
    }
    return workspace;
}
export async function rentBook(
    tx: Prisma.TransactionClient,
    id: string,
    workspaceId: string,
    userId: string,
    currency: string,
) {
    const workspace = await housingWorkspace(tx, workspaceId, userId, true);
    const book = await tx.cashbook.findFirst({
        where: { id, workspaceId, isActive: true, archivedAt: null, currency },
        include: { members: { where: { userId } } },
    });
    if (!book) throw new NotFoundError('Active cashbook in the tenancy currency');
    const role =
        workspace.ownerId === userId
            ? WorkspaceRole.OWNER
            : (workspace.members[0]?.role as WorkspaceRole);
    const explicit = book.members[0]?.role as CashbookRole | undefined;
    if (
        workspace.type !== 'PERSONAL' &&
        !(explicit
            ? hasPermission(explicit, CashbookPermission.CREATE_ENTRY)
            : hasWorkspacePermission(role, WorkspacePermission.ACCESS_ALL_CASHBOOKS))
    ) {
        throw new AuthorizationError('You cannot record entries in this book');
    }
    return book;
}
/** Tenant notifications belong to a workspace the tenant can actually open.
 * The landlord's workspace must never be used as their notification inbox. */
export async function rentalNotify(
    tx: Prisma.TransactionClient,
    userId: string | null,
    data: {
        type: 'HOUSING_INVITATION' | 'HOUSING_UPDATED' | 'RENT_DUE' | 'RENTAL_ISSUE_UPDATED';
        entityType: 'HOUSING_TENANCY' | 'RENTAL_ISSUE';
        entityId: string;
        title: string;
        body: string;
        groupKey: string;
    },
    preferredWorkspaceId?: string,
) {
    if (
        !userId ||
        !(await tx.user.findFirst({
            where: { id: userId, isActive: true, deletedAt: null },
            select: { id: true },
        }))
    )
        return;
    const workspace = preferredWorkspaceId
        ? await tx.workspace.findFirst({
              where: {
                  id: preferredWorkspaceId,
                  isActive: true,
                  OR: [{ ownerId: userId }, { type: 'BUSINESS', members: { some: { userId } } }],
              },
          })
        : ((await tx.workspace.findFirst({
              where: { ownerId: userId, type: 'PERSONAL', isActive: true },
          })) ??
          (await tx.workspace.findFirst({
              where: { ownerId: userId, isActive: true },
              orderBy: { createdAt: 'asc' },
          })));
    if (!workspace) return;
    await tx.notification.upsert({
        where: { userId_type_groupKey: { userId, type: data.type, groupKey: data.groupKey } },
        create: { userId, workspaceId: workspace.id, ...data },
        update: {},
    });
}

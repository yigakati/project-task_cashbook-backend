import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import { WorkspacesRepository } from './workspaces.repository';
import { NotFoundError, AuthorizationError, AppError } from '../../core/errors/AppError';
import { WorkspaceType, WorkspaceRole, AuditAction } from '../../core/types';
import { CreateWorkspaceDto, UpdateWorkspaceDto } from './workspaces.dto';
import { assertEastAfricanCurrency } from '../../core/finance';
import { provisionWorkspaceAccounting, seedDefaultWalletAccounts } from '../../core/ledger/coa.seed';

@injectable()
export class WorkspacesService {
    constructor(
        private workspacesRepository: WorkspacesRepository,
        @inject('PrismaClient') private prisma: PrismaClient,
    ) { }

    async getUserWorkspaces(userId: string) {
        return this.workspacesRepository.findUserWorkspaces(userId);
    }

    async getWorkspace(workspaceId: string, userId: string) {
        const workspace = await this.workspacesRepository.findById(workspaceId);
        if (!workspace || !workspace.isActive) {
            throw new NotFoundError('Workspace');
        }
        return workspace;
    }

    async createBusinessWorkspace(userId: string, dto: CreateWorkspaceDto) {
        const defaultCurrency = assertEastAfricanCurrency(dto.defaultCurrency || 'UGX');
        const workspace = await this.prisma.$transaction(async (tx) => {
            const ws = await tx.workspace.create({
                data: {
                    name: dto.name,
                    type: WorkspaceType.BUSINESS,
                    ownerId: userId,
                    defaultCurrency,
                },
                include: {
                    owner: {
                        select: { id: true, email: true, firstName: true, lastName: true },
                    },
                },
            });

            // Owner is automatically the first member
            await tx.workspaceMember.create({
                data: {
                    workspaceId: ws.id,
                    userId,
                    role: WorkspaceRole.OWNER,
                },
            });

            // Chart of accounts + default wallet types. Without this the
            // workspace cannot post a journal, and (before the ledger existed)
            // could not even create a wallet, since nothing seeded AccountType.
            await provisionWorkspaceAccounting(tx, ws.id, defaultCurrency);

            // The three obvious wallets — Mobile Money, Bank, Cash on Hand —
            // so the workspace opens with something to attach entries to.
            await seedDefaultWalletAccounts(tx, ws.id, defaultCurrency, userId);

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: ws.id,
                    action: AuditAction.WORKSPACE_CREATED,
                    resource: 'workspace',
                    resourceId: ws.id,
                    details: { name: dto.name, defaultCurrency } as any,
                },
            });

            return ws;
        });

        return workspace;
    }

    async updateWorkspace(workspaceId: string, userId: string, dto: UpdateWorkspaceDto) {
        const workspace = await this.workspacesRepository.findById(workspaceId);
        if (!workspace || !workspace.isActive) {
            throw new NotFoundError('Workspace');
        }

        if (workspace.ownerId !== userId) {
            // Check if user is an admin
            const membership = await this.prisma.workspaceMember.findUnique({
                where: { workspaceId_userId: { workspaceId, userId } },
            });
            if (!membership || (membership.role !== 'OWNER' && membership.role !== 'ADMIN')) {
                throw new AuthorizationError('Only workspace owner or admin can update workspace');
            }
        }

        if (dto.defaultCurrency !== undefined) {
            const nextCurrency = assertEastAfricanCurrency(dto.defaultCurrency);
            if (nextCurrency !== workspace.defaultCurrency) {
                throw new AppError(
                    'Workspace base currency cannot be changed after creation',
                    400,
                    'BASE_CURRENCY_LOCKED',
                );
            }
        }

        const updated = await this.workspacesRepository.update(workspaceId, {
            ...(dto.name !== undefined && { name: dto.name }),
        });

        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.WORKSPACE_UPDATED,
                resource: 'workspace',
                resourceId: workspaceId,
                details: dto as any,
            },
        });

        return updated;
    }

    async deleteWorkspace(workspaceId: string, userId: string) {
        const workspace = await this.workspacesRepository.findById(workspaceId);
        if (!workspace || !workspace.isActive) {
            throw new NotFoundError('Workspace');
        }

        if (workspace.type === 'PERSONAL') {
            throw new AppError('Cannot delete personal workspace', 400, 'INVALID_OPERATION');
        }

        if (workspace.ownerId !== userId) {
            throw new AuthorizationError('Only the workspace owner can delete it');
        }

        await this.workspacesRepository.softDelete(workspaceId);

        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.WORKSPACE_DELETED,
                resource: 'workspace',
                resourceId: workspaceId,
            },
        });
    }
}

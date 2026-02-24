import { injectable } from 'tsyringe';
import { AccountTypesRepository } from './account-types.repository';
import { CreateAccountTypeBody, UpdateAccountTypeBody } from './account-types.dto';
import { AppError, NotFoundError, ConflictError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';
import { getPrismaClient } from '../../config/database';

@injectable()
export class AccountTypesService {
    constructor(private repository: AccountTypesRepository) { }

    async createAccountType(workspaceId: string, userId: string, data: CreateAccountTypeBody) {
        // Enforce uniqueness by name + workspace
        const existing = await this.repository.findByNameAndWorkspace(data.name, workspaceId);
        if (existing) {
            throw new ConflictError('Account type with this name already exists in this workspace');
        }

        const accountType = await this.repository.create({
            workspaceId,
            name: data.name,
            classification: data.classification
        });

        // Audit Logging
        await getPrismaClient().auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.ACCOUNT_TYPE_CREATED || 'ACCOUNT_TYPE_CREATED',
                resource: 'account_type',
                resourceId: accountType.id,
                details: { name: accountType.name, classification: accountType.classification } as any
            }
        });

        return accountType;
    }

    async getWorkspaceAccountTypes(workspaceId: string) {
        return this.repository.findAllByWorkspace(workspaceId);
    }

    async updateAccountType(id: string, workspaceId: string, userId: string, data: UpdateAccountTypeBody) {
        const accountType = await this.repository.findById(id);
        if (!accountType || accountType.workspaceId !== workspaceId) {
            throw new NotFoundError('Account Type');
        }

        if (data.name && data.name !== accountType.name) {
            const existing = await this.repository.findByNameAndWorkspace(data.name, workspaceId);
            if (existing) {
                throw new ConflictError('Account type with this name already exists in this workspace');
            }
        }

        const updated = await this.repository.update(id, data);

        await getPrismaClient().auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.ACCOUNT_TYPE_UPDATED || 'ACCOUNT_TYPE_UPDATED',
                resource: 'account_type',
                resourceId: accountType.id,
                details: { old: { name: accountType.name }, new: data } as any
            }
        });

        return updated;
    }

    async deleteAccountType(id: string, workspaceId: string, userId: string) {
        const accountType = await this.repository.findById(id);
        if (!accountType || accountType.workspaceId !== workspaceId) {
            throw new NotFoundError('Account Type');
        }

        // Prevent deletion if linked to accounts
        const linkedAccountsCount = await this.repository.countAccountsByType(id);
        if (linkedAccountsCount > 0) {
            throw new AppError('Cannot delete account type because it is used by existing accounts.', 400, 'DELETE_RESTRICTED');
        }

        await this.repository.delete(id);

        await getPrismaClient().auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.ACCOUNT_TYPE_DELETED || 'ACCOUNT_TYPE_DELETED',
                resource: 'account_type',
                resourceId: id,
                details: { name: accountType.name } as any
            }
        });
    }
}

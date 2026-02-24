import { injectable } from 'tsyringe';
import { AccountsRepository } from './accounts.repository';
import { CreateAccountBody, UpdateAccountBody, ArchiveAccountBody } from './accounts.dto';
import { AppError, NotFoundError, ConflictError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';
import { getPrismaClient } from '../../config/database';

@injectable()
export class AccountsService {
    constructor(private repository: AccountsRepository) { }

    async createAccount(workspaceId: string, userId: string, data: CreateAccountBody) {
        // Validate accountType belongs to workspace
        const accountType = await getPrismaClient().accountType.findUnique({
            where: { id: data.accountTypeId }
        });

        if (!accountType || accountType.workspaceId !== workspaceId) {
            throw new AppError('Invalid account type provided', 400, 'INVALID_ACCOUNT_TYPE');
        }

        const account = await this.repository.create({
            workspaceId,
            ...data
        });

        await getPrismaClient().auditLog.create({
            data: {
                userId,
                workspaceId,
                action: 'ACCOUNT_CREATED' as AuditAction,
                resource: 'account',
                resourceId: account.id,
                details: { name: account.name, type: accountType.name, currency: account.currency } as any
            }
        });

        return account;
    }

    async getWorkspaceAccounts(workspaceId: string) {
        return this.repository.findAllByWorkspace(workspaceId);
    }

    async getAccountById(id: string, workspaceId: string) {
        const account = await this.repository.findById(id);
        if (!account || account.workspaceId !== workspaceId) {
            throw new NotFoundError('Account');
        }
        return account;
    }

    async updateAccount(id: string, workspaceId: string, userId: string, data: UpdateAccountBody) {
        const account = await this.repository.findById(id);
        if (!account || account.workspaceId !== workspaceId) {
            throw new NotFoundError('Account');
        }

        const updated = await this.repository.update(id, data);

        await getPrismaClient().auditLog.create({
            data: {
                userId,
                workspaceId,
                action: 'ACCOUNT_UPDATED' as AuditAction,
                resource: 'account',
                resourceId: account.id,
                details: { old: { name: account.name, allowNegative: account.allowNegative }, new: data } as any
            }
        });

        return updated;
    }

    async setAccountArchiveStatus(id: string, workspaceId: string, userId: string, data: ArchiveAccountBody) {
        const account = await this.repository.findById(id);
        if (!account || account.workspaceId !== workspaceId) {
            throw new NotFoundError('Account');
        }

        if (account.balance.toNumber() !== 0 && data.archive) {
            throw new AppError('Cannot archive an account with a non-zero balance.', 400, 'ARCHIVE_RESTRICTED');
        }

        const updated = await this.repository.update(id, {
            archivedAt: data.archive ? new Date() : null
        });

        await getPrismaClient().auditLog.create({
            data: {
                userId,
                workspaceId,
                action: data.archive ? 'ACCOUNT_ARCHIVED' as AuditAction : 'ACCOUNT_UNARCHIVED' as AuditAction,
                resource: 'account',
                resourceId: account.id,
                details: { status: data.archive ? 'archived' : 'active' } as any
            }
        });

        return updated;
    }

    async deleteAccount(id: string, workspaceId: string, userId: string) {
        const account = await this.repository.findById(id);
        if (!account || account.workspaceId !== workspaceId) {
            throw new NotFoundError('Account');
        }

        // Prevent deletion if transactions exist
        const transactionsCount = await this.repository.countTransactions(id);
        if (transactionsCount > 0) {
            throw new AppError('Cannot delete account because it has recorded transactions. Please archive it instead.', 400, 'DELETE_RESTRICTED');
        }

        await this.repository.delete(id);

        await getPrismaClient().auditLog.create({
            data: {
                userId,
                workspaceId,
                action: 'ACCOUNT_DELETED' as AuditAction,
                resource: 'account',
                resourceId: id,
                details: { name: account.name } as any
            }
        });
    }

    async calculateNetWorth(workspaceId: string) {
        const accounts = await this.repository.findAllByWorkspace(workspaceId);

        let assets = 0;
        let liabilities = 0;
        const breakdown: { accountId: string; name: string; type: string; classification: string; balance: number; currency: string }[] = [];

        accounts.forEach(account => {
            // Skip archived or explicitly excluded accounts
            if (account.archivedAt || account.excludeFromTotal) return;

            const balance = account.balance.toNumber();
            const classification = account.accountType.classification;

            breakdown.push({
                accountId: account.id,
                name: account.name,
                type: account.accountType.name,
                classification,
                balance,
                currency: account.currency
            });

            // If an asset has a positive balance, it's an asset. If negative, it acts as a liability.
            // If a liability has a positive balance (meaning you owe), it's a liability. 
            // The exact addition/subtraction depends on the specific accounting equation desired.
            // Standard approach: Net Worth = Assets - Liabilities
            if (classification === 'ASSET') {
                assets += balance;
            } else if (classification === 'LIABILITY') {
                liabilities += balance; // Assuming positive liabilities means debt
            }
        });

        const netWorth = assets - liabilities;

        return {
            netWorth,
            assets,
            liabilities,
            breakdown
        };
    }
}

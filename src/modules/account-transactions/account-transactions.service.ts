import { injectable } from 'tsyringe';
import { AccountTransactionsRepository } from './account-transactions.repository';
import { CreateAccountTransactionBody, UpdateAccountTransactionBody } from './account-transactions.dto';
import { AppError, NotFoundError } from '../../core/errors/AppError';
import { AuditAction, EntryType } from '../../core/types';
import { getPrismaClient } from '../../config/database';
import { Decimal } from '@prisma/client/runtime/library';
import { TransactionSourceType } from '@prisma/client';

@injectable()
export class AccountTransactionsService {
    constructor(private repository: AccountTransactionsRepository) { }

    async getAllTransactionsByAccount(accountId: string, workspaceId: string, pagination?: { skip: number; take: number }) {
        return this.repository.findAllByAccount(accountId, workspaceId, pagination);
    }

    async createDirectTransaction(
        workspaceId: string,
        accountId: string,
        userId: string,
        data: CreateAccountTransactionBody
    ) {
        const amount = new Decimal(data.amount);
        const isIncome = data.type === EntryType.INCOME;

        return getPrismaClient().$transaction(async (tx) => {
            // Lock account row for updates
            await tx.$queryRaw`SELECT id FROM accounts WHERE id = ${accountId}::uuid FOR UPDATE`;

            const account = await tx.account.findUnique({ where: { id: accountId } });

            if (!account || account.workspaceId !== workspaceId) {
                throw new NotFoundError('Account');
            }

            if (account.archivedAt) {
                throw new AppError('Cannot create transactions for an archived account', 400, 'ACCOUNT_ARCHIVED');
            }

            if (data.accountCategoryId) {
                const category = await tx.accountCategory.findUnique({
                    where: { id: data.accountCategoryId }
                });
                if (!category || category.workspaceId !== workspaceId) {
                    throw new AppError('Invalid account category provided', 400, 'INVALID_CATEGORY');
                }
            }

            const currentBalance = account.balance;
            let newBalance = isIncome ? currentBalance.add(amount) : currentBalance.sub(amount);

            if (!account.allowNegative && newBalance.lessThan(0)) {
                throw new AppError(`Transaction exceeds account balance. Current balance is ${currentBalance.toString()}`, 400, 'INSUFFICIENT_FUNDS');
            }

            await tx.account.update({
                where: { id: accountId },
                data: {
                    balance: isIncome ? { increment: amount } : { decrement: amount }
                }
            });

            const transaction = await tx.accountTransaction.create({
                data: {
                    workspaceId,
                    accountId,
                    sourceType: TransactionSourceType.DIRECT,
                    type: data.type as any,
                    amount,
                    description: data.description,
                    accountCategoryId: data.accountCategoryId
                }
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.ACCOUNT_TRANSACTION_DIRECT_CREATED as any,
                    resource: 'account_transaction',
                    resourceId: transaction.id,
                    details: {
                        previous_balance: currentBalance,
                        new_balance: newBalance,
                        delta: isIncome ? amount : amount.negated(),
                        type: data.type,
                        amount: amount
                    } as any
                }
            });

            return transaction;
        });
    }

    async updateDirectTransaction(
        id: string,
        workspaceId: string,
        accountId: string,
        userId: string,
        data: UpdateAccountTransactionBody
    ) {
        return getPrismaClient().$transaction(async (tx) => {
            await tx.$queryRaw`SELECT id FROM accounts WHERE id = ${accountId}::uuid FOR UPDATE`;
            const account = await tx.account.findUnique({ where: { id: accountId } });

            if (!account || account.workspaceId !== workspaceId) {
                throw new NotFoundError('Account');
            }

            const transaction = await tx.accountTransaction.findUnique({ where: { id } });
            if (!transaction || transaction.workspaceId !== workspaceId || transaction.accountId !== accountId) {
                throw new NotFoundError('Account Transaction');
            }

            if (transaction.sourceType !== TransactionSourceType.DIRECT) {
                throw new AppError('Linked transactions can only be updated via cashbook entries.', 403, 'FORBIDDEN');
            }

            if (data.accountCategoryId) {
                const category = await tx.accountCategory.findUnique({ where: { id: data.accountCategoryId } });
                if (!category || category.workspaceId !== workspaceId) {
                    throw new AppError('Invalid account category provided', 400, 'INVALID_CATEGORY');
                }
            }

            const currentBalance = account.balance;
            const oldAmount = transaction.amount;
            const wasIncome = transaction.type === EntryType.INCOME;
            let balanceWithoutTx = wasIncome ? currentBalance.sub(oldAmount) : currentBalance.add(oldAmount);

            const newType = data.type || transaction.type;
            const newAmount = data.amount ? new Decimal(data.amount) : transaction.amount;
            const isIncome = newType === EntryType.INCOME;

            let newBalance = isIncome ? balanceWithoutTx.add(newAmount) : balanceWithoutTx.sub(newAmount);

            if (!account.allowNegative && newBalance.lessThan(0)) {
                throw new AppError('Transaction exceeds account balance.', 400, 'INSUFFICIENT_FUNDS');
            }

            await tx.account.update({
                where: { id: accountId },
                data: { balance: newBalance }
            });

            const updatedTransaction = await tx.accountTransaction.update({
                where: { id },
                data: {
                    ...(data.type && { type: data.type as any }),
                    ...(data.amount && { amount: newAmount }),
                    ...(data.description && { description: data.description }),
                    ...(data.accountCategoryId !== undefined && { accountCategoryId: data.accountCategoryId })
                }
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.ACCOUNT_TRANSACTION_DIRECT_UPDATED as any,
                    resource: 'account_transaction',
                    resourceId: id,
                    details: {
                        previous_balance: currentBalance,
                        new_balance: newBalance,
                        delta: newBalance.sub(currentBalance),
                        changes: data
                    } as any
                }
            });

            return updatedTransaction;
        });
    }

    async deleteDirectTransaction(
        id: string,
        workspaceId: string,
        accountId: string,
        userId: string
    ) {
        return getPrismaClient().$transaction(async (tx) => {
            await tx.$queryRaw`SELECT id FROM accounts WHERE id = ${accountId}::uuid FOR UPDATE`;
            const account = await tx.account.findUnique({ where: { id: accountId } });

            if (!account || account.workspaceId !== workspaceId) {
                throw new NotFoundError('Account');
            }

            const transaction = await tx.accountTransaction.findUnique({ where: { id } });
            if (!transaction || transaction.workspaceId !== workspaceId || transaction.accountId !== accountId) {
                throw new NotFoundError('Account Transaction');
            }

            if (transaction.sourceType !== TransactionSourceType.DIRECT) {
                throw new AppError('Linked transactions can only be deleted via cashbook entries.', 403, 'FORBIDDEN');
            }

            const currentBalance = account.balance;
            const oldAmount = transaction.amount;
            const wasIncome = transaction.type === EntryType.INCOME;

            let newBalance = wasIncome ? currentBalance.sub(oldAmount) : currentBalance.add(oldAmount);

            if (!account.allowNegative && newBalance.lessThan(0)) {
                throw new AppError('Reversing this transaction would exceed the account balance limit.', 400, 'INSUFFICIENT_FUNDS');
            }

            await tx.account.update({
                where: { id: accountId },
                data: { balance: newBalance }
            });

            await tx.accountTransaction.delete({ where: { id } });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.ACCOUNT_TRANSACTION_DIRECT_DELETED as any,
                    resource: 'account_transaction',
                    resourceId: id,
                    details: {
                        previous_balance: currentBalance,
                        new_balance: newBalance,
                        delta: newBalance.sub(currentBalance)
                    } as any
                }
            });
        });
    }
}

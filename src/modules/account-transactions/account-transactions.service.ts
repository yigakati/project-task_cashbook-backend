import { injectable, inject } from 'tsyringe';
import { PrismaClient, TransactionSourceType } from '@prisma/client';
import { AccountTransactionsRepository } from './account-transactions.repository';
import { CreateAccountTransactionBody, UpdateAccountTransactionBody } from './account-transactions.dto';
import { AppError, NotFoundError } from '../../core/errors/AppError';
import { AuditAction, EntryType } from '../../core/types';
import { Decimal } from '@prisma/client/runtime/library';
import { InventoryService } from '../inventory/inventory.service';

@injectable()
export class AccountTransactionsService {
    constructor(
        private repository: AccountTransactionsRepository,
        @inject('PrismaClient') private prisma: PrismaClient,
        private inventoryService: InventoryService,
    ) { }

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
        const chargeAmount = data.chargeAmount ? new Decimal(data.chargeAmount) : new Decimal(0);
        const effectiveAmount = isIncome ? amount.sub(chargeAmount) : amount.add(chargeAmount);

        return this.prisma.$transaction(async (tx) => {
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

            const balanceBefore = account.balance;

            // Negative balance guard
            if (!account.allowNegative && !isIncome) {
                const newBalance = balanceBefore.sub(effectiveAmount);
                if (newBalance.lessThan(0)) {
                    throw new AppError(`Transaction exceeds account balance. Current balance is ${balanceBefore.toString()}`, 400, 'INSUFFICIENT_FUNDS');
                }
            }

            // Use increment/decrement for atomic balance update (Issue 8)
            await tx.account.update({
                where: { id: accountId },
                data: {
                    balance: isIncome ? { increment: effectiveAmount } : { decrement: effectiveAmount }
                }
            });

            const balanceAfter = isIncome ? balanceBefore.add(effectiveAmount) : balanceBefore.sub(effectiveAmount);

            const transaction = await tx.accountTransaction.create({
                data: {
                    workspaceId,
                    accountId,
                    sourceType: TransactionSourceType.DIRECT,
                    type: data.type as any,
                    amount,
                    chargeAmount: chargeAmount.greaterThan(0) ? chargeAmount : null,
                    description: data.description,
                    accountCategoryId: data.accountCategoryId
                }
            });

            // Generic audit log
            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.ACCOUNT_TRANSACTION_DIRECT_CREATED as any,
                    resource: 'account_transaction',
                    resourceId: transaction.id,
                    details: {
                        previous_balance: balanceBefore.toString(),
                        new_balance: balanceAfter.toString(),
                        delta: isIncome ? effectiveAmount.toString() : effectiveAmount.negated().toString(),
                        type: data.type,
                        amount: amount.toString(),
                        ...(chargeAmount.greaterThan(0) ? { chargeAmount: chargeAmount.toString() } : {})
                    } as any
                }
            });

            // Financial audit log (Issue 6)
            await tx.financialAuditLog.create({
                data: {
                    userId,
                    workspaceId,
                    accountId,
                    action: AuditAction.ACCOUNT_TRANSACTION_DIRECT_CREATED as any,
                    amount,
                    balanceBefore,
                    balanceAfter,
                    details: {
                        accountName: account.name,
                        type: data.type,
                        sourceType: 'DIRECT',
                        transactionId: transaction.id,
                        ...(chargeAmount.greaterThan(0) ? { chargeAmount: chargeAmount.toString() } : {})
                    },
                }
            });

            // ─── Inventory Integration (non-intrusive) ─────────────
            if (data.inventoryItems && data.inventoryItems.length > 0) {
                await this.inventoryService.processAccountTransactionInventory(
                    tx,
                    workspaceId,
                    transaction.id,
                    data.type,
                    amount,
                    data.inventoryItems,
                    userId,
                );
            }

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
        return this.prisma.$transaction(async (tx) => {
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

            const balanceBefore = account.balance;
            const oldAmount = transaction.amount;
            const wasIncome = transaction.type === EntryType.INCOME;
            const oldChargeAmount = transaction.chargeAmount || new Decimal(0);
            const oldEffectiveAmount = wasIncome ? oldAmount.sub(oldChargeAmount) : oldAmount.add(oldChargeAmount);

            const newType = data.type || transaction.type;
            const newAmount = data.amount ? new Decimal(data.amount) : transaction.amount;
            const isIncome = newType === EntryType.INCOME;
            const newChargeAmount = data.chargeAmount !== undefined
                ? (data.chargeAmount ? new Decimal(data.chargeAmount) : new Decimal(0))
                : (transaction.chargeAmount || new Decimal(0));
            const newEffectiveAmount = isIncome ? newAmount.sub(newChargeAmount) : newAmount.add(newChargeAmount);

            // Reverse old effect, then apply new (using increment/decrement — Issue 8)
            // Step 1: Reverse old
            await tx.account.update({
                where: { id: accountId },
                data: {
                    balance: wasIncome ? { decrement: oldEffectiveAmount } : { increment: oldEffectiveAmount }
                }
            });

            // Step 2: Apply new
            const balanceWithoutTx = wasIncome ? balanceBefore.sub(oldEffectiveAmount) : balanceBefore.add(oldEffectiveAmount);

            // Negative balance guard
            if (!account.allowNegative && !isIncome) {
                const provisional = balanceWithoutTx.sub(newEffectiveAmount);
                if (provisional.lessThan(0)) {
                    throw new AppError('Transaction exceeds account balance.', 400, 'INSUFFICIENT_FUNDS');
                }
            }

            await tx.account.update({
                where: { id: accountId },
                data: {
                    balance: isIncome ? { increment: newEffectiveAmount } : { decrement: newEffectiveAmount }
                }
            });

            const balanceAfter = isIncome ? balanceWithoutTx.add(newEffectiveAmount) : balanceWithoutTx.sub(newEffectiveAmount);

            const updatedTransaction = await tx.accountTransaction.update({
                where: { id },
                data: {
                    ...(data.type && { type: data.type as any }),
                    ...(data.amount && { amount: newAmount }),
                    ...(data.chargeAmount !== undefined ? { chargeAmount: data.chargeAmount ? new Decimal(data.chargeAmount) : null } : {}),
                    ...(data.description && { description: data.description }),
                    ...(data.accountCategoryId !== undefined && { accountCategoryId: data.accountCategoryId })
                }
            });

            // Generic audit log
            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.ACCOUNT_TRANSACTION_DIRECT_UPDATED as any,
                    resource: 'account_transaction',
                    resourceId: id,
                    details: {
                        previous_balance: balanceBefore.toString(),
                        new_balance: balanceAfter.toString(),
                        delta: balanceAfter.sub(balanceBefore).toString(),
                        changes: data,
                        ...(newChargeAmount.greaterThan(0) ? { chargeAmount: newChargeAmount.toString() } : {})
                    } as any
                }
            });

            // Financial audit log
            await tx.financialAuditLog.create({
                data: {
                    userId,
                    workspaceId,
                    accountId,
                    action: AuditAction.ACCOUNT_TRANSACTION_DIRECT_UPDATED as any,
                    amount: newAmount,
                    balanceBefore,
                    balanceAfter,
                    details: {
                        transactionId: id,
                        sourceType: 'DIRECT',
                        changes: data
                    },
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
        return this.prisma.$transaction(async (tx) => {
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

            const balanceBefore = account.balance;
            const oldAmount = transaction.amount;
            const wasIncome = transaction.type === EntryType.INCOME;
            const chargeAmount = transaction.chargeAmount || new Decimal(0);
            const effectiveAmount = wasIncome ? oldAmount.sub(chargeAmount) : oldAmount.add(chargeAmount);

            // Negative balance guard
            if (!account.allowNegative && wasIncome) {
                const provisional = balanceBefore.sub(effectiveAmount);
                if (provisional.lessThan(0)) {
                    throw new AppError('Reversing this transaction would exceed the account balance limit.', 400, 'INSUFFICIENT_FUNDS');
                }
            }

            // Use increment/decrement for atomic balance update (Issue 8)
            await tx.account.update({
                where: { id: accountId },
                data: {
                    balance: wasIncome ? { decrement: effectiveAmount } : { increment: effectiveAmount }
                }
            });

            const balanceAfter = wasIncome ? balanceBefore.sub(effectiveAmount) : balanceBefore.add(effectiveAmount);

            await tx.accountTransaction.delete({ where: { id } });

            // Generic audit log
            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.ACCOUNT_TRANSACTION_DIRECT_DELETED as any,
                    resource: 'account_transaction',
                    resourceId: id,
                    details: {
                        previous_balance: balanceBefore.toString(),
                        new_balance: balanceAfter.toString(),
                        delta: balanceAfter.sub(balanceBefore).toString()
                    } as any
                }
            });

            // Financial audit log
            await tx.financialAuditLog.create({
                data: {
                    userId,
                    workspaceId,
                    accountId,
                    action: AuditAction.ACCOUNT_TRANSACTION_DIRECT_DELETED as any,
                    amount: oldAmount,
                    balanceBefore,
                    balanceAfter,
                    details: {
                        transactionId: id,
                        sourceType: 'DIRECT',
                    },
                }
            });
        });
    }
}

import { injectable, inject } from 'tsyringe';
import { PrismaClient, TransactionSourceType, EntryType } from '@prisma/client';
import { AccountsRepository } from './accounts.repository';
import {
    CreateAccountBody,
    UpdateAccountBody,
    ArchiveAccountBody,
    CreateAccountTransferBody,
} from './accounts.dto';
import { AppError, NotFoundError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';
import { Decimal } from '@prisma/client/runtime/library';
import { assertSameCurrency, normalizeCurrency, recomputeWalletBalance } from '../../core/finance';
import { withFinancialTransaction } from '../../core/db/transaction';
import { acquireLocks } from '../../core/db/locks';
import { ensureWalletLedgerAccount } from '../../core/ledger/coa.seed';
import { config } from '../../config';
import { PostingService } from '../../core/ledger/posting.service';
import {
    buildOpeningBalanceJournal,
    buildTransferJournal,
} from '../../core/ledger/rules/wallet.rules';

@injectable()
export class AccountsService {
    constructor(
        private repository: AccountsRepository,
        @inject('PrismaClient') private prisma: PrismaClient,
        private postingService: PostingService,
    ) { }

    async createAccount(workspaceId: string, userId: string, data: CreateAccountBody) {
        return this.prisma.$transaction(async (tx) => {
            const workspace = await tx.workspace.findUnique({ where: { id: workspaceId } });
            if (!workspace || !workspace.isActive) {
                throw new NotFoundError('Workspace');
            }
            const workspaceCurrency = normalizeCurrency(workspace.defaultCurrency);
            if (data.currency) {
                assertSameCurrency(workspaceCurrency, data.currency, 'workspace base vs account');
            }

            // Validate accountType belongs to workspace
            const accountType = await tx.accountType.findUnique({
                where: { id: data.accountTypeId }
            });

            if (!accountType || accountType.workspaceId !== workspaceId) {
                throw new AppError('Invalid account type provided', 400, 'INVALID_ACCOUNT_TYPE');
            }

            const { initialBalance, ...accountData } = data;
            const initialAmount = new Decimal(initialBalance || '0');
            const hasInitialBalance = !initialAmount.equals(0);

            const account = await tx.account.create({
                data: {
                    workspaceId,
                    ...accountData,
                    currency: workspaceCurrency,
                    // Starts at zero; the opening-balance journal below moves it.
                    // Setting it here as well would double the balance.
                    balance: config.LEDGER_MODE === 'on' ? new Decimal(0) : initialAmount,
                },
                include: { accountType: true }
            });

            // Every wallet gets a ledger account, so wallet movements are real
            // journal lines rather than a parallel balance.
            await ensureWalletLedgerAccount(tx, account, accountType.classification);

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.ACCOUNT_CREATED,
                    resource: 'account',
                    resourceId: account.id,
                    details: { name: account.name, type: accountType.name, currency: account.currency, initialBalance: hasInitialBalance ? initialAmount.toString() : '0' } as any
                }
            });

            // If an initial balance is provided, create a direct transaction to back it up
            if (hasInitialBalance) {
                const isIncome = initialAmount.greaterThan(0);
                const absAmount = initialAmount.abs();
                const transactionType = isIncome ? EntryType.INCOME : EntryType.EXPENSE;

                const transaction = await tx.accountTransaction.create({
                    data: {
                        workspaceId,
                        accountId: account.id,
                        sourceType: TransactionSourceType.DIRECT,
                        type: transactionType,
                        amount: absAmount,
                        description: 'Initial Balance',
                        // Opening balance is as-of account creation.
                        transactionDate: account.createdAt,
                    }
                });

                // Dr Wallet / Cr Opening Balance Equity — the standard way to
                // introduce a starting balance without inventing income.
                if (config.LEDGER_MODE !== 'off') {
                    await this.postingService.post(
                        tx,
                        buildOpeningBalanceJournal({
                            workspaceId,
                            accountId: account.id,
                            amount: initialAmount,
                            accountName: account.name,
                            openedAt: account.createdAt,
                            currency: account.currency,
                            createdById: userId,
                        }),
                        { applyCaches: config.LEDGER_MODE === 'on', onDuplicate: 'RETURN_EXISTING' },
                    );
                }

                // Generic audit log for this opening transaction
                await tx.auditLog.create({
                    data: {
                        userId,
                        workspaceId,
                        action: AuditAction.ACCOUNT_TRANSACTION_DIRECT_CREATED as any,
                        resource: 'account_transaction',
                        resourceId: transaction.id,
                        details: {
                            previous_balance: '0',
                            new_balance: initialAmount.toString(),
                            delta: initialAmount.toString(),
                            type: transactionType,
                            amount: absAmount.toString()
                        } as any
                    }
                });

                // Financial audit log
                await tx.financialAuditLog.create({
                    data: {
                        userId,
                        workspaceId,
                        accountId: account.id,
                        action: AuditAction.ACCOUNT_TRANSACTION_DIRECT_CREATED as any,
                        amount: absAmount,
                        balanceBefore: new Decimal(0),
                        balanceAfter: initialAmount,
                        details: {
                            accountName: account.name,
                            type: transactionType,
                            sourceType: 'DIRECT',
                            transactionId: transaction.id,
                            isInitialBalance: true
                        },
                    }
                });
            }

            return account;
        });
    }

    /**
     * List the workspace's wallets.
     *
     * `includeBalances` is false for a plain member: they need wallet identity
     * to attach an entry to one and to read it back, but the organisation's cash
     * position is not theirs to see. Stripping the field server-side means the
     * data never leaves the process, rather than relying on the UI to hide it.
     */
    async getWorkspaceAccounts(workspaceId: string, includeBalances = true) {
        const accounts = await this.repository.findAllByWorkspace(workspaceId);
        if (includeBalances) return accounts;

        return accounts.map(({ balance, ...rest }) => rest);
    }

    async getAccountById(id: string, workspaceId: string, includeBalances = true) {
        const account = await this.repository.findById(id);
        if (!account || account.workspaceId !== workspaceId) {
            throw new NotFoundError('Account');
        }
        if (includeBalances) return account;

        const { balance, ...rest } = account;
        return rest;
    }

    async updateAccount(id: string, workspaceId: string, userId: string, data: UpdateAccountBody) {
        return this.prisma.$transaction(async (tx) => {
            const account = await tx.account.findUnique({
                where: { id },
                include: { accountType: true }
            });

            if (!account || account.workspaceId !== workspaceId) {
                throw new NotFoundError('Account');
            }

            const updated = await tx.account.update({
                where: { id },
                data,
                include: { accountType: true }
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.ACCOUNT_UPDATED,
                    resource: 'account',
                    resourceId: account.id,
                    details: { old: { name: account.name, allowNegative: account.allowNegative }, new: data } as any
                }
            });

            return updated;
        });
    }

    async setAccountArchiveStatus(id: string, workspaceId: string, userId: string, data: ArchiveAccountBody) {
        return this.prisma.$transaction(async (tx) => {
            const account = await tx.account.findUnique({
                where: { id },
                include: { accountType: true }
            });

            if (!account || account.workspaceId !== workspaceId) {
                throw new NotFoundError('Account');
            }

            if (account.balance.toNumber() !== 0 && data.archive) {
                throw new AppError(
                    `"${account.name}" still holds ${account.balance.toString()} ${account.currency}. `
                    + 'Move the balance to another account first, then archive it.',
                    400,
                    'ARCHIVE_RESTRICTED',
                );
            }

            const updated = await tx.account.update({
                where: { id },
                data: { archivedAt: data.archive ? new Date() : null },
                include: { accountType: true }
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: data.archive ? AuditAction.ACCOUNT_ARCHIVED : AuditAction.ACCOUNT_UNARCHIVED,
                    resource: 'account',
                    resourceId: account.id,
                    details: { status: data.archive ? 'archived' : 'active' } as any
                }
            });

            return updated;
        });
    }

    async deleteAccount(id: string, workspaceId: string, userId: string) {
        return this.prisma.$transaction(async (tx) => {
            const account = await tx.account.findUnique({
                where: { id },
                include: { accountType: true }
            });

            if (!account || account.workspaceId !== workspaceId) {
                throw new NotFoundError('Account');
            }

            // Everything that ties history to this account.
            //
            // Counting only transactions was not enough: a transfer writes an
            // account_transfers row and a journal but no transaction row, and
            // transfers, ticket sales and expense claims all hold the account
            // with a restricting foreign key. An account whose only activity
            // was a transfer therefore passed this check and then failed in
            // the database, surfacing as an opaque 500 instead of telling the
            // user to archive it.
            const [transactions, transfersOut, transfersIn, ticketSales, expenseClaims] = await Promise.all([
                tx.accountTransaction.count({ where: { accountId: id } }),
                tx.accountTransfer.count({ where: { fromAccountId: id } }),
                tx.accountTransfer.count({ where: { toAccountId: id } }),
                tx.ticketSale.count({ where: { accountId: id } }),
                tx.taskExpenseClaim.count({ where: { accountId: id } }),
            ]);
            const activity = transactions + transfersOut + transfersIn + ticketSales + expenseClaims;

            if (activity > 0) {
                throw new AppError(
                    `"${account.name}" has recorded activity, so it cannot be deleted. Archive it `
                    + 'instead — it keeps its history and drops out of your totals.',
                    400,
                    'DELETE_RESTRICTED',
                );
            }

            await tx.account.delete({ where: { id } });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.ACCOUNT_DELETED,
                    resource: 'account',
                    resourceId: id,
                    details: { name: account.name } as any
                }
            });
        });
    }

    async calculateNetWorth(workspaceId: string) {
        const accounts = await this.repository.findAllByWorkspace(workspaceId);

        // Per-currency accumulators
        const byCurrency: Record<string, { assets: Decimal; liabilities: Decimal }> = {};

        const breakdown: {
            accountId: string;
            name: string;
            type: string;
            classification: string;
            balance: string;
            currency: string;
        }[] = [];

        accounts.forEach(account => {
            // Skip archived or explicitly excluded accounts
            if (account.archivedAt || account.excludeFromTotal) return;

            const classification = account.accountType.classification;
            const currency = account.currency;

            breakdown.push({
                accountId: account.id,
                name: account.name,
                type: account.accountType.name,
                classification,
                balance: account.balance.toString(),
                currency,
            });

            // Initialize currency bucket if needed
            if (!byCurrency[currency]) {
                byCurrency[currency] = { assets: new Decimal(0), liabilities: new Decimal(0) };
            }

            // Net Worth = Assets − Liabilities, with one subtlety that had the
            // sign inverted:
            //
            // `Account.balance` is Σ(debit − credit). Assets are debit-normal so
            // they come out POSITIVE; liabilities are credit-normal so they come
            // out NEGATIVE — owing 20,000 is a balance of −20,000. Summing those
            // raw and then subtracting applied the minus twice: 15,000 held
            // against 20,000 owed reported +35,000 instead of −5,000, calling a
            // business solvent at the exact moment it is not.
            //
            // So liabilities are accumulated as a POSITIVE magnitude — which is
            // also how every balance sheet prints what is owed — and the
            // subtraction below then means what it says. An overpaid liability
            // genuinely has a debit balance, and negating it keeps that case
            // correct too rather than special-casing it.
            if (classification === 'ASSET') {
                byCurrency[currency].assets = byCurrency[currency].assets.add(account.balance);
            } else if (classification === 'LIABILITY') {
                byCurrency[currency].liabilities = byCurrency[currency].liabilities.sub(account.balance);
            }
        });

        // Build per-currency summary
        const currencies = Object.entries(byCurrency).map(([currency, totals]) => ({
            currency,
            assets: totals.assets.toString(),
            liabilities: totals.liabilities.toString(),
            netWorth: totals.assets.sub(totals.liabilities).toString(),
        }));

        return {
            currencies,
            breakdown,
        };
    }

    /**
     * Transfer money between two wallets (same currency).
     * Principal is not income/expense. Optional fee reduces the source wallet only.
     */
    async transferBetweenAccounts(
        workspaceId: string,
        userId: string,
        data: CreateAccountTransferBody,
    ) {
        if (data.fromAccountId === data.toAccountId) {
            throw new AppError('Cannot transfer to the same account', 400, 'INVALID_TRANSFER');
        }

        const amount = new Decimal(data.amount);
        const feeAmount = data.feeAmount ? new Decimal(data.feeAmount) : new Decimal(0);
        if (amount.lessThanOrEqualTo(0)) {
            throw new AppError('Transfer amount must be positive', 400, 'INVALID_AMOUNT');
        }
        if (feeAmount.lessThan(0)) {
            throw new AppError('Fee cannot be negative', 400, 'INVALID_FEE');
        }

        return withFinancialTransaction(this.prisma, async (tx) => {
            // acquireLocks sorts ids internally, so both directions of a transfer
            // take the same lock order.
            await acquireLocks(tx, [
                { target: 'WALLET_ACCOUNT', ids: [data.fromAccountId, data.toAccountId] },
            ]);

            const from = await tx.account.findUnique({ where: { id: data.fromAccountId } });
            const to = await tx.account.findUnique({ where: { id: data.toAccountId } });

            if (!from || from.workspaceId !== workspaceId) {
                throw new NotFoundError('Source account');
            }
            if (!to || to.workspaceId !== workspaceId) {
                throw new NotFoundError('Destination account');
            }
            if (from.archivedAt || to.archivedAt) {
                throw new AppError('Cannot transfer involving an archived account', 400, 'ACCOUNT_ARCHIVED');
            }
            if (from.currency !== to.currency) {
                throw new AppError(
                    `Currency mismatch: source is ${from.currency}, destination is ${to.currency}`,
                    400,
                    'CURRENCY_MISMATCH',
                );
            }

            const totalDebit = amount.add(feeAmount);
            if (!from.allowNegative && from.balance.sub(totalDebit).lessThan(0)) {
                throw new AppError(
                    `Insufficient funds on source account. Balance is ${from.balance.toString()}`,
                    400,
                    'INSUFFICIENT_FUNDS',
                );
            }

            const transferredAt = data.transferredAt ? new Date(data.transferredAt) : new Date();

            const transfer = await tx.accountTransfer.create({
                data: {
                    workspaceId,
                    fromAccountId: from.id,
                    toAccountId: to.id,
                    amount,
                    feeAmount: feeAmount.greaterThan(0) ? feeAmount : null,
                    description: data.description,
                    transferredAt,
                    createdById: userId,
                },
            });

            // One balanced journal moves both wallets and books the fee as a
            // real expense. Previously the fee reduced the source wallet but
            // appeared in no expense total anywhere.
            if (config.LEDGER_MODE !== 'off') {
                await this.postingService.post(
                    tx,
                    buildTransferJournal({
                        workspaceId,
                        transferId: transfer.id,
                        fromAccountId: from.id,
                        toAccountId: to.id,
                        amount,
                        feeAmount,
                        description: data.description || `Transfer ${from.name} → ${to.name}`,
                        transferredAt,
                        currency: from.currency,
                        createdById: userId,
                    }),
                    { applyCaches: config.LEDGER_MODE === 'on', onDuplicate: 'RETURN_EXISTING' },
                );
            }

            await tx.financialAuditLog.create({
                data: {
                    userId,
                    workspaceId,
                    accountId: from.id,
                    action: AuditAction.ACCOUNT_TRANSFER_CREATED,
                    amount,
                    balanceBefore: from.balance,
                    balanceAfter: from.balance.sub(totalDebit),
                    details: {
                        transferId: transfer.id,
                        fromAccountId: from.id,
                        toAccountId: to.id,
                        feeAmount: feeAmount.toString(),
                        description: data.description,
                    },
                },
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.ACCOUNT_TRANSFER_CREATED,
                    resource: 'account_transfer',
                    resourceId: transfer.id,
                    details: {
                        fromAccountId: from.id,
                        toAccountId: to.id,
                        amount: amount.toString(),
                        feeAmount: feeAmount.toString(),
                    } as any,
                },
            });

            return transfer;
        });
    }

    /**
     * Recompute wallet balance from non-voided account transactions + transfers.
     */
    async recalculateAccountBalance(accountId: string, workspaceId: string, userId: string) {
        return withFinancialTransaction(this.prisma, async (tx) => {
            await acquireLocks(tx, [{ target: 'WALLET_ACCOUNT', ids: [accountId] }]);
            const account = await tx.account.findUnique({ where: { id: accountId } });
            if (!account || account.workspaceId !== workspaceId) {
                throw new NotFoundError('Account');
            }

            const oldBalance = account.balance;

            const transactions = await tx.accountTransaction.findMany({
                where: { accountId, voidedAt: null },
                select: { type: true, amount: true, chargeAmount: true },
            });

            const transfers = await tx.accountTransfer.findMany({
                where: {
                    voidedAt: null,
                    OR: [{ fromAccountId: accountId }, { toAccountId: accountId }],
                },
                select: {
                    fromAccountId: true,
                    toAccountId: true,
                    amount: true,
                    feeAmount: true,
                },
            });

            const computed = recomputeWalletBalance(
                transactions,
                transfers.map((t) =>
                    t.fromAccountId === accountId
                        ? { direction: 'OUT' as const, amount: t.amount, feeAmount: t.feeAmount }
                        : { direction: 'IN' as const, amount: t.amount },
                ),
            );

            await tx.account.update({
                where: { id: accountId },
                data: { balance: computed },
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.ACCOUNT_BALANCE_RECALCULATED,
                    resource: 'account',
                    resourceId: accountId,
                    details: {
                        oldBalance: oldBalance.toString(),
                        newBalance: computed.toString(),
                        drifted: !oldBalance.equals(computed),
                    } as any,
                },
            });

            return {
                accountId,
                oldBalance: oldBalance.toString(),
                newBalance: computed.toString(),
                drifted: !oldBalance.equals(computed),
            };
        });
    }
}

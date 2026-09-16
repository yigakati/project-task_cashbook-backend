import { injectable, inject } from 'tsyringe';
import { Prisma, PrismaClient, TransactionSourceType, InventoryReferenceType } from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import { EntriesRepository } from './entries.repository';
import {
    NotFoundError,
    AppError,
    ConflictError,
    AuthorizationError,
} from '../../core/errors/AppError';
import {
    AuditAction,
    CashbookRole,
    EntryType,
} from '../../core/types';
import {
    CreateEntryDto,
    UpdateEntryDto,
    DeleteEntryDto,
    ReviewDeleteRequestDto,
    EntryQueryDto,
} from './entries.dto';
import { logger } from '../../utils/logger';
import { isDateInPast } from '../../utils/helpers';
import { CashbookPermission, hasPermission } from '../../core/types/permissions';
import { ObligationStatus, ObligationType } from '@prisma/client';
import { InventoryService } from '../inventory/inventory.service';
import { generateReceiptPdf } from './receipt.generator';
import { invoiceLogoUrl } from '../invoicing/invoice-logo';
import { receiptEmailTemplate } from '../../utils/emailTemplates';
import { sendEmail } from '../../config/email';
import {
    effectiveCashAmount,
    obligationStatusFromAmounts,
    // Still used for overdraft checks and audit-log before/after values — the
    // balance writes themselves now come from the ledger.
    walletBalanceDelta,
} from '../../core/finance';
import { withFinancialTransaction } from '../../core/db/transaction';
import { acquireLocks } from '../../core/db/locks';
import { assertPeriodOpen, resolveReversalDate } from '../../core/ledger/period';
import { config } from '../../config';
import { PostingService } from '../../core/ledger/posting.service';
import { resolveWorkspaceRole } from '../../core/authz/workspace-access';
import { hasWorkspacePermission } from '../../core/types/workspace-permissions';
import { WorkspacePermission } from '../../core/types/workspace-permissions';
import {
    buildEntryJournal,
    entryPostingKey,
    type EntryPostingInput,
} from '../../core/ledger/rules/entry.rules';

@injectable()
export class EntriesService {
    constructor(
        private entriesRepository: EntriesRepository,
        @inject('PrismaClient') private prisma: PrismaClient,
        private inventoryService: InventoryService,
        private postingService: PostingService,
    ) { }

    // ─── List Entries ──────────────────────────────────
    async getEntries(cashbookId: string, query: EntryQueryDto) {
        const { entries, total } = await this.entriesRepository.findByCashbookId(cashbookId, {
            page: query.page,
            limit: query.limit,
            type: query.type,
            categoryId: query.categoryId,
            contactId: query.contactId,
            paymentModeId: query.paymentModeId,
            startDate: query.startDate,
            endDate: query.endDate,
            sortBy: query.sortBy,
            sortOrder: query.sortOrder,
            includeReversed: query.includeReversed,
        });

        const totalPages = Math.ceil(total / query.limit);

        const entryIds = entries.map(e => e.id);
        const inventoryTransactions = entryIds.length > 0 ? await this.prisma.inventoryTransaction.findMany({
            where: {
                referenceType: InventoryReferenceType.ENTRY,
                referenceId: { in: entryIds }
            },
            include: {
                item: { select: { id: true, name: true, sku: true, unit: true } }
            }
        }) : [];

        const invMap = new Map();
        inventoryTransactions.forEach(it => {
            if (!invMap.has(it.referenceId)) invMap.set(it.referenceId, []);
            invMap.get(it.referenceId).push(it);
        });

        const mappedEntries = entries.map(entry => {
            const { accountTransactions, ...rest } = entry as any;
            return {
                ...rest,
                account: accountTransactions?.[0]?.account || null,
                inventoryItems: invMap.get(entry.id) || [],
            };
        });

        return {
            data: mappedEntries,
            pagination: {
                page: query.page,
                limit: query.limit,
                total,
                totalPages,
                hasNext: query.page < totalPages,
                hasPrevious: query.page > 1,
            },
        };
    }

    // ─── Get Single Entry ─────────────────────────────
    async getEntry(entryId: string) {
        const entry = await this.entriesRepository.findById(entryId);
        if (!entry || entry.isDeleted) {
            throw new NotFoundError('Entry');
        }
        const inventoryTransactions = await this.prisma.inventoryTransaction.findMany({
            where: {
                referenceType: InventoryReferenceType.ENTRY,
                referenceId: entryId
            },
            include: {
                item: { select: { id: true, name: true, sku: true, unit: true } }
            }
        });

        const { accountTransactions, ...rest } = entry as any;
        return {
            ...rest,
            account: accountTransactions?.[0]?.account || null,
            inventoryItems: inventoryTransactions,
        };
    }

    // ─── Create Entry ─────────────────────────────────
    /**
     * Record money moving, and everything that follows from it.
     *
     * The body lives in `createEntryWithin` so that another module can post an
     * entry as part of ITS transaction. Ticketing is the first: a ticket sale
     * and the entry it posts have to commit or fail together, and a nested
     * `withFinancialTransaction` would not give that — the sale would be
     * durable while the money it recorded was not.
     */
    async createEntry(cashbookId: string, userId: string, dto: CreateEntryDto) {
        const entry = await withFinancialTransaction(this.prisma, (tx) =>
            this.createEntryWithin(tx, cashbookId, userId, dto));

        // Background Hook: Send Automatic Receipt if paying an Obligation.
        // Deliberately outside the transaction, and deliberately not awaited:
        // the entry is already committed, and an SMTP failure must not undo it.
        if (dto.obligationId && dto.type === EntryType.INCOME) {
            this.sendReceipt(entry.id, userId).catch(err => {
                logger.error(`Failed to send background receipt for entry ${entry.id}:`, err);
            });
        }

        return entry;
    }

    /**
     * The whole of entry creation, inside a transaction the caller owns.
     *
     * @internal Not routed and not part of the public surface. Callers take on
     * two obligations the wrapper above would otherwise discharge for them:
     *
     *   1. AUTHORITY. This method does not check whether the caller may post to
     *      this book. `createEntry` is reached through requireCashbookMember;
     *      anything else calling in must have made its own check first.
     *   2. LOCK ORDER. It acquires CASHBOOK, WALLET_ACCOUNT and OBLIGATION. A
     *      caller holding locks already must have taken them at a LOWER rank
     *      (see core/db/locks.ts) or it reintroduces the deadlock that module
     *      exists to prevent. TICKET_DAY and TICKET_SHIFT rank above cashbook
     *      for exactly this reason.
     */
    async createEntryWithin(
        tx: Prisma.TransactionClient,
        cashbookId: string,
        userId: string,
        dto: CreateEntryDto,
    ) {
        // Reading through `tx` rather than `this.prisma` so validation sees the
        // same snapshot the write does.
        const cashbook = await tx.cashbook.findUnique({
            where: { id: cashbookId },
        });

        if (!cashbook || !cashbook.isActive) {
            throw new NotFoundError('Cashbook');
        }

        const entryDate = new Date(dto.entryDate);

        // Check backdate rule
        if (!cashbook.allowBackdate && isDateInPast(entryDate)) {
            throw new AppError(
                'Backdated entries are not allowed for this cashbook',
                400,
                'BACKDATE_NOT_ALLOWED'
            );
        }

        const amount = new Decimal(dto.amount);

        // Account Logic - Pre-validation
        if (dto.accountId) {
            const account = await tx.account.findUnique({
                where: { id: dto.accountId }
            });

            if (!account || account.workspaceId !== cashbook.workspaceId) {
                throw new AppError('Invalid account selected', 400, 'INVALID_ACCOUNT');
            }

            if (account.archivedAt) {
                throw new AppError('Cannot create entries for an archived account', 400, 'ACCOUNT_ARCHIVED');
            }

            // Currency mismatch check (Issue 4)
            if (account.currency !== cashbook.currency) {
                throw new AppError(
                    `Account currency (${account.currency}) does not match cashbook currency (${cashbook.currency})`,
                    400,
                    'CURRENCY_MISMATCH'
                );
            }
        }

        // Carried into the posting rules: a payment against a receivable clears
        // AR rather than booking fresh revenue.
        let obligationForPosting: { id: string; type: 'RECEIVABLE' | 'PAYABLE' } | null = null;

        // Obligation Pre-validation requirements
        if (dto.obligationId) {
            const obligation = await tx.cashbookObligation.findUnique({
                where: { id: dto.obligationId }
            });

            if (!obligation) {
                throw new NotFoundError('Obligation');
            }

            obligationForPosting = {
                id: obligation.id,
                type: obligation.type as 'RECEIVABLE' | 'PAYABLE',
            };

            if (obligation.cashbookId !== cashbookId || obligation.workspaceId !== cashbook.workspaceId) {
                throw new AppError('Obligation does not belong to this cashbook', 400, 'INVALID_OBLIGATION');
            }

            if (obligation.archivedAt) {
                throw new AppError('Cannot apply payment to an archived obligation', 400, 'OBLIGATION_ARCHIVED');
            }

            if (obligation.status === ObligationStatus.PAID || obligation.status === ObligationStatus.CANCELLED) {
                throw new AppError(`Cannot apply payment to an obligation that is ${obligation.status.toLowerCase()}`, 400, 'INVALID_OBLIGATION_STATUS');
            }

            if (obligation.type === ObligationType.RECEIVABLE && dto.type !== EntryType.INCOME) {
                throw new AppError('Receivables must be settled with INCOME entries', 400, 'DIRECTION_MISMATCH');
            }

            if (obligation.type === ObligationType.PAYABLE && dto.type !== EntryType.EXPENSE) {
                throw new AppError('Payables must be settled with EXPENSE entries', 400, 'DIRECTION_MISMATCH');
            }

            if (amount.greaterThan(obligation.outstandingAmount)) {
                throw new AppError(`Payment amount ${amount.toString()} exceeds outstanding balance of ${obligation.outstandingAmount.toString()}`, 400, 'OVERPAYMENT');
            }
        }

        // Take every lock this write needs, once, in a globally consistent
        // order. Locking the cashbook is what makes balanceBefore/balanceAfter
        // in the audit log truthful under concurrency.
        await acquireLocks(tx, [
            { target: 'CASHBOOK', ids: [cashbookId] },
            { target: 'WALLET_ACCOUNT', ids: [dto.accountId] },
            { target: 'OBLIGATION', ids: [dto.obligationId] },
        ]);

        const lockedCashbook = await tx.cashbook.findUniqueOrThrow({
            where: { id: cashbookId },
        });

        // Create entry
        const newEntry = await tx.entry.create({
            data: {
                cashbookId,
                type: dto.type as any,
                amount,
                chargeAmount: dto.chargeAmount ? new Decimal(dto.chargeAmount) : null,
                description: dto.description,
                categoryId: dto.categoryId || null,
                contactId: dto.contactId || null,
                paymentModeId: dto.paymentModeId || null,
                obligationId: dto.obligationId || null,
                entryDate,
                createdById: userId,
                integrationApiKeyId: dto.integrationApiKeyId ?? null,
                externalRef: dto.externalRef ?? null,
            },
            include: {
                category: true,
                contact: true,
                paymentMode: true,
                createdBy: {
                    select: { id: true, email: true, firstName: true, lastName: true },
                },
            },
        });

        // Balances are written by PostingService from the journal legs (see
        // the posting call at the end of this transaction). The legacy
        // cashbookIncrementPayload / account.update arithmetic that used to
        // live here was deleted once shadow mode proved the two agree.
        const balanceBefore = lockedCashbook.balance;
        const chargeAmount = dto.chargeAmount ? new Decimal(dto.chargeAmount) : new Decimal(0);
        const hasWalletLink = Boolean(dto.accountId);

        const balanceAfter = hasWalletLink
            ? balanceBefore
            : balanceBefore.add(walletBalanceDelta(dto.type, amount, chargeAmount));

        if (dto.accountId) {
            // Already locked by acquireLocks above.
            const lockedAccount = await tx.account.findUniqueOrThrow({
                where: { id: dto.accountId }
            });

            // Overdraft is a business rule, not a bookkeeping one, so it is
            // still checked here — the ledger would happily post a negative
            // wallet balance.
            const walletDelta = walletBalanceDelta(dto.type, amount, chargeAmount);
            if (!lockedAccount.allowNegative && walletDelta.lessThan(0)) {
                const newAccountBalance = lockedAccount.balance.add(walletDelta);
                if (newAccountBalance.lessThan(0)) {
                    throw new AppError(`Transaction exceeds account balance. Current balance is ${lockedAccount.balance.toString()}`, 400, 'INSUFFICIENT_FUNDS');
                }
            }

            // The wallet subledger row the frontend reads. It carries
            // accountCategoryId, which the GL does not, so it stays — but as
            // a projection alongside the journal, not a source of truth.
            await this.upsertCashbookAccountTransaction(tx, {
                workspaceId: cashbook.workspaceId,
                accountId: dto.accountId,
                sourceId: newEntry.id,
                type: dto.type,
                amount,
                chargeAmount: chargeAmount.greaterThan(0) ? chargeAmount : null,
                description: newEntry.description,
                transactionDate: entryDate,
            });
        }

        if (dto.obligationId) {
            // Block inventory on payment entries if obligation already stocked goods
            if (dto.inventoryItems && dto.inventoryItems.length > 0) {
                const existingOblInv = await tx.inventoryTransaction.count({
                    where: {
                        referenceType: InventoryReferenceType.OBLIGATION,
                        referenceId: dto.obligationId,
                    },
                });
                if (existingOblInv > 0) {
                    throw new AppError(
                        'This obligation already has inventory stock movements. Do not attach inventoryItems on the payment entry (avoids double stock-in).',
                        400,
                        'INVENTORY_DOUBLE_APPLY',
                    );
                }
            }

            // Already locked by acquireLocks above.
            const lockedObligation = await tx.cashbookObligation.findUniqueOrThrow({
                where: { id: dto.obligationId }
            });

            if (amount.greaterThan(lockedObligation.outstandingAmount)) {
                throw new AppError(`Concurrent payment exceeded outstanding balance`, 400, 'OVERPAYMENT');
            }

            const newOutstanding = lockedObligation.outstandingAmount.sub(amount);
            const newStatus = obligationStatusFromAmounts(
                lockedObligation.totalAmount,
                newOutstanding,
                lockedObligation.status,
            ) as ObligationStatus;

            await tx.cashbookObligation.update({
                where: { id: dto.obligationId },
                data: {
                    outstandingAmount: newOutstanding,
                    status: newStatus
                }
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: cashbook.workspaceId,
                    action: AuditAction.OBLIGATION_PAYMENT_APPLIED,
                    resource: 'obligation',
                    resourceId: dto.obligationId,
                    details: {
                        entryId: newEntry.id,
                        appliedAmount: amount,
                        previousOutstanding: lockedObligation.outstandingAmount,
                        newOutstanding,
                        statusBefore: lockedObligation.status,
                        statusAfter: newStatus
                    } as any
                }
            });

            const { InvoicingService } = await import('../invoicing/invoicing.service');
            await InvoicingService.syncInvoiceFromObligation(tx, {
                referenceType: lockedObligation.referenceType,
                referenceId: lockedObligation.referenceId,
                outstandingAmount: newOutstanding,
            });

            // Peer links: a payment on a linked obligation opens a settlement
            // the counterparty must confirm or reject. Fire after the invoice
            // sync, same transaction, so proof and books never diverge.
            const { PeerLinksService } = await import('../peer-links/peer-links.service');
            await PeerLinksService.onPaymentApplied(tx, {
                obligation: { id: lockedObligation.id, peerLinkId: lockedObligation.peerLinkId },
                entry: {
                    id: newEntry.id,
                    amount,
                    entryDate,
                    createdById: userId,
                },
            });
        }

        // Create entry audit
        await tx.entryAudit.create({
            data: {
                entryId: newEntry.id,
                userId,
                action: 'CREATED',
                newValues: {
                    type: dto.type,
                    amount: dto.amount,
                    chargeAmount: dto.chargeAmount || null,
                    description: dto.description,
                    entryDate: dto.entryDate,
                },
            },
        });

        // Financial audit log
        await tx.financialAuditLog.create({
            data: {
                userId,
                workspaceId: cashbook.workspaceId,
                cashbookId,
                entryId: newEntry.id,
                action: AuditAction.ENTRY_CREATED,
                amount,
                balanceBefore,
                balanceAfter,
                details: {
                    type: dto.type,
                    description: dto.description,
                    chargeAmount: dto.chargeAmount || null,
                },
            },
        });

        // ─── Inventory Integration (non-intrusive) ─────────────
        if (dto.inventoryItems && dto.inventoryItems.length > 0) {
            await this.inventoryService.processEntryInventory(
                tx,
                cashbook.workspaceId,
                newEntry.id,
                dto.type,
                amount,
                dto.inventoryItems,
                userId,
                dto.description,
                cashbook.currency,
            );
        }

        // ─── Double-entry posting ──────────────────────────────
        await this.postEntryJournal(tx, {
            workspaceId: cashbook.workspaceId,
            cashbookId,
            entryId: newEntry.id,
            version: newEntry.version,
            type: dto.type as 'INCOME' | 'EXPENSE',
            amount,
            chargeAmount,
            description: dto.description,
            entryDate,
            currency: cashbook.currency,
            createdById: userId,
            accountId: dto.accountId ?? null,
            categoryId: dto.categoryId ?? null,
            contactId: dto.contactId ?? null,
            obligation: obligationForPosting,
        });

        return newEntry;
    }

    // ─── Update Entry ─────────────────────────────────
    async updateEntry(entryId: string, userId: string, dto: UpdateEntryDto) {
        const entry = await this.entriesRepository.findById(entryId);
        if (!entry || entry.isDeleted) {
            throw new NotFoundError('Entry');
        }

        // Soft immutability: reconciled entries cannot change money-affecting fields
        const financialFieldsTouched =
            dto.type !== undefined ||
            dto.amount !== undefined ||
            dto.chargeAmount !== undefined ||
            dto.accountId !== undefined ||
            dto.obligationId !== undefined ||
            dto.entryDate !== undefined ||
            dto.inventoryItems !== undefined;

        if (entry.isReconciled && financialFieldsTouched) {
            throw new AppError(
                'This entry is reconciled and cannot be modified. Unreconcile it first, or post a correcting entry.',
                400,
                'ENTRY_RECONCILED',
            );
        }

        // Money-affecting edits must carry expectedVersion. Without it there is no
        // way to detect that another request changed the entry between the client
        // reading it and submitting. The claim itself happens atomically inside the
        // transaction below; this is only the fast-fail.
        if (financialFieldsTouched && dto.expectedVersion === undefined) {
            throw new AppError(
                'expectedVersion is required when changing amount, type, charge, date, wallet, obligation or inventory.',
                400,
                'EXPECTED_VERSION_REQUIRED',
            );
        }

        if (dto.expectedVersion !== undefined && dto.expectedVersion !== entry.version) {
            throw new ConflictError(
                `Entry was modified by another request (expected version ${dto.expectedVersion}, current ${entry.version})`,
            );
        }

        const cashbook = await this.prisma.cashbook.findUnique({
            where: { id: entry.cashbookId },
        });

        if (!cashbook) {
            throw new NotFoundError('Cashbook');
        }

        // Backdate check for new date
        if (dto.entryDate) {
            const newDate = new Date(dto.entryDate);
            if (!cashbook.allowBackdate && isDateInPast(newDate)) {
                throw new AppError(
                    'Backdated entries are not allowed for this cashbook',
                    400,
                    'BACKDATE_NOT_ALLOWED'
                );
            }
        }

        const oldValues: Record<string, any> = {};
        const newValues: Record<string, any> = {};
        const changes: Record<string, { from: any; to: any }> = {};

        // Unlocked probe, used ONLY to discover which wallet rows this update may
        // touch so they can be locked up front. The authoritative read happens
        // inside the transaction, under lock. If a concurrent update changed the
        // wallet link between this probe and the transaction, the version claim
        // below rejects us — every update bumps version — so acting on the probe
        // for lock selection is safe.
        const walletProbe = await this.prisma.accountTransaction.findFirst({
            where: {
                sourceId: entryId,
                sourceType: TransactionSourceType.CASHBOOK_ENTRY,
                voidedAt: null,
            },
            select: { accountId: true },
        });

        // Track changes
        if (dto.type && dto.type !== entry.type) {
            oldValues.type = entry.type;
            newValues.type = dto.type;
            changes.type = { from: entry.type, to: dto.type };
        }
        if (dto.amount && dto.amount !== entry.amount.toString()) {
            oldValues.amount = entry.amount.toString();
            newValues.amount = dto.amount;
            changes.amount = { from: entry.amount.toString(), to: dto.amount };
        }
        if (dto.chargeAmount !== undefined && dto.chargeAmount !== (entry.chargeAmount?.toString() || null)) {
            oldValues.chargeAmount = entry.chargeAmount?.toString() || null;
            newValues.chargeAmount = dto.chargeAmount;
            changes.chargeAmount = { from: entry.chargeAmount?.toString() || null, to: dto.chargeAmount };
        }
        if (dto.description && dto.description !== entry.description) {
            oldValues.description = entry.description;
            newValues.description = dto.description;
            changes.description = { from: entry.description, to: dto.description };
        }
        if (dto.entryDate) {
            oldValues.entryDate = entry.entryDate.toISOString();
            newValues.entryDate = dto.entryDate;
            changes.entryDate = { from: entry.entryDate.toISOString(), to: dto.entryDate };
        }

        const updated = await withFinancialTransaction(this.prisma, async (tx) => {
            // Lock every row this write may touch, once, in a globally consistent
            // order. Locking BOTH the current and the target wallet here is what
            // removes the X->Y / Y->X deadlock: previously they were locked in
            // argument order, so two opposite re-links could each hold one and
            // wait on the other.
            await acquireLocks(tx, [
                { target: 'CASHBOOK', ids: [entry.cashbookId] },
                { target: 'WALLET_ACCOUNT', ids: [walletProbe?.accountId, dto.accountId] },
                { target: 'OBLIGATION', ids: [entry.obligationId, dto.obligationId] },
            ]);

            // Atomic compare-and-swap on version. This is the real concurrency
            // guard: `updateMany` lets us put version in the WHERE clause, which
            // `update` cannot. Two racing edits with the same expectedVersion both
            // used to pass the pre-transaction check and both applied.
            if (dto.expectedVersion !== undefined) {
                const claimed = await tx.entry.updateMany({
                    where: { id: entryId, version: dto.expectedVersion, isDeleted: false },
                    data: { version: { increment: 1 } },
                });

                if (claimed.count === 0) {
                    const current = await tx.entry.findUnique({
                        where: { id: entryId },
                        select: { version: true, isDeleted: true },
                    });
                    throw new ConflictError(
                        current?.isDeleted
                            ? 'Entry was deleted by another request'
                            : `Entry was modified by another request (expected version ${dto.expectedVersion}, current ${current?.version})`,
                    );
                }
            }

            const lockedCashbook = await tx.cashbook.findUniqueOrThrow({
                where: { id: entry.cashbookId },
            });

            // Authoritative read, under lock, after the version claim.
            const existingTx = await tx.accountTransaction.findFirst({
                where: {
                    sourceId: entryId,
                    sourceType: TransactionSourceType.CASHBOOK_ENTRY,
                    voidedAt: null,
                },
            });

            // Defence in depth: if the wallet link moved between the probe and
            // now, we hold the wrong locks. The version claim should make this
            // unreachable; surfacing it as a conflict is safer than proceeding
            // with an unlocked row.
            if ((existingTx?.accountId ?? null) !== (walletProbe?.accountId ?? null)) {
                throw new ConflictError(
                    'Entry wallet link changed concurrently; retry the update.',
                );
            }

            const hasAccountChanged =
                dto.accountId !== undefined && dto.accountId !== (existingTx?.accountId || null);

            const targetAccountId = dto.accountId !== undefined ? dto.accountId : existingTx?.accountId || null;

            const wasIncome = entry.type === EntryType.INCOME;
            const oldAmount = entry.amount;
            const oldChargeAmount = entry.chargeAmount || new Decimal(0);
            const oldEffectiveAmount = effectiveCashAmount(entry.type, oldAmount, oldChargeAmount);
            const balanceBefore = lockedCashbook.balance;

            // Cashbook and wallet balances are rewritten by PostingService's
            // reverse-and-repost at the end of this transaction. The hand-written
            // reverse-then-apply arithmetic that lived here is gone.
            const newType = dto.type || entry.type;
            const newAmount = dto.amount ? new Decimal(dto.amount) : entry.amount;
            const isIncome = newType === EntryType.INCOME;
            const newChargeAmount = dto.chargeAmount !== undefined
                ? (dto.chargeAmount ? new Decimal(dto.chargeAmount) : new Decimal(0))
                : (entry.chargeAmount || new Decimal(0));
            const newEffectiveAmount = effectiveCashAmount(newType, newAmount, newChargeAmount);
            // Keeps the wallet statement's business date in step with the entry.
            const newEntryDate = dto.entryDate ? new Date(dto.entryDate) : entry.entryDate;

            // Cashbook balance audit: only unlinked entries move it
            let balanceAfter = balanceBefore;
            if (!existingTx) {
                balanceAfter = balanceAfter.sub(walletBalanceDelta(entry.type, oldAmount, oldChargeAmount));
            }
            if (!targetAccountId) {
                balanceAfter = balanceAfter.add(walletBalanceDelta(newType, newAmount, newChargeAmount));
            }

            // Deal with Accounts
            if (existingTx || dto.accountId) {
                const moneyChanged =
                    hasAccountChanged ||
                    oldAmount.toString() !== newAmount.toString() ||
                    wasIncome !== isIncome ||
                    oldChargeAmount.toString() !== newChargeAmount.toString();

                if (targetAccountId) {
                    if (moneyChanged || !existingTx) {
                        const targetAccount = await tx.account.findUniqueOrThrow({ where: { id: targetAccountId } });
                        if (targetAccount.archivedAt) {
                            throw new AppError('Cannot modify entries linked to an archived account', 400, 'ACCOUNT_ARCHIVED');
                        }

                        if ((hasAccountChanged || !existingTx) && targetAccount.currency !== lockedCashbook.currency) {
                            throw new AppError(
                                `Account currency (${targetAccount.currency}) does not match cashbook currency (${lockedCashbook.currency})`,
                                400,
                                'CURRENCY_MISMATCH'
                            );
                        }

                        // Already locked by acquireLocks above.
                        const lockedTarget = await tx.account.findUniqueOrThrow({ where: { id: targetAccountId } });

                        // Overdraft remains a business rule checked here; the
                        // ledger itself would post a negative balance happily.
                        // Compare against the balance net of this entry's old
                        // effect, since the repost reverses it first.
                        const newWalletDelta = walletBalanceDelta(newType, newAmount, newChargeAmount);
                        const oldWalletDelta =
                            existingTx && existingTx.accountId === targetAccountId
                                ? walletBalanceDelta(entry.type, oldAmount, oldChargeAmount)
                                : new Decimal(0);

                        if (!lockedTarget.allowNegative && newWalletDelta.lessThan(0)) {
                            const provisional = lockedTarget.balance
                                .sub(oldWalletDelta)
                                .add(newWalletDelta);
                            if (provisional.lessThan(0)) {
                                throw new AppError(`Transaction exceeds account balance.`, 400, 'INSUFFICIENT_FUNDS');
                            }
                        }
                    }

                    if (existingTx && dto.accountId !== null) {
                        await tx.accountTransaction.update({
                            where: { id: existingTx.id },
                            data: {
                                ...(hasAccountChanged && { accountId: targetAccountId as string }),
                                amount: newAmount,
                                chargeAmount: newChargeAmount.greaterThan(0) ? newChargeAmount : null,
                                type: newType as any,
                                description: dto.description || existingTx.description,
                                transactionDate: newEntryDate,
                            }
                        });
                    } else if (!existingTx) {
                        await this.upsertCashbookAccountTransaction(tx, {
                            workspaceId: cashbook.workspaceId,
                            accountId: targetAccountId,
                            sourceId: entryId,
                            type: newType,
                            amount: newAmount,
                            chargeAmount: newChargeAmount.greaterThan(0) ? newChargeAmount : null,
                            description: dto.description || entry.description,
                            transactionDate: newEntryDate,
                        });
                    }
                } else if (existingTx && dto.accountId === null) {
                    // Unlink wallet: void AT (keep audit history)
                    await tx.accountTransaction.update({
                        where: { id: existingTx.id },
                        data: { voidedAt: new Date() },
                    });
                }
            }

            // Deal with Obligations (independent of account logic)
            if (entry.obligationId || dto.obligationId) {
                const { InvoicingService } = await import('../invoicing/invoicing.service');
                const targetObligId = dto.obligationId !== undefined ? dto.obligationId : entry.obligationId;

                // If moving away from an obligation, reverse it
                if (entry.obligationId && dto.obligationId === null) {
                    // Already locked by acquireLocks above.
                    const oldOblig = await tx.cashbookObligation.findUniqueOrThrow({ where: { id: entry.obligationId } });

                    const newOutstanding = oldOblig.outstandingAmount.add(oldAmount);
                    const cappedOutstanding = newOutstanding.greaterThan(oldOblig.totalAmount)
                        ? oldOblig.totalAmount
                        : newOutstanding;
                    const newStatus = obligationStatusFromAmounts(
                        oldOblig.totalAmount,
                        cappedOutstanding,
                        oldOblig.status,
                    ) as ObligationStatus;

                    await tx.cashbookObligation.update({
                        where: { id: entry.obligationId },
                        data: { outstandingAmount: cappedOutstanding, status: newStatus }
                    });

                    await InvoicingService.syncInvoiceFromObligation(tx, {
                        referenceType: oldOblig.referenceType,
                        referenceId: oldOblig.referenceId,
                        outstandingAmount: cappedOutstanding,
                    });
                } else if (targetObligId) {
                    // Already locked by acquireLocks above.
                    const lockedTarget = await tx.cashbookObligation.findUniqueOrThrow({ where: { id: targetObligId } });

                    const changedObligation = entry.obligationId && entry.obligationId !== targetObligId;
                    const isNewAssignment = !entry.obligationId || changedObligation;

                    if (isNewAssignment) {
                        if (lockedTarget.cashbookId !== entry.cashbookId) {
                            throw new AppError('Obligation does not belong to this cashbook', 400, 'INVALID_OBLIGATION');
                        }

                        if (lockedTarget.archivedAt) {
                            throw new AppError('Cannot apply payment to an archived obligation', 400, 'OBLIGATION_ARCHIVED');
                        }

                        if (lockedTarget.status === ObligationStatus.CANCELLED) {
                            throw new AppError('Cannot apply payment to a cancelled obligation', 400, 'INVALID_OBLIGATION_STATUS');
                        }
                    }

                    if (changedObligation) {
                        // Already locked by acquireLocks above.
                        const oldOblig = await tx.cashbookObligation.findUniqueOrThrow({ where: { id: entry.obligationId as string } });
                        const revOutstanding = oldOblig.outstandingAmount.add(oldAmount);
                        const cappedRevOutstanding = revOutstanding.greaterThan(oldOblig.totalAmount)
                            ? oldOblig.totalAmount
                            : revOutstanding;
                        const revStatus = obligationStatusFromAmounts(
                            oldOblig.totalAmount,
                            cappedRevOutstanding,
                            oldOblig.status,
                        ) as ObligationStatus;

                        await tx.cashbookObligation.update({
                            where: { id: entry.obligationId as string },
                            data: { outstandingAmount: cappedRevOutstanding, status: revStatus }
                        });

                        await InvoicingService.syncInvoiceFromObligation(tx, {
                            referenceType: oldOblig.referenceType,
                            referenceId: oldOblig.referenceId,
                            outstandingAmount: cappedRevOutstanding,
                        });
                    }

                    // Same obligation: net change = oldAmount - newAmount; new obligation: subtract newAmount
                    const adjustment = !changedObligation && entry.obligationId ? oldAmount.sub(newAmount) : newAmount.negated();

                    const provisionalOutstanding = lockedTarget.outstandingAmount.add(adjustment);

                    if (provisionalOutstanding.lessThan(0)) {
                        throw new AppError(`Update would overpay the obligation`, 400, 'OVERPAYMENT');
                    }

                    if (lockedTarget.type === ObligationType.RECEIVABLE && newType !== EntryType.INCOME) {
                        throw new AppError('Receivables must be settled with INCOME entries', 400, 'DIRECTION_MISMATCH');
                    }
                    if (lockedTarget.type === ObligationType.PAYABLE && newType !== EntryType.EXPENSE) {
                        throw new AppError('Payables must be settled with EXPENSE entries', 400, 'DIRECTION_MISMATCH');
                    }

                    const newStatus = obligationStatusFromAmounts(
                        lockedTarget.totalAmount,
                        provisionalOutstanding,
                        lockedTarget.status,
                    ) as ObligationStatus;

                    await tx.cashbookObligation.update({
                        where: { id: targetObligId },
                        data: {
                            outstandingAmount: provisionalOutstanding,
                            status: newStatus
                        }
                    });

                    await InvoicingService.syncInvoiceFromObligation(tx, {
                        referenceType: lockedTarget.referenceType,
                        referenceId: lockedTarget.referenceId,
                        outstandingAmount: provisionalOutstanding,
                    });

                    await tx.auditLog.create({
                        data: {
                            userId,
                            workspaceId: cashbook.workspaceId,
                            action: AuditAction.OBLIGATION_UPDATED,
                            resource: 'obligation',
                            resourceId: targetObligId,
                            details: {
                                entryId,
                                adjustedAmount: adjustment,
                                newOutstanding: provisionalOutstanding,
                            } as any
                        }
                    });
                }
            }

            // Update entry
            const updatedEntry = await tx.entry.update({
                where: { id: entryId },
                data: {
                    ...(dto.type && { type: dto.type as any }),
                    ...(dto.amount && { amount: new Decimal(dto.amount) }),
                    ...(dto.chargeAmount !== undefined ? { chargeAmount: dto.chargeAmount ? new Decimal(dto.chargeAmount) : null } : {}),
                    ...(dto.description && { description: dto.description }),
                    ...(dto.categoryId !== undefined ? { categoryId: dto.categoryId } : {}),
                    ...(dto.contactId !== undefined ? { contactId: dto.contactId } : {}),
                    ...(dto.paymentModeId !== undefined ? { paymentModeId: dto.paymentModeId } : {}),
                    ...(dto.obligationId !== undefined ? { obligationId: dto.obligationId } : {}),
                    ...(dto.entryDate && { entryDate: new Date(dto.entryDate) }),
                    // The version claim above already incremented when
                    // expectedVersion was supplied; incrementing again here would
                    // skip a version and break the next client's compare-and-swap.
                    ...(dto.expectedVersion === undefined ? { version: { increment: 1 } } : {}),
                },
                include: {
                    category: true,
                    contact: true,
                    paymentMode: true,
                    createdBy: {
                        select: { id: true, email: true, firstName: true, lastName: true },
                    },
                },
            });

            // ─── Double-entry: reverse the old version, post the new one ───
            // The journal is never edited in place. The previous version's
            // journal is reversed and a fresh one posted under the new version's
            // posting key, so the ledger keeps a complete history of the edit.
            if (this.ledgerEnabled) {
                // Both ends of the edit must be in open periods: the version
                // being reversed and the version being posted. Editing an entry
                // out of, or into, closed books is exactly what closing prevents.
                await assertPeriodOpen(tx, cashbook.workspaceId, entry.entryDate);
                await assertPeriodOpen(tx, cashbook.workspaceId, updatedEntry.entryDate);

                const targetObligation = updatedEntry.obligationId
                    ? await tx.cashbookObligation.findUnique({
                        where: { id: updatedEntry.obligationId },
                        select: { id: true, type: true },
                    })
                    : null;

                await this.postingService.repost(tx, {
                    originalPostingKey: entryPostingKey(entryId, entry.version),
                    reason: 'Entry updated',
                    createdById: userId,
                    applyCaches: this.ledgerOwnsCaches,
                    next: buildEntryJournal({
                        workspaceId: cashbook.workspaceId,
                        cashbookId: entry.cashbookId,
                        entryId,
                        version: updatedEntry.version,
                        type: updatedEntry.type as 'INCOME' | 'EXPENSE',
                        amount: updatedEntry.amount,
                        chargeAmount: updatedEntry.chargeAmount,
                        description: updatedEntry.description,
                        entryDate: updatedEntry.entryDate,
                        currency: lockedCashbook.currency,
                        createdById: userId,
                        accountId: targetAccountId,
                        categoryId: updatedEntry.categoryId,
                        contactId: updatedEntry.contactId,
                        obligation: targetObligation
                            ? {
                                id: targetObligation.id,
                                type: targetObligation.type as 'RECEIVABLE' | 'PAYABLE',
                            }
                            : null,
                    }),
                });
            }

            // Audit trail (immutable record of the edit)
            await tx.entryAudit.create({
                data: {
                    entryId,
                    userId,
                    action: 'UPDATED',
                    changes,
                    oldValues,
                    newValues,
                },
            });

            // Financial audit log
            await tx.financialAuditLog.create({
                data: {
                    userId,
                    workspaceId: cashbook.workspaceId,
                    cashbookId: entry.cashbookId,
                    entryId,
                    action: AuditAction.ENTRY_UPDATED,
                    amount: newAmount,
                    balanceBefore,
                    balanceAfter,
                    details: { changes },
                },
            });

            // ─── Inventory Integration (reverse old + reapply) ─────
            // Only touch inventory if the caller explicitly sent `inventoryItems`.
            // If dto.inventoryItems is undefined → caller did not intend to change
            // inventory at all, so we must NOT reverse the existing transactions.
            // If dto.inventoryItems is an empty array → caller intentionally cleared
            // all inventory links (reverse existing, apply nothing).
            if (dto.inventoryItems !== undefined) {
                // Reverse existing inventory transactions for this entry
                await this.inventoryService.reverseInventoryForReference(
                    tx,
                    InventoryReferenceType.ENTRY,
                    entryId,
                );

                // Re-apply if new items provided
                if (dto.inventoryItems.length > 0) {
                    await this.inventoryService.processEntryInventory(
                        tx,
                        cashbook.workspaceId,
                        entryId,
                        newType,
                        newAmount,
                        dto.inventoryItems,
                        userId,
                        dto.description || entry.description,
                        cashbook.currency,
                    );
                }
            }

            return updatedEntry;
        });

        return updated;
    }

    // ─── Delete Entry (Owner / with permission) ────────
    async deleteEntry(
        entryId: string,
        userId: string,
        reason: string,
        userRole: CashbookRole
    ) {
        const entry = await this.entriesRepository.findById(entryId);
        if (!entry || entry.isDeleted) {
            throw new NotFoundError('Entry');
        }

        const canDelete = hasPermission(userRole, CashbookPermission.DELETE_ENTRY);
        const canApproveDelete = hasPermission(userRole, CashbookPermission.APPROVE_DELETE);

        // Users who can both delete and approve → direct delete
        if (canDelete && canApproveDelete) {
            await this.performDeletion(entry, userId, reason);
            return { action: 'DELETED', message: 'Entry deleted successfully' };
        }

        // Users who can only delete → create delete request
        if (canDelete) {
            // Check for existing pending request
            const existing = await this.entriesRepository.findPendingDeleteRequest(entryId);
            if (existing) {
                throw new ConflictError('A delete request is already pending for this entry');
            }

            const request = await this.entriesRepository.createDeleteRequest({
                entryId,
                requesterId: userId,
                reason,
            });

            const cashbook = await this.prisma.cashbook.findUnique({
                where: { id: entry.cashbookId },
                select: { workspaceId: true },
            });

            await this.prisma.auditLog.create({
                data: {
                    userId,
                    workspaceId: cashbook?.workspaceId,
                    action: AuditAction.ENTRY_DELETE_REQUESTED,
                    resource: 'entry',
                    resourceId: entryId,
                    details: { reason } as any,
                },
            });

            return { action: 'REQUEST_CREATED', message: 'Delete request submitted for approval', data: request };
        }

        throw new AppError('You do not have permission to delete entries', 403, 'AUTHORIZATION_ERROR');
    }

    // ─── Review Delete Request ─────────────────────────
    async reviewDeleteRequest(
        requestId: string,
        reviewerId: string,
        dto: ReviewDeleteRequestDto
    ) {
        const request = await this.entriesRepository.findDeleteRequestById(requestId);
        if (!request) {
            throw new NotFoundError('Delete request');
        }

        if (request.status !== 'PENDING') {
            throw new AppError('This request has already been reviewed', 400, 'ALREADY_REVIEWED');
        }

        if (request.requesterId === reviewerId) {
            throw new AppError('You cannot review your own delete request', 400, 'SELF_REVIEW');
        }

        await this.entriesRepository.updateDeleteRequest(requestId, {
            status: dto.status,
            reviewerId,
            reviewNote: dto.reviewNote,
        });

        const action = dto.status === 'APPROVED'
            ? AuditAction.ENTRY_DELETE_APPROVED
            : AuditAction.ENTRY_DELETE_REJECTED;

        const cashbook = request.entry?.cashbook;

        await this.prisma.auditLog.create({
            data: {
                userId: reviewerId,
                workspaceId: cashbook?.workspaceId,
                action,
                resource: 'delete_request',
                resourceId: requestId,
                details: {
                    entryId: request.entryId,
                    status: dto.status,
                    reviewNote: dto.reviewNote,
                } as any,
            },
        });

        // If approved, perform the actual deletion
        if (dto.status === 'APPROVED' && request.entry) {
            await this.performDeletion(request.entry, reviewerId, request.reason);
        }

        return { message: `Delete request ${dto.status.toLowerCase()}` };
    }

    // ─── Get Delete Requests ──────────────────────────
    async getDeleteRequests(cashbookId: string, status?: string) {
        return this.entriesRepository.findDeleteRequestsByCashbook(cashbookId, status);
    }

    // ─── Get Entry Audit Trail ─────────────────────────
    async getEntryAuditTrail(entryId: string) {
        const entry = await this.entriesRepository.findById(entryId);
        if (!entry) {
            throw new NotFoundError('Entry');
        }
        return this.entriesRepository.getEntryAudits(entryId);
    }

    // ─── Internal: Perform Deletion ────────────────────
    private async performDeletion(entry: any, userId: string, reason: string) {
        await withFinancialTransaction(this.prisma, (tx) =>
            this.reverseEntryWithin(tx, entry, userId, reason));
    }

    /**
     * Reverse an entry inside a transaction the caller owns.
     *
     * @internal Not routed. Split out of `performDeletion` for the same reason
     * `createEntryWithin` was split out of `createEntry`: ticketing has to void
     * a sale and reverse the entry it posted atomically.
     *
     * This does the MECHANICS of a reversal and none of the authority. The
     * cashbook's own path decides who may reverse via the DELETE_ENTRY /
     * APPROVE_DELETE maker-checker in `deleteEntry`; ticketing decides via its
     * own own-sale / supervisor / open-day rules. Both then land here, so there
     * is exactly one implementation of what reversing actually does — the
     * journal, the wallet, the obligation, the attachments and the audit trail.
     *
     * Callers must respect the lock ranks in core/db/locks.ts: this acquires
     * CASHBOOK, WALLET_ACCOUNT and OBLIGATION.
     */
    async reverseEntryWithin(
        tx: Prisma.TransactionClient,
        entry: any,
        userId: string,
        reason: string,
    ) {
        if (entry.isReconciled) {
            throw new AppError(
                'This entry is reconciled and cannot be deleted. Unreconcile it first.',
                400,
                'ENTRY_RECONCILED',
            );
        }

        const cashbook = await tx.cashbook.findUnique({
            where: { id: entry.cashbookId },
        });

        if (!cashbook) {
            throw new NotFoundError('Cashbook');
        }

        // Unlocked probe, used only to select wallet locks; see updateEntry. The
        // re-read after locking below is what catches a link that changed in
        // between, which is why this stays a separate read rather than being
        // folded into the locked one.
        const walletProbe = await tx.accountTransaction.findFirst({
            where: {
                sourceId: entry.id,
                sourceType: TransactionSourceType.CASHBOOK_ENTRY,
                voidedAt: null,
            },
            select: { accountId: true },
        });

        await acquireLocks(tx, [
            { target: 'CASHBOOK', ids: [entry.cashbookId] },
            { target: 'WALLET_ACCOUNT', ids: [walletProbe?.accountId] },
            { target: 'OBLIGATION', ids: [entry.obligationId] },
        ]);

        const lockedCashbook = await tx.cashbook.findUniqueOrThrow({
            where: { id: entry.cashbookId },
        });

        const balanceBefore = lockedCashbook.balance;
        const amount = entry.amount;
        const chargeAmount = entry.chargeAmount || new Decimal(0);

        // Check if there's a linked non-voided account FIRST
        const existingTx = await tx.accountTransaction.findFirst({
            where: {
                sourceId: entry.id,
                sourceType: TransactionSourceType.CASHBOOK_ENTRY,
                voidedAt: null,
            }
        });

        if ((existingTx?.accountId ?? null) !== (walletProbe?.accountId ?? null)) {
            throw new ConflictError('Entry wallet link changed concurrently; retry the delete.');
        }

        let balanceAfter = balanceBefore;

        // Cashbook and wallet balances are rewritten by the reversing
        // journal posted below; the hand-written reversal arithmetic is gone.
        if (!existingTx) {
            balanceAfter = balanceBefore.sub(walletBalanceDelta(entry.type, amount, chargeAmount));
        }

        if (existingTx) {
            // Already locked by acquireLocks above.
            const lockedAccount = await tx.account.findUniqueOrThrow({
                where: { id: existingTx.accountId },
            });
            const oldWalletDelta = walletBalanceDelta(entry.type, amount, chargeAmount);
            const reversalDelta = oldWalletDelta.negated();

            // Deleting an INCOME entry withdraws money from the wallet, which
            // can overdraw it. Every other wallet-debiting path guards this;
            // this one did not.
            if (!lockedAccount.allowNegative && reversalDelta.lessThan(0)) {
                if (lockedAccount.balance.add(reversalDelta).lessThan(0)) {
                    throw new AppError(
                        `Deleting this entry would overdraw account "${lockedAccount.name}" ` +
                        `(balance ${lockedAccount.balance.toString()}, reversal ${reversalDelta.toString()}). ` +
                        'Allow a negative balance on the account, or reverse the offsetting entries first.',
                        400,
                        'INSUFFICIENT_FUNDS',
                    );
                }
            }

            // Void wallet ledger row (retain audit history)
            await tx.accountTransaction.update({
                where: { id: existingTx.id },
                data: { voidedAt: new Date() },
            });
        }

        if (entry.obligationId) {
            // Already locked by acquireLocks above.
            const lockedObligation = await tx.cashbookObligation.findUniqueOrThrow({ where: { id: entry.obligationId } });

            const newOutstanding = lockedObligation.outstandingAmount.add(amount);
            const cappedOutstanding = newOutstanding.greaterThan(lockedObligation.totalAmount)
                ? lockedObligation.totalAmount
                : newOutstanding;
            const newStatus = obligationStatusFromAmounts(
                lockedObligation.totalAmount,
                cappedOutstanding,
                lockedObligation.status,
            ) as ObligationStatus;

            await tx.cashbookObligation.update({
                where: { id: entry.obligationId },
                data: {
                    outstandingAmount: cappedOutstanding,
                    status: newStatus
                }
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: cashbook.workspaceId,
                    action: AuditAction.OBLIGATION_PAYMENT_REVERSED,
                    resource: 'obligation',
                    resourceId: entry.obligationId,
                    details: {
                        entryId: entry.id,
                        reason,
                        reversedAmount: amount,
                        newOutstanding: cappedOutstanding
                    } as any
                }
            });

            const { InvoicingService } = await import('../invoicing/invoicing.service');
            await InvoicingService.syncInvoiceFromObligation(tx, {
                referenceType: lockedObligation.referenceType,
                referenceId: lockedObligation.referenceId,
                outstandingAmount: cappedOutstanding,
            });

            // Peer links: the settlement this payment opened — whether still
            // pending or already confirmed — no longer stands once the entry is
            // reversed.
            const { PeerLinksService } = await import('../peer-links/peer-links.service');
            await PeerLinksService.onPaymentReversed(tx, {
                obligation: { peerLinkId: lockedObligation.peerLinkId },
                entryId: entry.id,
            });
        }

        // ─── Inventory Integration (reverse on delete) ────────
        await this.inventoryService.reverseInventoryForReference(
            tx,
            InventoryReferenceType.ENTRY,
            entry.id,
        );

        // ─── Double-entry: post the reversing journal ──────────
        // The original journal is never removed. It is marked REVERSED and a
        // mirror-image REVERSING journal is appended, so the books stay in
        // balance and the history of the correction is itself auditable.
        await this.reverseEntryJournal(tx, {
            workspaceId: cashbook.workspaceId,
            entryId: entry.id,
            version: entry.version,
            reason,
            userId,
            originalDate: entry.entryDate,
        });

        // Mark the entry reversed. `isDeleted` is kept in step so the
        // existing repository filters and list queries keep working; it is
        // retired once every read path uses `status`.
        await tx.entry.update({
            where: { id: entry.id },
            data: {
                status: 'REVERSED',
                reversedAt: new Date(),
                reversedById: userId,
                reversalReason: reason,
                isDeleted: true,
                deletedAt: new Date(),
                deletedReason: reason,
                // Attachments are soft-deleted, not destroyed: a reversed
                // entry keeps its supporting documents for audit. The old
                // deleteMany here removed them permanently.
                attachments: {
                    updateMany: {
                        where: { isDeleted: false },
                        data: { isDeleted: true, deletedAt: new Date() },
                    },
                },
            },
        });

        // Entry audit
        await tx.entryAudit.create({
            data: {
                entryId: entry.id,
                userId,
                action: 'DELETED',
                oldValues: {
                    type: entry.type,
                    amount: entry.amount,
                    description: entry.description,
                } as any,
                newValues: {} as any,
            },
        });

        // Workspace/Cashbook Audit
        await tx.auditLog.create({
            data: {
                userId,
                workspaceId: cashbook.workspaceId,
                action: AuditAction.ENTRY_DELETED,
                resource: 'entry',
                resourceId: entry.id,
                details: {
                    amount: entry.amount,
                    type: entry.type,
                    reason,
                } as any
            }
        });
        // Financial audit log
        await tx.financialAuditLog.create({
            data: {
                userId,
                workspaceId: cashbook.workspaceId,
                cashbookId: entry.cashbookId,
                entryId: entry.id,
                action: AuditAction.ENTRY_DELETED,
                amount,
                balanceBefore,
                balanceAfter,
                reason,
                details: {
                    type: entry.type,
                    description: entry.description,
                },
            },
        });
    }

    // ─── Double-entry posting ──────────────────────────────
    //
    // Rollout is controlled by config.LEDGER_MODE:
    //   off    skip entirely
    //   shadow write journals but leave the cached columns to the legacy
    //          arithmetic, so LedgerIntegrityService can prove the two agree
    //   on     the ledger owns the caches (Phase 2)

    private get ledgerEnabled(): boolean {
        return config.LEDGER_MODE !== 'off';
    }

    /** In shadow mode the legacy code still writes the caches; don't double up. */
    private get ledgerOwnsCaches(): boolean {
        return config.LEDGER_MODE === 'on';
    }

    private async postEntryJournal(
        tx: Prisma.TransactionClient,
        input: EntryPostingInput,
    ): Promise<void> {
        if (!this.ledgerEnabled) return;

        // Closed books stay closed. Checked here rather than in PostingService
        // so reversals can shift their date instead of failing.
        await assertPeriodOpen(tx, input.workspaceId, input.entryDate);

        await this.postingService.post(tx, buildEntryJournal(input), {
            applyCaches: this.ledgerOwnsCaches,
            // A retried create must not double-post. The posting key is
            // deterministic, so this is the database-level exactly-once guard.
            onDuplicate: 'RETURN_EXISTING',
        });
    }

    /** Reverse the journal for an entry version, if one was posted. */
    private async reverseEntryJournal(
        tx: Prisma.TransactionClient,
        args: {
            workspaceId: string;
            entryId: string;
            version: number;
            reason: string;
            userId: string;
            originalDate: Date;
        },
    ): Promise<void> {
        if (!this.ledgerEnabled) return;

        // A correction to a closed period posts at today's date rather than
        // being rejected — the books stay closed, and the correction is still
        // recorded.
        const reversalDate = await resolveReversalDate(tx, args.workspaceId, args.originalDate);

        await this.postingService.reverse(tx, {
            workspaceId: args.workspaceId,
            originalPostingKey: entryPostingKey(args.entryId, args.version),
            reason: args.reason,
            createdById: args.userId,
            reversalDate,
            applyCaches: this.ledgerOwnsCaches,
        });
    }

    /**
     * Create or revive a cashbook-linked AccountTransaction.
     * Revives a previously voided row for the same (sourceId, accountId) to honor the unique constraint.
     */
    private async upsertCashbookAccountTransaction(
        tx: any,
        data: {
            workspaceId: string;
            accountId: string;
            sourceId: string;
            type: string;
            amount: Decimal;
            chargeAmount: Decimal | null;
            description: string;
            /** Entry.entryDate — the wallet statement must show the business date. */
            transactionDate: Date;
        },
    ) {
        const existingAny = await tx.accountTransaction.findFirst({
            where: {
                sourceId: data.sourceId,
                accountId: data.accountId,
                sourceType: TransactionSourceType.CASHBOOK_ENTRY,
            },
        });

        if (existingAny) {
            return tx.accountTransaction.update({
                where: { id: existingAny.id },
                data: {
                    voidedAt: null,
                    type: data.type as any,
                    amount: data.amount,
                    chargeAmount: data.chargeAmount,
                    description: data.description,
                    transactionDate: data.transactionDate,
                },
            });
        }

        return tx.accountTransaction.create({
            data: {
                workspaceId: data.workspaceId,
                accountId: data.accountId,
                sourceType: TransactionSourceType.CASHBOOK_ENTRY,
                sourceId: data.sourceId,
                type: data.type as any,
                amount: data.amount,
                chargeAmount: data.chargeAmount,
                description: data.description,
                transactionDate: data.transactionDate,
            },
        });
    }

    // ─── Receipts ──────────────────────────────────────
    /**
     * The receipt as data, for the client to render and print.
     *
     * The same model the PDF generator is handed, so a printed receipt and an
     * emailed one show identical facts. Building the document twice from two
     * queries is how the printed copy quietly starts disagreeing with the
     * emailed one.
     *
     * Emailing still renders server-side, because the recipient never loads our
     * page. Printing renders client-side, because the person printing already
     * has the page open and a browser prints better than we do.
     */
    async getReceiptModel(entryId: string) {
        const entry = await this.prisma.entry.findUnique({
            where: { id: entryId },
            include: {
                cashbook: { select: { workspaceId: true, currency: true, name: true } },
                contact: { include: { customerProfile: true } },
                paymentMode: true,
                obligation: true,
            },
        });

        if (!entry) throw new NotFoundError('Entry');
        if (!entry.contact) {
            throw new AppError(
                'This entry is not linked to a customer, so there is nobody to receipt.',
                400,
                'NO_CONTACT',
            );
        }
        if (entry.type !== 'INCOME') {
            throw new AppError(
                'Receipts acknowledge money received. This entry is money out.',
                400,
                'NOT_INCOME',
            );
        }

        const workspaceId = entry.cashbook.workspaceId;
        const [workspace, settings] = await Promise.all([
            this.prisma.workspace.findUnique({ where: { id: workspaceId } }),
            this.prisma.invoiceSettings.findUnique({ where: { workspaceId } }),
        ]);

        return {
            receiptNumber: entry.id.split('-').pop() || entry.id,
            paymentDate: entry.entryDate,
            amountPaid: entry.amount.toString(),
            currency: entry.cashbook.currency,
            paymentMode: entry.paymentMode ? { name: entry.paymentMode.name } : null,
            description: entry.description,
            obligation: entry.obligation
                ? {
                    title: entry.obligation.title,
                    totalAmount: entry.obligation.totalAmount.toString(),
                    outstandingAmount: entry.obligation.outstandingAmount.toString(),
                }
                : null,
            customer: {
                name: entry.contact.name,
                email: entry.contact.email,
                phone: entry.contact.phone,
                company: entry.contact.company,
                billingAddress: entry.contact.customerProfile?.billingAddress ?? null,
                taxId: entry.contact.customerProfile?.taxId ?? null,
            },
            // Only what InvoiceSettings actually models. Inventing address and
            // phone fields here would print empty lines on every receipt.
            business: {
                name: workspace?.name ?? 'Business',
                logoUrl: invoiceLogoUrl(settings?.logoKey),
                accentColor: settings?.accentColor ?? null,
                footer: settings?.defaultFooter ?? null,
                notes: settings?.defaultNotes ?? null,
            },
            /** False means the Send button should explain itself rather than fail. */
            canEmail: Boolean(entry.contact.email),
        };
    }

    async sendReceipt(entryId: string, userId: string) {
        const entry = await this.prisma.entry.findUnique({
            where: { id: entryId },
            include: {
                cashbook: { select: { workspaceId: true, currency: true } },
                contact: { include: { customerProfile: true } },
                paymentMode: true,
                obligation: true,
            }
        });

        if (!entry) throw new NotFoundError('Entry');
        // An obligation is NOT required. A receipt acknowledges that money was
        // received; most sales are paid on the spot and never become a
        // receivable. Requiring one meant the commonest case — a walk-in
        // customer paying cash — could not be given a receipt at all.
        if (!entry.contact) {
            throw new AppError(
                'This entry is not linked to a customer, so there is nobody to receipt.',
                400,
                'NO_CONTACT',
            );
        }
        if (!entry.contact.email) {
            throw new AppError(
                'That customer has no email address. Add one, or print the receipt instead.',
                400,
                'NO_EMAIL',
            );
        }
        if (entry.type !== 'INCOME') {
            throw new AppError(
                'Receipts acknowledge money received. This entry is money out.',
                400,
                'NOT_INCOME',
            );
        }

        const workspaceId = entry.cashbook.workspaceId;

        // Fetch Business Data & Settings
        const workspace = await this.prisma.workspace.findUnique({ where: { id: workspaceId } });
        const settings = await this.prisma.invoiceSettings.findUnique({ where: { workspaceId } });

        const businessName = workspace?.name || 'Business';

        // Prepare PDF/Email Models
        const pdfModel = {
            receiptNumber: entry.id.split('-').pop() || entry.id,
            paymentDate: entry.entryDate,
            amountPaid: entry.amount,
            currency: entry.cashbook.currency,
            paymentMode: entry.paymentMode,
            // Falls back to the entry itself when the payment does not settle a
            // receivable: paid in full, nothing outstanding.
            obligation: entry.obligation
                ? {
                    title: entry.obligation.title,
                    totalAmount: entry.obligation.totalAmount,
                    outstandingAmount: entry.obligation.outstandingAmount,
                }
                : {
                    title: entry.description,
                    totalAmount: entry.amount,
                    outstandingAmount: new Decimal(0),
                },
            customer: {
                name: entry.contact.name,
                email: entry.contact.email,
                phone: entry.contact.phone,
                company: entry.contact.company,
                customerProfile: entry.contact.customerProfile,
            }
        };

        const pdfBuffer = await generateReceiptPdf(pdfModel, businessName, settings);

        // Send Email
        const amountStr = entry.amount.toNumber().toLocaleString(undefined, { minimumFractionDigits: 2 });
        const remainingStr = (entry.obligation?.outstandingAmount ?? new Decimal(0))
            .toNumber().toLocaleString(undefined, { minimumFractionDigits: 2 });
        const paymentDateStr = new Date(entry.entryDate).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });

        const html = receiptEmailTemplate({
            customerName: entry.contact.name,
            businessName,
            receiptNumber: pdfModel.receiptNumber,
            obligationName: entry.obligation?.title ?? entry.description,
            currency: entry.cashbook.currency,
            amountPaid: amountStr,
            paymentDate: paymentDateStr,
            remainingBal: remainingStr,
            logoUrl: invoiceLogoUrl(settings?.logoKey),
        });

        await sendEmail({
            to: entry.contact.email,
            subject: `Payment Receipt - ${entry.obligation?.title ?? entry.description}`,
            html,
            attachments: [{
                filename: `Receipt_${pdfModel.receiptNumber}.pdf`,
                content: pdfBuffer,
                contentType: 'application/pdf',
            }]
        });

        // Log Transparency
        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId,
                action: 'RECEIPT_SENT' as any,
                resource: 'entry',
                resourceId: entry.id,
                details: {
                    sentTo: entry.contact.email,
                    amount: entry.amount.toString(),
                    remainingBalance: (entry.obligation?.outstandingAmount ?? new Decimal(0)).toString(),
                } as any,
            }
        });

        return { success: true };
    }

    /**
     * Move an entry from one book to another.
     *
     * The replacement for a "cashbook to cashbook transfer". Now that every
     * entry names a wallet, books hold no cash, so there is nothing to transfer
     * between them — the money never moves. What people actually want when they
     * ask for that is this: the amount was filed against the wrong book.
     *
     * So this changes ATTRIBUTION, not money. The wallet is untouched, the
     * amount is untouched, and the org-wide totals are unchanged; only which
     * book's income/expense the entry counts toward changes.
     *
     * It is still a ledger operation, not a column update. The old book's
     * journal is reversed and a fresh one posted against the new book, exactly
     * as an edit does — so both books' totals move by the same amount in
     * opposite directions, and the history shows where the entry used to live
     * rather than silently rewriting it.
     */
    async reassignEntry(
        entryId: string,
        userId: string,
        dto: { targetCashbookId: string; reason: string; expectedVersion: number },
    ) {
        const entry = await this.entriesRepository.findById(entryId);
        if (!entry || entry.isDeleted) throw new NotFoundError('Entry');

        if (entry.status === 'REVERSED') {
            throw new AppError(
                'This entry has been reversed. Reversed entries stay where they are as a record of what happened.',
                400,
                'ENTRY_REVERSED',
            );
        }

        // Reconciliation is a statement about one book: "this entry matches a
        // line on that book's statement". Moving it elsewhere would silently
        // invalidate that, so it has to be undone deliberately first.
        if (entry.isReconciled) {
            throw new AppError(
                'This entry is reconciled. Unreconcile it before moving it to another book.',
                400,
                'ENTRY_RECONCILED',
            );
        }

        const source = await this.prisma.cashbook.findUnique({
            where: { id: entry.cashbookId },
            select: { id: true, name: true, workspaceId: true, currency: true },
        });
        if (!source) throw new NotFoundError('Cashbook');

        if (dto.targetCashbookId === source.id) {
            throw new AppError('That entry is already in this book.', 400, 'SAME_CASHBOOK');
        }

        // Must be able to post INTO the destination, checked the same way the
        // route would if the id arrived in the path. Without this, write access
        // to one book would be write access to every book in the workspace.
        const target = await this.assertCanPostToCashbook(
            dto.targetCashbookId,
            source.workspaceId,
            userId,
        );

        // No FX here, and inventing one silently would be worse than refusing.
        if (target.currency !== source.currency) {
            throw new AppError(
                `Cannot move a ${source.currency} entry into a ${target.currency} book.`,
                400,
                'CURRENCY_MISMATCH',
            );
        }

        return withFinancialTransaction(this.prisma, async (tx) => {
            const walletProbe = await tx.accountTransaction.findFirst({
                where: { sourceId: entryId },
                select: { accountId: true },
            });

            // Both books, in a globally consistent order, plus the wallet the
            // repost will touch.
            await acquireLocks(tx, [
                { target: 'CASHBOOK', ids: [source.id, target.id] },
                { target: 'WALLET_ACCOUNT', ids: [walletProbe?.accountId] },
                { target: 'OBLIGATION', ids: [entry.obligationId] },
            ]);

            const claimed = await tx.entry.updateMany({
                where: { id: entryId, version: dto.expectedVersion, isDeleted: false },
                data: { version: { increment: 1 }, cashbookId: target.id },
            });
            if (claimed.count === 0) {
                throw new ConflictError(
                    'This entry changed while you were looking at it. Reload and try again.',
                );
            }

            const moved = await tx.entry.findUniqueOrThrow({ where: { id: entryId } });

            if (this.ledgerEnabled) {
                // One date, but it must be open in both books' shared workspace
                // — moving an entry into closed books is what closing prevents.
                await assertPeriodOpen(tx, source.workspaceId, entry.entryDate);

                const obligation = moved.obligationId
                    ? await tx.cashbookObligation.findUnique({
                        where: { id: moved.obligationId },
                        select: { id: true, type: true },
                    })
                    : null;

                await this.postingService.repost(tx, {
                    originalPostingKey: entryPostingKey(entryId, entry.version),
                    reason: `Moved from ${source.name} to ${target.name}: ${dto.reason}`,
                    createdById: userId,
                    applyCaches: this.ledgerOwnsCaches,
                    next: buildEntryJournal({
                        workspaceId: source.workspaceId,
                        cashbookId: target.id,
                        entryId,
                        version: moved.version,
                        type: moved.type as 'INCOME' | 'EXPENSE',
                        amount: moved.amount,
                        chargeAmount: moved.chargeAmount,
                        description: moved.description,
                        entryDate: moved.entryDate,
                        currency: target.currency,
                        createdById: userId,
                        accountId: walletProbe?.accountId ?? null,
                        categoryId: moved.categoryId,
                        contactId: moved.contactId,
                        obligation: obligation
                            ? { id: obligation.id, type: obligation.type as 'RECEIVABLE' | 'PAYABLE' }
                            : null,
                    }),
                });
            }

            await tx.entryAudit.create({
                data: {
                    entryId,
                    userId,
                    action: 'UPDATED',
                    changes: { cashbookId: { from: source.id, to: target.id } } as never,
                    oldValues: { cashbookId: source.id, cashbookName: source.name } as never,
                    newValues: {
                        cashbookId: target.id,
                        cashbookName: (target as { name?: string }).name ?? null,
                        reason: dto.reason,
                    } as never,
                },
            });

            await tx.financialAuditLog.create({
                data: {
                    userId,
                    workspaceId: source.workspaceId,
                    cashbookId: target.id,
                    entryId,
                    action: AuditAction.ENTRY_UPDATED,
                    amount: moved.amount,
                    balanceBefore: new Decimal(0),
                    balanceAfter: new Decimal(0),
                    details: {
                        movedFrom: source.name,
                        movedTo: (target as { name?: string }).name ?? target.id,
                        reason: dto.reason,
                    } as never,
                },
            });

            return moved;
        });
    }

    /**
     * Can this user post into that book?
     *
     * The same check `requireCashbookMember(CREATE_ENTRY)` performs, run
     * in-service because the destination arrives in the body rather than the
     * path. A role holding ACCESS_ALL_CASHBOOKS passes without an explicit
     * membership row; everyone else needs one, which is what keeps a
     * PROJECT_MANAGER confined to the books they were granted.
     */
    private async assertCanPostToCashbook(cashbookId: string, workspaceId: string, userId: string) {
        const cashbook = await this.prisma.cashbook.findUnique({
            where: { id: cashbookId },
            select: { id: true, name: true, workspaceId: true, isActive: true, currency: true },
        });
        if (!cashbook || !cashbook.isActive || cashbook.workspaceId !== workspaceId) {
            throw new NotFoundError('Cashbook');
        }

        const orgRole = await resolveWorkspaceRole(this.prisma, workspaceId, userId);
        if (hasWorkspacePermission(orgRole, WorkspacePermission.ACCESS_ALL_CASHBOOKS)) {
            return cashbook;
        }

        const membership = await this.prisma.cashbookMember.findUnique({
            where: { cashbookId_userId: { cashbookId, userId } },
            select: { role: true },
        });
        if (!membership || !hasPermission(membership.role as never, CashbookPermission.CREATE_ENTRY)) {
            throw new AuthorizationError(
                'You cannot record entries in that book. Choose one you have access to.',
            );
        }
        return cashbook;
    }
}

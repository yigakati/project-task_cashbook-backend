import { injectable, inject } from 'tsyringe';
import {
    Prisma, PrismaClient, RentalAgreementStatus, InventoryTransactionType,
    InventoryReferenceType, NotificationType, NotificationEntityType,
} from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import { NotFoundError, AppError, AuthorizationError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';
import { withFinancialTransaction } from '../../core/db/transaction';
import { NotificationsService } from '../notifications/notifications.service';
import { InventoryService } from './inventory.service';
import {
    CreateRentalAgreementDto, RespondRentalAgreementDto, RentalAgreementQueryDto,
} from './agreements.dto';

const AGREEMENT_INCLUDE = {
    lenderUser: { select: { id: true, email: true, firstName: true, lastName: true } },
    borrowerUser: { select: { id: true, email: true, firstName: true, lastName: true } },
    lenderItem: { select: { id: true, name: true, unit: true, sku: true, currency: true } },
    rental: { select: { id: true, status: true, startDate: true, endDate: true } },
    // One-time flags: the UI hides the record buttons once set.
    expenseEntry: { select: { id: true } },
    incomeEntry: { select: { id: true } },
} satisfies Prisma.RentalAgreementInclude;

/**
 * Cross-workspace rental agreements — lending an item to another platform
 * user under a contract they accept.
 *
 * Proposing reserves the units (they cannot be sold or rented elsewhere while
 * the decision is pending); acceptance converts the reservation into a normal
 * rental on the lender's books with the borrower as counterparty. Returns
 * flow through the ordinary rental return.
 */
@injectable()
export class RentalAgreementsService {
    constructor(
        @inject('PrismaClient') private prisma: PrismaClient,
        private inventoryService: InventoryService,
    ) { }

    // ─── Propose (lender) ────────────────────────────────
    async create(lenderWorkspaceId: string, lenderItemId: string, userId: string, dto: CreateRentalAgreementDto) {
        const item = await this.prisma.inventoryItem.findUnique({
            where: { id: lenderItemId },
            include: { stock: true },
        });
        if (!item || item.workspaceId !== lenderWorkspaceId) {
            throw new NotFoundError('Inventory item');
        }
        if (item.commercialMode === 'SELL_ONLY') {
            throw new AppError(`Item "${item.name}" is sell-only and cannot be lent`, 400, 'ITEM_NOT_RENTABLE');
        }

        /*
         * Who is being lent the item? The named customer — resolved through
         * their contact's linked account, the reliable identity — or, as a
         * fallback, a raw email address.
         */
        let borrower: { id: string; isActive: boolean } | null = null;
        if (dto.customerId) {
            const contact = await this.prisma.contact.findFirst({
                where: { id: dto.customerId, workspaceId: lenderWorkspaceId, isActive: true },
                select: { userId: true, name: true, email: true },
            });
            if (!contact) throw new NotFoundError('Customer');
            /*
             * The linked account when the contact carries one; otherwise the
             * email the workspace itself recorded — the same read-time
             * resolution the contacts list performs, so a customer created
             * normally (no userId on the row) can still receive a contract.
             */
            if (contact.userId) {
                borrower = await this.prisma.user.findUnique({
                    where: { id: contact.userId },
                    select: { id: true, isActive: true },
                });
            } else if (contact.email) {
                borrower = await this.prisma.user.findUnique({
                    where: { email: contact.email.toLowerCase() },
                    select: { id: true, isActive: true },
                });
            }
            if (!borrower) {
                throw new AppError(
                    `Customer "${contact.name}" does not have an account on the platform — a rental contract needs someone who can accept it`,
                    400,
                    'CUSTOMER_HAS_NO_ACCOUNT',
                );
            }
        } else {
            borrower = await this.prisma.user.findUnique({
                where: { email: dto.borrowerEmail!.toLowerCase() },
                select: { id: true, isActive: true },
            });
        }
        if (!borrower || !borrower.isActive) {
            throw new AppError('No active user found with that email', 404, 'USER_NOT_FOUND');
        }
        if (borrower.id === userId) {
            throw new AppError('You cannot lend an item to yourself', 400, 'SELF_AGREEMENT');
        }

        const qty = Math.round(dto.quantity);
        if (qty <= 0) {
            throw new AppError('Quantity must be at least 1', 400, 'INVALID_QUANTITY');
        }
        const periods = Math.max(1, Math.round(dto.periodCount ?? 1));
        const startDate = new Date(dto.startDate);
        const endDate = dto.endDate ? new Date(dto.endDate) : null;

        const agreement = await withFinancialTransaction(this.prisma, async (tx) => {
            // Reserve under lock: a concurrent proposal against the same
            // stock cannot both promise the same units.
            await tx.$queryRaw`SELECT id FROM inventory_stock WHERE item_id = ${lenderItemId}::uuid FOR UPDATE`;
            const stock = await tx.inventoryStock.findUniqueOrThrow({ where: { itemId: lenderItemId } });
            const available = stock.quantityOnHand - stock.quantityReserved - stock.quantityRentedOut;
            if (available < qty) {
                throw new AppError(
                    `Insufficient stock. Available: ${available}, requested: ${qty}`,
                    400,
                    'INSUFFICIENT_STOCK',
                );
            }

            const created = await tx.rentalAgreement.create({
                data: {
                    status: RentalAgreementStatus.PENDING,
                    lenderUserId: userId,
                    lenderWorkspaceId,
                    lenderItemId,
                    quantity: qty,
                    periodUnit: dto.periodUnit,
                    periodCount: periods,
                    startDate,
                    endDate,
                    rate: dto.rate ? new Decimal(dto.rate) : null,
                    borrowerUserId: borrower.id,
                    notes: dto.notes || null,
                },
            });

            // The reservation itself — visible in every availability read
            // from this moment until the agreement resolves.
            await tx.inventoryStock.update({
                where: { itemId: lenderItemId },
                data: { quantityReserved: { increment: qty } },
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: lenderWorkspaceId,
                    action: AuditAction.RENTAL_AGREEMENT_CREATED,
                    resource: 'rental_agreement',
                    resourceId: created.id,
                    details: { itemId: lenderItemId, quantity: qty, borrowerUserId: borrower.id } as any,
                },
            });

            return created;
        });

        NotificationsService.dispatch({
            type: NotificationType.RENTAL_AGREEMENT_RECEIVED,
            userId: borrower.id,
            workspaceId: lenderWorkspaceId,
            title: 'Rental contract for you',
            body: `${qty} × ${item.name} is being rented to you — review the terms and accept to receive it`,
            entityType: NotificationEntityType.RENTAL_AGREEMENT,
            entityId: agreement.id,
            groupKey: `rental-agreement:${agreement.id}`,
        });

        return this.getForUser(agreement.id, userId);
    }

    // ─── Accept (borrower) ───────────────────────────────
    /**
     * The reservation becomes a rental: units move to rented-out on the
     * lender's books, the agreement points at the rental it created, and the
     * borrower's chosen workspace is recorded as provenance. No stock or
     * books exist on the borrower's side — the item stays in the lender's
     * inventory until it comes back.
     */
    async accept(agreementId: string, userId: string, dto: RespondRentalAgreementDto) {
        const agreement = await withFinancialTransaction(this.prisma, async (tx) => {
            const pending = await tx.rentalAgreement.findUnique({ where: { id: agreementId } });
            if (!pending) throw new NotFoundError('Rental agreement');
            if (pending.borrowerUserId !== userId) {
                throw new AuthorizationError('Only the borrower can accept this agreement');
            }
            if (pending.status !== RentalAgreementStatus.PENDING) {
                throw new AppError(`This agreement is already ${pending.status.toLowerCase()}`, 400, 'INVALID_STATUS');
            }

            // Provenance workspace: the borrower's choice. Owner passes; a
            // member must hold OWNER/ADMIN — the same rule the options list
            // applies, enforced again here because the list is not the boundary.
            if (dto.borrowerWorkspaceId) {
                const ws = await tx.workspace.findUnique({ where: { id: dto.borrowerWorkspaceId } });
                if (!ws || !ws.isActive) throw new NotFoundError('Workspace');
                if (ws.ownerId !== userId) {
                    const membership = await tx.workspaceMember.findUnique({
                        where: { workspaceId_userId: { workspaceId: ws.id, userId } },
                    });
                    if (!membership || !['OWNER', 'ADMIN'].includes(membership.role)) {
                        throw new AuthorizationError('You can only accept into a workspace you own or administer');
                    }
                }
            }

            const item = await tx.inventoryItem.findUniqueOrThrow({
                where: { id: pending.lenderItemId },
            });
            // A customer row standing for the borrower on the lender's books —
            // the rental needs a counterparty and so does the history.
            const borrower = await tx.user.findUniqueOrThrow({
                where: { id: userId },
                select: { id: true, firstName: true, lastName: true, email: true },
            });
            let customerId = await tx.contact.findFirst({
                where: { workspaceId: pending.lenderWorkspaceId, userId },
                select: { id: true },
            });
            if (!customerId) {
                const created = await tx.contact.create({
                    data: {
                        workspaceId: pending.lenderWorkspaceId,
                        userId,
                        type: 'STAFF',
                        name: `${borrower.firstName} ${borrower.lastName}`.trim() || borrower.email,
                        email: borrower.email,
                    },
                });
                customerId = { id: created.id };
            }

            const rental = await tx.inventoryRental.create({
                data: {
                    workspaceId: pending.lenderWorkspaceId,
                    customerId: customerId.id,
                    invoiceId: null,
                    status: 'ACTIVE' as any,
                    currency: item.currency,
                    startDate: pending.startDate,
                    endDate: pending.endDate,
                    notes: pending.notes || 'Loan via rental agreement',
                    createdById: pending.lenderUserId,
                },
            });
            await tx.inventoryRentalLine.create({
                data: {
                    rentalId: rental.id,
                    inventoryItemId: pending.lenderItemId,
                    quantity: pending.quantity,
                    unitRate: pending.rate ?? new Decimal(0),
                    periodUnit: pending.periodUnit,
                    periodCount: pending.periodCount,
                    lineTotal: (pending.rate ?? new Decimal(0)).mul(pending.quantity).mul(pending.periodCount),
                },
            });

            // Reservation converts to rented-out: the promise becomes the
            // real RENTAL_OUT movement (COGS-free, like every rental).
            await tx.inventoryStock.update({
                where: { itemId: pending.lenderItemId },
                data: {
                    quantityReserved: { decrement: pending.quantity },
                    quantityRentedOut: { increment: pending.quantity },
                },
            });
            await tx.inventoryTransaction.create({
                data: {
                    workspaceId: pending.lenderWorkspaceId,
                    itemId: pending.lenderItemId,
                    transactionType: InventoryTransactionType.RENTAL_OUT,
                    quantity: -pending.quantity,
                    unitCost: new Decimal(0),
                    totalCost: new Decimal(0),
                    sellingPrice: pending.rate,
                    referenceType: InventoryReferenceType.RENTAL,
                    referenceId: rental.id,
                    notes: `Rental out via agreement ${agreementId.slice(0, 8)}`,
                    createdById: userId,
                },
            });

            // PENDING-guarded claim.
            const { count } = await tx.rentalAgreement.updateMany({
                where: { id: agreementId, status: RentalAgreementStatus.PENDING },
                data: {
                    status: RentalAgreementStatus.ACCEPTED,
                    borrowerWorkspaceId: dto.borrowerWorkspaceId || null,
                    rentalId: rental.id,
                    respondedAt: new Date(),
                },
            });
            if (count !== 1) {
                throw new AppError('This agreement is no longer pending', 400, 'INVALID_STATUS');
            }

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: pending.lenderWorkspaceId,
                    action: AuditAction.RENTAL_AGREEMENT_ACCEPTED,
                    resource: 'rental_agreement',
                    resourceId: agreementId,
                    details: {
                        rentalId: rental.id,
                        borrowerWorkspaceId: dto.borrowerWorkspaceId ?? null,
                    } as any,
                },
            });

            return tx.rentalAgreement.findUniqueOrThrow({ where: { id: agreementId } });
        });

        NotificationsService.dispatch({
            type: NotificationType.RENTAL_AGREEMENT_DECIDED,
            userId: agreement.lenderUserId,
            workspaceId: agreement.lenderWorkspaceId,
            title: 'Rental agreement accepted',
            body: `Your rental contract was accepted — ${agreement.quantity} units are now out on rental`,
            entityType: NotificationEntityType.RENTAL_AGREEMENT,
            entityId: agreement.id,
            groupKey: `rental-agreement:${agreement.id}:decided`,
        });

        return agreement;
    }

    // ─── Release the reservation when the agreement dies ──
    private async releaseReservation(tx: Prisma.TransactionClient, agreement: { id: string; lenderItemId: string; quantity: number; lenderWorkspaceId: string }) {
        await tx.inventoryStock.update({
            where: { itemId: agreement.lenderItemId },
            data: { quantityReserved: { decrement: agreement.quantity } },
        });
    }

    async decline(agreementId: string, userId: string, reason?: string) {
        const agreement = await this.prisma.rentalAgreement.findUnique({ where: { id: agreementId } });
        if (!agreement) throw new NotFoundError('Rental agreement');
        if (agreement.borrowerUserId !== userId) {
            throw new AuthorizationError('Only the borrower can decline this agreement');
        }
        if (agreement.status !== RentalAgreementStatus.PENDING) {
            throw new AppError(`This agreement is already ${agreement.status.toLowerCase()}`, 400, 'INVALID_STATUS');
        }

        const { count } = await this.prisma.$transaction(async (tx) => {
            const res = await tx.rentalAgreement.updateMany({
                where: { id: agreementId, status: RentalAgreementStatus.PENDING },
                data: { status: RentalAgreementStatus.DECLINED, respondedAt: new Date() },
            });
            if (res.count === 1) {
                await this.releaseReservation(tx, agreement);
                await tx.auditLog.create({
                    data: {
                        userId,
                        workspaceId: agreement.lenderWorkspaceId,
                        action: AuditAction.RENTAL_AGREEMENT_DECLINED,
                        resource: 'rental_agreement',
                        resourceId: agreementId,
                        details: { reason: reason ?? null } as any,
                    },
                });
            }
            return res;
        });
        if (count !== 1) {
            throw new AppError('This agreement is no longer pending', 400, 'INVALID_STATUS');
        }

        NotificationsService.dispatch({
            type: NotificationType.RENTAL_AGREEMENT_DECIDED,
            userId: agreement.lenderUserId,
            workspaceId: agreement.lenderWorkspaceId,
            title: 'Rental agreement declined',
            body: `Your rental contract offer was declined${reason ? `: ${reason}` : ''}`,
            entityType: NotificationEntityType.RENTAL_AGREEMENT,
            entityId: agreementId,
            groupKey: `rental-agreement:${agreementId}:decided`,
        });

        return this.prisma.rentalAgreement.findUniqueOrThrow({ where: { id: agreementId } });
    }

    async cancel(agreementId: string, userId: string, reason?: string) {
        const agreement = await this.prisma.rentalAgreement.findUnique({ where: { id: agreementId } });
        if (!agreement) throw new NotFoundError('Rental agreement');
        if (agreement.lenderUserId !== userId) {
            throw new AuthorizationError('Only the lender can cancel this agreement');
        }
        if (agreement.status !== RentalAgreementStatus.PENDING) {
            throw new AppError('Only pending agreements can be cancelled. Accepted ones are returned through the rental flow.', 400, 'INVALID_STATUS');
        }

        const { count } = await this.prisma.$transaction(async (tx) => {
            const res = await tx.rentalAgreement.updateMany({
                where: { id: agreementId, status: RentalAgreementStatus.PENDING },
                data: { status: RentalAgreementStatus.CANCELLED, respondedAt: new Date() },
            });
            if (res.count === 1) {
                await this.releaseReservation(tx, agreement);
                await tx.auditLog.create({
                    data: {
                        userId,
                        workspaceId: agreement.lenderWorkspaceId,
                        action: AuditAction.RENTAL_AGREEMENT_CANCELLED,
                        resource: 'rental_agreement',
                        resourceId: agreementId,
                        details: { reason: reason ?? null } as any,
                    },
                });
            }
            return res;
        });
        if (count !== 1) {
            throw new AppError('This agreement is no longer pending', 400, 'INVALID_STATUS');
        }

        NotificationsService.dispatch({
            type: NotificationType.RENTAL_AGREEMENT_DECIDED,
            userId: agreement.borrowerUserId,
            workspaceId: agreement.lenderWorkspaceId,
            title: 'Rental agreement cancelled',
            body: 'The rental contract offered to you was withdrawn by its lender',
            entityType: NotificationEntityType.RENTAL_AGREEMENT,
            entityId: agreementId,
            groupKey: `rental-agreement:${agreementId}:decided`,
        });

        return this.prisma.rentalAgreement.findUniqueOrThrow({ where: { id: agreementId } });
    }

    // ─── Query ───────────────────────────────────────────
    async list(userId: string, query: RentalAgreementQueryDto) {
        const where: Prisma.RentalAgreementWhereInput = {};
        if (query.direction === 'lent') {
            where.lenderUserId = userId;
        } else if (query.direction === 'borrowed') {
            where.borrowerUserId = userId;
        } else {
            where.OR = [{ lenderUserId: userId }, { borrowerUserId: userId }];
        }
        if (query.status) where.status = query.status as RentalAgreementStatus;

        const [agreements, total] = await Promise.all([
            this.prisma.rentalAgreement.findMany({
                where,
                include: AGREEMENT_INCLUDE,
                skip: (Math.max(1, query.page || 1) - 1) * (query.limit || 20),
                take: query.limit || 20,
                orderBy: { createdAt: 'desc' },
            }),
            this.prisma.rentalAgreement.count({ where }),
        ]);

        const totalPages = Math.ceil(total / (query.limit || 20)) || 1;
        return {
            data: agreements,
            pagination: {
                page: Math.max(1, query.page || 1),
                limit: query.limit || 20,
                total,
                totalPages,
                hasNext: (query.page || 1) < totalPages,
                hasPrevious: (query.page || 1) > 1,
            },
        };
    }

    async getForUser(agreementId: string, userId: string) {
        const agreement = await this.prisma.rentalAgreement.findUnique({
            where: { id: agreementId },
            include: AGREEMENT_INCLUDE,
        });
        if (!agreement) throw new NotFoundError('Rental agreement');
        if (agreement.lenderUserId !== userId && agreement.borrowerUserId !== userId) {
            throw new AuthorizationError('You are not a party to this agreement');
        }
        return agreement;
    }

    /**
     * The lender's side of the money: record the rental income in one of the
     * lender's own books — the mirror of the borrower's expense.
     *
     * Available once the contract is accepted (the rental is out). The book
     * must belong to the lender's workspace; the ordinary entry path handles
     * journals, wallets and balances.
     */
    async recordLenderIncome(
        agreementId: string,
        userId: string,
        dto: { cashbookId: string; accountId?: string; entryDate?: string },
    ) {
        const { EntriesService } = await import('../entries/entries.service');
        const { container } = await import('tsyringe');

        const agreement = await this.prisma.rentalAgreement.findUnique({
            where: { id: agreementId },
            select: {
                id: true, status: true, lenderUserId: true, lenderWorkspaceId: true,
                rate: true, quantity: true, periodCount: true, periodUnit: true,
                incomeEntryId: true,
                lenderItem: { select: { name: true, currency: true } },
            },
        });
        if (!agreement) throw new NotFoundError('Rental agreement');
        if (agreement.lenderUserId !== userId) {
            throw new AuthorizationError('Only the lender can record this income');
        }
        if (agreement.status !== RentalAgreementStatus.ACCEPTED) {
            throw new AppError('The contract must be accepted before recording its income', 400, 'INVALID_STATUS');
        }

        const cashbook = await this.prisma.cashbook.findUnique({ where: { id: dto.cashbookId } });
        if (!cashbook || !cashbook.isActive) throw new NotFoundError('Cashbook');
        if (cashbook.workspaceId !== agreement.lenderWorkspaceId) {
            throw new AppError(
                'The rental income can only be recorded in the lender\'s own workspace',
                400,
                'WRONG_WORKSPACE',
            );
        }
        if (cashbook.currency !== agreement.lenderItem.currency) {
            throw new AppError(
                `This book's currency (${cashbook.currency}) does not match the rental's (${agreement.lenderItem.currency})`,
                400,
                'CURRENCY_MISMATCH',
            );
        }

        const charge = (agreement.rate ?? new Decimal(0))
            .mul(agreement.quantity)
            .mul(agreement.periodCount);
        if (charge.lessThanOrEqualTo(0)) {
            throw new AppError('This contract carries no charge — there is nothing to record', 400, 'NO_CHARGE');
        }
        // One-time by design — checked after the request's own validity so
        // the error reported is the actual problem.
        if (agreement.incomeEntryId) {
            throw new AppError('The rental income has already been recorded for this contract', 409, 'ALREADY_RECORDED');
        }

        return withFinancialTransaction(this.prisma, async (tx) => {
            const entry = await container.resolve(EntriesService).createEntryWithin(
                tx,
                cashbook.id,
                userId,
                {
                    type: 'INCOME',
                    amount: charge.toFixed(4),
                    description: `Rental income — ${agreement.quantity} × ${agreement.lenderItem.name} (${agreement.periodCount} ${agreement.periodUnit.toLowerCase()}${agreement.periodCount > 1 ? 's' : ''}) — contract ${agreementId.slice(0, 8)}`,
                    accountId: dto.accountId,
                    entryDate: dto.entryDate ?? new Date().toISOString(),
                } as any,
            );

            // The one-time claim — same race protection as the expense side.
            const { count } = await tx.rentalAgreement.updateMany({
                where: { id: agreementId, incomeEntryId: null },
                data: { incomeEntryId: entry.id },
            });
            if (count !== 1) {
                throw new AppError('The rental income has already been recorded for this contract', 409, 'ALREADY_RECORDED');
            }

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: agreement.lenderWorkspaceId,
                    action: AuditAction.RENTAL_AGREEMENT_INCOME_RECORDED,
                    resource: 'rental_agreement',
                    resourceId: agreementId,
                    details: {
                        entryId: entry.id,
                        amount: charge.toString(),
                        cashbookId: cashbook.id,
                    } as any,
                },
            });

            return entry;
        });
    }

    /**
     * The borrower's side of the money: record the rental cost as an EXPENSE
     * entry in their accepted workspace.
     *
     * Only meaningful once the contract is accepted, and only into the
     * workspace the acceptance named — anywhere else is somebody else's book.
     * The entry follows the ordinary entry path, so journals, wallets and
     * balances all behave; the description ties it back to the contract.
     */
    async recordBorrowerExpense(
        agreementId: string,
        userId: string,
        dto: { cashbookId: string; accountId?: string; entryDate?: string },
    ) {
        const { EntriesService } = await import('../entries/entries.service');
        const { container } = await import('tsyringe');

        const agreement = await this.prisma.rentalAgreement.findUnique({
            where: { id: agreementId },
            select: {
                id: true, status: true, borrowerUserId: true, borrowerWorkspaceId: true,
                lenderWorkspaceId: true, rate: true, quantity: true, periodCount: true,
                periodUnit: true, expenseEntryId: true,
                lenderItem: { select: { name: true, currency: true } },
                lenderUser: { select: { firstName: true, lastName: true } },
            },
        });
        if (!agreement) throw new NotFoundError('Rental agreement');
        if (agreement.borrowerUserId !== userId) {
            throw new AuthorizationError('Only the borrower can record this expense');
        }
        if (agreement.status !== RentalAgreementStatus.ACCEPTED) {
            throw new AppError('Accept the contract before recording its cost', 400, 'INVALID_STATUS');
        }
        if (!agreement.borrowerWorkspaceId) {
            throw new AppError(
                'This contract was accepted without a workspace — record the expense manually',
                400,
                'NO_BORROWER_WORKSPACE',
            );
        }

        const cashbook = await this.prisma.cashbook.findUnique({ where: { id: dto.cashbookId } });
        if (!cashbook || !cashbook.isActive) throw new NotFoundError('Cashbook');
        if (cashbook.workspaceId !== agreement.borrowerWorkspaceId) {
            throw new AppError(
                'The rental cost can only be recorded in the workspace the contract was accepted into',
                400,
                'WRONG_WORKSPACE',
            );
        }
        if (cashbook.currency !== agreement.lenderItem.currency) {
            throw new AppError(
                `This book's currency (${cashbook.currency}) does not match the rental's (${agreement.lenderItem.currency})`,
                400,
                'CURRENCY_MISMATCH',
            );
        }

        const charge = (agreement.rate ?? new Decimal(0))
            .mul(agreement.quantity)
            .mul(agreement.periodCount);
        if (charge.lessThanOrEqualTo(0)) {
            throw new AppError('This contract carries no charge — there is nothing to record', 400, 'NO_CHARGE');
        }
        // One-time by design: a second click (or a retry racing the first)
        // must not bill the contract twice. Checked last so a wrong-workspace
        // or wrong-party attempt reports its actual problem first.
        if (agreement.expenseEntryId) {
            throw new AppError('The rental expense has already been recorded for this contract', 409, 'ALREADY_RECORDED');
        }

        const lenderName = `${agreement.lenderUser.firstName} ${agreement.lenderUser.lastName}`.trim();

        return withFinancialTransaction(this.prisma, async (tx) => {
            const entry = await container.resolve(EntriesService).createEntryWithin(
                tx,
                cashbook.id,
                userId,
                {
                    type: 'EXPENSE',
                    amount: charge.toFixed(4),
                    description: `Rental — ${agreement.quantity} × ${agreement.lenderItem.name} (${agreement.periodCount} ${agreement.periodUnit.toLowerCase()}${agreement.periodCount > 1 ? 's' : ''}) — ${lenderName}`,
                    accountId: dto.accountId,
                    entryDate: dto.entryDate ?? new Date().toISOString(),
                } as any,
            );

            /*
             * The one-time claim, atomically: only a request that still sees
             * null wins, and it stamps the REAL entry id (the FK demands it).
             * A concurrent loser throws here — and the whole transaction,
             * including its entry, rolls back. Nothing is double-billed.
             */
            const { count } = await tx.rentalAgreement.updateMany({
                where: { id: agreementId, expenseEntryId: null },
                data: { expenseEntryId: entry.id },
            });
            if (count !== 1) {
                throw new AppError('The rental expense has already been recorded for this contract', 409, 'ALREADY_RECORDED');
            }

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: agreement.borrowerWorkspaceId,
                    action: AuditAction.RENTAL_AGREEMENT_EXPENSE_RECORDED,
                    resource: 'rental_agreement',
                    resourceId: agreementId,
                    details: {
                        entryId: entry.id,
                        amount: charge.toString(),
                        cashbookId: cashbook.id,
                    } as any,
                },
            });

            return entry;
        });
    }

    /** The borrower's workspace options for provenance at acceptance. */
    async getAcceptanceOptions(agreementId: string, userId: string) {
        const agreement = await this.getForUser(agreementId, userId);
        if (agreement.borrowerUserId !== userId) {
            throw new AuthorizationError('Only the borrower can respond to this agreement');
        }
        if (agreement.status !== RentalAgreementStatus.PENDING) {
            throw new AppError(`This agreement is already ${agreement.status.toLowerCase()}`, 400, 'INVALID_STATUS');
        }

        /*
         * Only workspaces the borrower owns or administers. An accepted
         * contract becomes an EXPENSE the borrower can record into the
         * accepted workspace — that write needs authority, and a plain
         * member's workspace is not theirs to commit. Owners pass by default;
         * members must hold ADMIN (or the equivalent OWNER role).
         */
        const [owned, adminMemberships] = await Promise.all([
            this.prisma.workspace.findMany({
                where: { ownerId: userId, isActive: true },
                select: { id: true, name: true, type: true },
            }),
            this.prisma.workspaceMember.findMany({
                where: { userId, role: { in: ['OWNER', 'ADMIN'] } },
                select: { workspace: { select: { id: true, name: true, type: true, isActive: true } } },
            }),
        ]);
        const admin = adminMemberships
            .map((m) => m.workspace)
            .filter((w) => w.isActive);
        const seen = new Set<string>();
        const workspaces = [...owned, ...admin].filter((w) => {
            if (seen.has(w.id) || w.id === agreement.lenderWorkspaceId) return false;
            seen.add(w.id);
            return true;
        });
        return { workspaces };
    }
}

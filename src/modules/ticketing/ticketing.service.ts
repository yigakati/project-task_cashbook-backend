/**
 * The ticket desk.
 *
 * The design constraint that shapes everything here: an attendant on a phone at
 * a gate, in a queue, must confirm a sale in two taps. Everything that would
 * normally be a decision — which book, which category, what price, what
 * discount, what the entry says — is resolved from configuration the manager
 * already made, or computed. The attendant chooses tiers, a wallet, and confirms.
 *
 * The money side is not re-invented. A sale posts one ordinary cashbook Entry
 * through EntriesService.createEntryWithin, which posts the journal, moves the
 * wallet and updates the cached balances exactly as a hand-typed entry would. A
 * void reverses it through EntriesService.reverseEntryWithin. Ticketing owns
 * WHAT was sold and WHO may reverse it; the ledger owns what that means to the
 * books, and there is one implementation of each.
 */
import { injectable, inject } from 'tsyringe';
import { Prisma, PrismaClient } from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import {
    AppError,
    NotFoundError,
    AuthorizationError,
    ConflictError,
} from '../../core/errors/AppError';
import { AuditAction, StaffTag, WorkspaceRole } from '../../core/types';
import { WorkspacePermission } from '../../core/types/workspace-permissions';
import { ticketDeskCapabilities, isTicketingEnabled } from '../../core/authz/ticketing-access';
import { withFinancialTransaction } from '../../core/db/transaction';
import { acquireLocks } from '../../core/db/locks';
import { toDecimal } from '../../core/finance/money';
import { WorkspaceClock, BusinessDate, toDateColumn } from '../../core/time/workspace-clock';
import { ticketClockFor, sessionDayOfWeek } from './business-day';
import {
    quoteSale,
    SaleQuote,
    TicketTypeSnapshot,
    DiscountRuleSnapshot,
    MembershipSnapshot,
} from './pricing';
import {
    QuoteSaleDto,
    CreateSaleDto,
    VoidSaleDto,
    ListSalesDto,
    ListDaysDto,
    CloseDayDto,
    OpenShiftDto,
    CloseShiftDto,
} from './ticketing.dto';
import { EntriesService } from '../entries/entries.service';
import { PaymentModesService } from '../payment-modes/payment-modes.service';
import { logger } from '../../utils/logger';

/** Everything the desk needs about the caller, resolved once by the guard. */
export interface DeskActor {
    userId: string;
    role: WorkspaceRole;
    staffTag: StaffTag | null;
    capabilities: Set<WorkspacePermission>;
}

const ZERO = new Decimal(0);

@injectable()
export class TicketingService {
    constructor(
        @inject('PrismaClient') private prisma: PrismaClient,
        private entriesService: EntriesService,
        private paymentModesService: PaymentModesService,
    ) { }

    // ─── Access ───────────────────────────────────────

    /**
     * What the client is allowed to render.
     *
     * The frontend asks the server rather than re-deriving the staff-tag rule in
     * TypeScript. Two implementations of "may this person sell tickets" is one
     * more than can be kept in step, and the one that drifts is always the one
     * that decides what a user sees.
     */
    async getAccess(workspaceId: string, actor: DeskActor, enabled = true) {
        if (!enabled) {
            // The module is not unlocked for this organisation — the normal
            // answer for most workspaces, so it is returned as data rather
            // than as an error the browser logs on every page load.
            return {
                enabled: false,
                configured: false,
                role: actor.role,
                staffTag: actor.staffTag,
                capabilities: [...actor.capabilities],
            };
        }

        const settings = await this.prisma.ticketSettings.findUnique({
            where: { workspaceId },
            select: { isConfigured: true },
        });

        return {
            enabled: true,
            configured: settings?.isConfigured ?? false,
            role: actor.role,
            staffTag: actor.staffTag,
            capabilities: [...actor.capabilities],
        };
    }

    // ─── Today ────────────────────────────────────────

    /**
     * What the attendant sees on landing: the session running now, its tiers and
     * offers, how much room is left, and their own open drawer.
     *
     * Only the current business day. Yesterday's takings are a supervisor's
     * concern and a distraction at a gate — history is behind an explicit date
     * filter on the sales list.
     */
    async getToday(workspaceId: string, actor: DeskActor) {
        const settings = await this.requireSettings(workspaceId, { configured: false });
        const clock = await ticketClockFor(this.prisma, workspaceId);
        const businessDate = clock.businessDate(new Date());

        // The gate book's currency, which every wallet the desk offers must
        // match — the entry path refuses a mismatch and there is no FX anywhere.
        const gateBook = settings.cashbookId
            ? await this.prisma.cashbook.findUnique({
                where: { id: settings.cashbookId },
                select: { currency: true },
            })
            : null;
        const currency = gateBook?.currency ?? null;

        if (!settings.isConfigured) {
            return {
                state: 'SETUP_REQUIRED' as const,
                businessDate,
                session: null,
                ticketDay: null,
                openShift: null,
                wallets: [],
                paymentModes: [],
            };
        }

        const session = await this.resolveSession(workspaceId, clock, businessDate);

        if (!session) {
            return {
                state: 'NO_SESSION' as const,
                businessDate,
                session: null,
                ticketDay: null,
                openShift: await this.findOpenShift(workspaceId, actor.userId),
                wallets: await this.listWallets(workspaceId, currency),
                paymentModes: await this.listPaymentModes(workspaceId),
            };
        }

        const ticketDay = await this.prisma.ticketDay.findUnique({
            where: {
                workspaceId_businessDate_sessionId: {
                    workspaceId,
                    businessDate: toDateColumn(businessDate),
                    sessionId: session.id,
                },
            },
        });

        const issued = ticketDay ? await this.countIssued(this.prisma, ticketDay.id) : 0;
        const capacity = ticketDay?.capacity ?? session.capacity ?? null;

        return {
            state: 'OPEN' as const,
            businessDate,
            session: {
                id: session.id,
                name: session.name,
                description: session.description,
                dayOfWeek: session.dayOfWeek,
                specificDate: session.specificDate,
                types: session.types,
                rules: session.rules,
            },
            ticketDay: ticketDay
                ? {
                    id: ticketDay.id,
                    status: ticketDay.status,
                    issuedCount: issued,
                    capacity,
                    remaining: capacity === null ? null : Math.max(0, capacity - issued),
                }
                : { id: null, status: 'OPEN', issuedCount: 0, capacity, remaining: capacity },
            openShift: await this.findOpenShift(workspaceId, actor.userId),
            wallets: await this.listWallets(workspaceId, currency),
            paymentModes: await this.listPaymentModes(workspaceId),
            defaultPaymentModeId: settings.defaultPaymentModeId,
            allowSelfVoid: settings.allowSelfVoid,
        };
    }

    // ─── Quote ────────────────────────────────────────

    /** A price preview, computed by the function that will do the charging. */
    async quote(workspaceId: string, dto: QuoteSaleDto) {
        const clock = await ticketClockFor(this.prisma, workspaceId);
        const businessDate = clock.businessDate(new Date());
        const session = await this.requireSession(workspaceId, clock, businessDate, dto.sessionId);
        const membership = await this.resolveMembership(
            this.prisma, workspaceId, dto.memberNo, businessDate,
        );

        const result = quoteSale({
            types: this.typeSnapshots(session.types),
            lines: dto.lines,
            rules: this.ruleSnapshots(session.rules),
            membership,
            manualRuleIds: dto.manualRuleIds,
        });

        return {
            businessDate,
            sessionId: session.id,
            membership: membership
                ? { id: membership.id, tierId: membership.tierId, memberNo: dto.memberNo }
                : null,
            ...serializeQuote(result),
        };
    }

    // ─── Payment method for a wallet ──────────────────

    /**
     * The payment method that goes with a wallet, get-or-create.
     *
     * Delegates to PaymentModesService so the desk and the ordinary entry
     * screens share one implementation — the alternative is two get-or-create
     * routines that drift on naming or on how they handle a soft-deleted mode.
     * The ticketing route wrapping this is gated on SELL_TICKETS; the general
     * one on workspace membership. Same behaviour, different doors.
     */
    async ensurePaymentModeForAccount(workspaceId: string, accountId: string, userId: string) {
        return this.paymentModesService.ensurePaymentModeForAccount(workspaceId, accountId, userId);
    }

    // ─── Create sale ──────────────────────────────────

    /**
     * One confirm tap.
     *
     * Everything below commits together or not at all: the sale, the tickets, the
     * membership redemption and the cashbook entry that records the money. That
     * atomicity is the whole reason EntriesService exposes createEntryWithin — a
     * sale durable without its entry is a night's takings that never reached the
     * books, and one durable without its sale is money with no admissions behind
     * it.
     */
    async createSale(workspaceId: string, actor: DeskActor, dto: CreateSaleDto) {
        const settings = await this.requireSettings(workspaceId, { configured: true });
        const clock = await ticketClockFor(this.prisma, workspaceId);
        const businessDate = clock.businessDate(new Date());
        const session = await this.requireSession(workspaceId, clock, businessDate, dto.sessionId);

        // Validate the wallet before opening a transaction: a bad wallet is the
        // commonest mistake and does not deserve a rollback.
        const wallet = await this.prisma.account.findUnique({ where: { id: dto.accountId } });
        if (!wallet || wallet.workspaceId !== workspaceId) {
            throw new AppError('Choose a wallet in this workspace', 400, 'INVALID_ACCOUNT');
        }
        if (wallet.archivedAt) {
            throw new AppError('That wallet is archived', 400, 'ACCOUNT_ARCHIVED');
        }

        if (dto.paymentModeId) {
            const mode = await this.prisma.paymentMode.findUnique({
                where: { id: dto.paymentModeId },
            });
            if (!mode || mode.workspaceId !== workspaceId) {
                throw new AppError('Choose a payment method in this workspace', 400, 'INVALID_PAYMENT_MODE');
            }
        }

        // Discounting by hand is a manager's decision, not an attendant's.
        if (dto.manualRuleIds?.length && !actor.capabilities.has(WorkspacePermission.MANAGE_TICKETING)) {
            throw new AuthorizationError('Only a manager may apply a manual discount');
        }

        // Opened before the transaction, not inside it — see ensureDay.
        const ticketDay = await this.ensureDay(workspaceId, session, businessDate, actor.userId);

        const sale = await withFinancialTransaction(this.prisma, async (tx) => {
            // TICKET_DAY ranks above CASHBOOK, so this composes with the locks
            // createEntryWithin takes below rather than racing them.
            await acquireLocks(tx, [{ target: 'TICKET_DAY', ids: [ticketDay.id] }]);

            const locked = await tx.ticketDay.findUniqueOrThrow({ where: { id: ticketDay.id } });
            if (locked.status !== 'OPEN') {
                throw new AppError(
                    'This day has been closed. Reopen it before selling.',
                    409,
                    'TICKET_DAY_CLOSED',
                );
            }

            // Re-price under the lock, from the database, ignoring anything the
            // client thought the answer was.
            const membership = await this.resolveMembership(tx, workspaceId, dto.memberNo, businessDate);
            const quote = quoteSale({
                types: this.typeSnapshots(session.types),
                lines: dto.lines,
                rules: this.ruleSnapshots(session.rules),
                membership,
                manualRuleIds: dto.manualRuleIds,
            });

            await this.assertCapacity(tx, locked, session, quote, dto.lines);

            const shift = await this.findOpenShift(workspaceId, actor.userId, tx);

            const sale = await tx.ticketSale.create({
                data: {
                    workspaceId,
                    ticketDayId: locked.id,
                    shiftId: shift?.id ?? null,
                    accountId: dto.accountId,
                    paymentModeId: dto.paymentModeId ?? settings.defaultPaymentModeId ?? null,
                    membershipId: membership?.id ?? null,
                    grossAmount: quote.grossAmount,
                    discountAmount: quote.discountAmount,
                    netAmount: quote.netAmount,
                    ticketCount: quote.ticketCount,
                    soldById: actor.userId,
                    lines: {
                        create: quote.lines.map((line) => ({
                            ticketTypeId: line.ticketTypeId,
                            quantity: line.quantity,
                            unitPrice: line.unitPrice,
                            lineGross: line.lineGross,
                            lineDiscount: line.lineDiscount,
                            lineNet: line.lineNet,
                        })),
                    },
                },
            });

            // Serials come from the day's counter, which is why the day is
            // locked: two attendants confirming at once would otherwise be
            // handed the same number.
            const firstSerial = locked.nextSerial;
            await tx.ticketDay.update({
                where: { id: locked.id },
                data: { nextSerial: firstSerial + quote.tickets.length },
            });

            const datePart = businessDate.replace(/-/g, '');
            await tx.ticket.createMany({
                data: quote.tickets.map((ticket, i) => ({
                    workspaceId,
                    saleId: sale.id,
                    ticketDayId: locked.id,
                    ticketTypeId: ticket.ticketTypeId,
                    serialNo: `TKT-${datePart}-${String(firstSerial + i).padStart(4, '0')}`,
                    patronClass: ticket.patronClass as any,
                    grossPrice: ticket.grossPrice,
                    discountAmount: ticket.discountAmount,
                    netPrice: ticket.netPrice,
                    appliedRuleId: ticket.appliedRuleId,
                })),
            });

            // ─── The money ───
            //
            // A sale comped to zero posts NO entry. There is no money to record,
            // the ledger has nothing to say about it, and a zero-amount entry
            // fails validation. The tickets are still issued and still counted as
            // admissions, which is the point of tracking comps at all.
            let entryId: string | null = null;
            if (quote.netAmount.greaterThan(0)) {
                const entry = await this.entriesService.createEntryWithin(
                    tx,
                    settings.cashbookId!,
                    actor.userId,
                    {
                        type: 'INCOME',
                        amount: quote.netAmount.toFixed(4),
                        description: this.describeSale(session.name, quote, dto.note),
                        categoryId: this.revenueCategoryFor(session.types, quote, settings)
                            ?? undefined,
                        accountId: dto.accountId,
                        paymentModeId: dto.paymentModeId ?? settings.defaultPaymentModeId ?? undefined,
                        contactId: membership?.contactId ?? undefined,
                        entryDate: new Date().toISOString(),
                    } as any,
                );
                entryId = entry.id;
                await tx.ticketSale.update({
                    where: { id: sale.id },
                    data: { entryId },
                });
            }

            if (membership && quote.membershipTicketCount > 0) {
                await tx.membershipUsage.create({
                    data: {
                        membershipId: membership.id,
                        saleId: sale.id,
                        ticketDayId: locked.id,
                        ticketCount: quote.membershipTicketCount,
                        discountAmount: quote.membershipDiscount,
                    },
                });
            }

            await tx.auditLog.create({
                data: {
                    userId: actor.userId,
                    workspaceId,
                    action: AuditAction.TICKET_SALE_CREATED,
                    resource: 'ticket_sale',
                    resourceId: sale.id,
                    details: {
                        businessDate,
                        sessionId: session.id,
                        ticketCount: quote.ticketCount,
                        gross: quote.grossAmount.toFixed(4),
                        discount: quote.discountAmount.toFixed(4),
                        net: quote.netAmount.toFixed(4),
                        entryId,
                        membershipId: membership?.id ?? null,
                        appliedRules: quote.appliedRules.map((r) => r.ruleName),
                    } as any,
                },
            });

            return sale.id;
        });

        return this.getSale(workspaceId, sale);
    }

    // ─── Void ─────────────────────────────────────────

    /**
     * Reverse a sale.
     *
     * Who may, and when:
     *
     *   An ATTENDANT may void their OWN sale while the day is still open. A
     *   mis-tap at a gate is caught in seconds, and routing that through an
     *   approval blocks the queue on somebody else's phone. `allowSelfVoid` lets
     *   an org turn this off.
     *
     *   A MANAGER (MANAGE_TICKETING) may void any sale on any open day.
     *
     *   Nobody may void on a CLOSED day. Closing marks the entries reconciled,
     *   and the ledger already treats a reconciled entry as immutable — this
     *   check just produces a comprehensible error rather than that one.
     *
     * There is no edit. A wrong amount is voided and re-issued, so the record
     * shows what happened rather than what somebody decided it should have said.
     */
    async voidSale(workspaceId: string, saleId: string, actor: DeskActor, dto: VoidSaleDto) {
        const sale = await this.prisma.ticketSale.findUnique({
            where: { id: saleId },
            include: { ticketDay: true },
        });

        if (!sale || sale.workspaceId !== workspaceId) {
            throw new NotFoundError('Ticket sale');
        }
        if (sale.status === 'VOIDED') {
            throw new AppError('This sale has already been reversed', 409, 'ALREADY_VOIDED');
        }
        if (sale.ticketDay.status !== 'OPEN') {
            throw new AppError(
                'That day has been closed and reconciled. Reopen it to reverse a sale.',
                409,
                'TICKET_DAY_CLOSED',
            );
        }

        const isManager = actor.capabilities.has(WorkspacePermission.MANAGE_TICKETING);
        if (!isManager) {
            const settings = await this.requireSettings(workspaceId, { configured: true });
            const ownSale = sale.soldById === actor.userId;
            if (!ownSale) {
                throw new AuthorizationError(
                    'You can only reverse sales you rang up yourself. Ask a supervisor.',
                );
            }
            if (!settings.allowSelfVoid) {
                throw new AuthorizationError(
                    'Reversing a sale needs a supervisor in this workspace.',
                );
            }
        }

        await withFinancialTransaction(this.prisma, async (tx) => {
            await acquireLocks(tx, [{ target: 'TICKET_DAY', ids: [sale.ticketDayId] }]);

            // Re-read under the lock: a day can close, or another attendant can
            // void the same sale, between the checks above and here.
            const locked = await tx.ticketSale.findUniqueOrThrow({
                where: { id: saleId },
                include: { ticketDay: { select: { status: true } } },
            });
            if (locked.status === 'VOIDED') {
                throw new ConflictError('This sale was reversed while you were looking at it.');
            }
            if (locked.ticketDay.status !== 'OPEN') {
                throw new ConflictError('That day was closed while you were looking at it.');
            }

            if (locked.entryId) {
                const entry = await tx.entry.findUnique({ where: { id: locked.entryId } });
                if (entry && entry.status !== 'REVERSED') {
                    await this.entriesService.reverseEntryWithin(
                        tx, entry, actor.userId, `Ticket sale reversed: ${dto.reason}`,
                    );
                }
            }

            await tx.ticketSale.update({
                where: { id: saleId },
                data: {
                    status: 'VOIDED',
                    voidedAt: new Date(),
                    voidedById: actor.userId,
                    voidReason: dto.reason,
                    version: { increment: 1 },
                },
            });

            await tx.ticket.updateMany({
                where: { saleId },
                data: { status: 'VOIDED' },
            });

            // The redemption is removed rather than kept, because these rows are
            // what enforce a tier's per-day cap. Leaving a voided redemption in
            // place would spend an allowance nobody received. The void itself is
            // audited below, so the history is not lost.
            await tx.membershipUsage.deleteMany({ where: { saleId } });

            await tx.auditLog.create({
                data: {
                    userId: actor.userId,
                    workspaceId,
                    action: AuditAction.TICKET_SALE_VOIDED,
                    resource: 'ticket_sale',
                    resourceId: saleId,
                    details: {
                        reason: dto.reason,
                        net: locked.netAmount.toFixed(4),
                        ticketCount: locked.ticketCount,
                        entryId: locked.entryId,
                        soldById: locked.soldById,
                        voidedBySupervisor: isManager && locked.soldById !== actor.userId,
                        membershipId: locked.membershipId,
                    } as any,
                },
            });
        });

        return this.getSale(workspaceId, saleId);
    }

    // ─── Reads ────────────────────────────────────────

    /**
     * The day's sales.
     *
     * Defaults to the CURRENT business day rather than everything ever sold.
     * With hundreds of sales a night, an unbounded default list is both a slow
     * query and a screen an attendant has to scroll past to find the sale they
     * just rang up wrong.
     */
    async listSales(workspaceId: string, actor: DeskActor, query: ListSalesDto) {
        const clock = await ticketClockFor(this.prisma, workspaceId);
        const businessDate = query.businessDate ?? clock.businessDate(new Date());

        // An attendant sees the desk's takings for the day, which is what they
        // need to spot their own mistake. Reading another DAY is a supervisor
        // action, because that is reporting rather than working the gate.
        const isManager = actor.capabilities.has(WorkspacePermission.MANAGE_TICKETING)
            || actor.capabilities.has(WorkspacePermission.VIEW_TICKET_ANALYTICS);
        if (query.businessDate && query.businessDate !== clock.businessDate(new Date()) && !isManager) {
            throw new AuthorizationError('Only a supervisor can look at earlier days');
        }

        const where: Prisma.TicketSaleWhereInput = {
            workspaceId,
            ticketDay: {
                businessDate: toDateColumn(businessDate),
                ...(query.sessionId ? { sessionId: query.sessionId } : {}),
            },
            ...(query.soldById ? { soldById: query.soldById } : {}),
            ...(query.shiftId ? { shiftId: query.shiftId } : {}),
            ...(query.includeVoided ? {} : { status: 'COMPLETED' as const }),
        };

        const [total, data] = await Promise.all([
            this.prisma.ticketSale.count({ where }),
            this.prisma.ticketSale.findMany({
                where,
                include: {
                    lines: { include: { ticketType: { select: { id: true, name: true } } } },
                    tickets: { select: { id: true, serialNo: true, netPrice: true, status: true } },
                    account: { select: { id: true, name: true } },
                    paymentMode: { select: { id: true, name: true } },
                    soldBy: { select: { id: true, firstName: true, lastName: true } },
                    voidedBy: { select: { id: true, firstName: true, lastName: true } },
                    membership: {
                        select: {
                            id: true, memberNo: true,
                            contact: { select: { id: true, name: true } },
                            tier: { select: { id: true, name: true } },
                        },
                    },
                },
                orderBy: { soldAt: 'desc' },
                skip: (query.page - 1) * query.limit,
                take: query.limit,
            }),
        ]);

        const totalPages = Math.ceil(total / query.limit) || 1;
        const totals = await this.dayTotals(workspaceId, businessDate, query.sessionId);

        return {
            data,
            businessDate,
            totals,
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

    async getSale(workspaceId: string, saleId: string) {
        const sale = await this.prisma.ticketSale.findUnique({
            where: { id: saleId },
            include: {
                lines: { include: { ticketType: { select: { id: true, name: true } } } },
                tickets: {
                    select: {
                        id: true, serialNo: true, patronClass: true,
                        grossPrice: true, discountAmount: true, netPrice: true,
                        status: true, appliedRule: { select: { id: true, name: true } },
                    },
                    orderBy: { serialNo: 'asc' },
                },
                account: { select: { id: true, name: true } },
                paymentMode: { select: { id: true, name: true } },
                soldBy: { select: { id: true, firstName: true, lastName: true } },
                voidedBy: { select: { id: true, firstName: true, lastName: true } },
                ticketDay: { select: { id: true, businessDate: true, status: true } },
                membership: {
                    select: {
                        id: true, memberNo: true,
                        tier: { select: { id: true, name: true } },
                        contact: { select: { id: true, name: true } },
                    },
                },
            },
        });

        if (!sale || sale.workspaceId !== workspaceId) throw new NotFoundError('Ticket sale');
        return sale;
    }

    // ─── Days ─────────────────────────────────────────

    async listDays(workspaceId: string, query: ListDaysDto) {
        const where: Prisma.TicketDayWhereInput = {
            workspaceId,
            ...(query.status ? { status: query.status } : {}),
            ...(query.from || query.to
                ? {
                    businessDate: {
                        ...(query.from ? { gte: toDateColumn(query.from) } : {}),
                        ...(query.to ? { lte: toDateColumn(query.to) } : {}),
                    },
                }
                : {}),
        };

        const [total, data] = await Promise.all([
            this.prisma.ticketDay.count({ where }),
            this.prisma.ticketDay.findMany({
                where,
                include: {
                    session: { select: { id: true, name: true } },
                    openedBy: { select: { id: true, firstName: true, lastName: true } },
                    closedBy: { select: { id: true, firstName: true, lastName: true } },
                    _count: { select: { sales: true, shifts: true } },
                },
                orderBy: { businessDate: 'desc' },
                skip: (query.page - 1) * query.limit,
                take: query.limit,
            }),
        ]);

        const totalPages = Math.ceil(total / query.limit) || 1;
        return {
            data,
            pagination: {
                page: query.page, limit: query.limit, total, totalPages,
                hasNext: query.page < totalPages, hasPrevious: query.page > 1,
            },
        };
    }

    /**
     * The Z-report: a day's takings, per tier, per attendant, per wallet.
     */
    async getDaySummary(workspaceId: string, ticketDayId: string) {
        const day = await this.prisma.ticketDay.findUnique({
            where: { id: ticketDayId },
            include: {
                session: { select: { id: true, name: true } },
                shifts: {
                    include: { attendant: { select: { id: true, firstName: true, lastName: true } } },
                    orderBy: { openedAt: 'asc' },
                },
            },
        });
        if (!day || day.workspaceId !== workspaceId) throw new NotFoundError('Ticket day');

        const businessDate = day.businessDate.toISOString().slice(0, 10);
        const totals = await this.dayTotals(workspaceId, businessDate, day.sessionId);
        const byType = await this.breakdownByType(workspaceId, ticketDayId);
        const byWallet = await this.breakdownByWallet(workspaceId, ticketDayId);
        const byAttendant = await this.breakdownByAttendant(workspaceId, ticketDayId);

        return { day, businessDate, totals, byType, byWallet, byAttendant };
    }

    /**
     * Close the day.
     *
     * This is what "reconcile all" means: the day's entries are marked
     * isReconciled, which the ledger already treats as immutable — they can no
     * longer be deleted, reassigned, or have their amounts edited by any path in
     * the application. The takings become a closed record rather than a running
     * total.
     */
    async closeDay(workspaceId: string, ticketDayId: string, actor: DeskActor, dto: CloseDayDto) {
        return withFinancialTransaction(this.prisma, async (tx) => {
            await acquireLocks(tx, [{ target: 'TICKET_DAY', ids: [ticketDayId] }]);

            const day = await tx.ticketDay.findUnique({ where: { id: ticketDayId } });
            if (!day || day.workspaceId !== workspaceId) throw new NotFoundError('Ticket day');
            if (day.status === 'CLOSED') {
                throw new AppError('This day is already closed', 409, 'TICKET_DAY_CLOSED');
            }

            const openShifts = await tx.ticketShift.count({
                where: { ticketDayId, status: 'OPEN' },
            });
            if (openShifts > 0) {
                throw new AppError(
                    `${openShifts} drawer(s) are still open. Count them in before closing the day.`,
                    409,
                    'SHIFTS_STILL_OPEN',
                );
            }

            const sales = await tx.ticketSale.findMany({
                where: { ticketDayId, status: 'COMPLETED', entryId: { not: null } },
                select: { entryId: true },
            });
            const entryIds = sales.map((s) => s.entryId!).filter(Boolean);

            if (entryIds.length > 0) {
                await tx.entry.updateMany({
                    where: { id: { in: entryIds }, status: 'POSTED' },
                    data: { isReconciled: true },
                });
            }

            const closed = await tx.ticketDay.update({
                where: { id: ticketDayId },
                data: {
                    status: 'CLOSED',
                    closedAt: new Date(),
                    closedById: actor.userId,
                    closingNotes: dto.notes ?? null,
                },
            });

            await tx.auditLog.create({
                data: {
                    userId: actor.userId,
                    workspaceId,
                    action: AuditAction.TICKET_DAY_CLOSED,
                    resource: 'ticket_day',
                    resourceId: ticketDayId,
                    details: {
                        businessDate: day.businessDate.toISOString().slice(0, 10),
                        reconciledEntries: entryIds.length,
                        notes: dto.notes ?? null,
                    } as any,
                },
            });

            return closed;
        });
    }

    /** Reopening unreconciles, so a correction is possible — and says who did it. */
    async reopenDay(workspaceId: string, ticketDayId: string, actor: DeskActor, dto: CloseDayDto) {
        return withFinancialTransaction(this.prisma, async (tx) => {
            await acquireLocks(tx, [{ target: 'TICKET_DAY', ids: [ticketDayId] }]);

            const day = await tx.ticketDay.findUnique({ where: { id: ticketDayId } });
            if (!day || day.workspaceId !== workspaceId) throw new NotFoundError('Ticket day');
            if (day.status === 'OPEN') {
                throw new AppError('This day is already open', 409, 'TICKET_DAY_OPEN');
            }

            const sales = await tx.ticketSale.findMany({
                where: { ticketDayId, status: 'COMPLETED', entryId: { not: null } },
                select: { entryId: true },
            });
            const entryIds = sales.map((s) => s.entryId!).filter(Boolean);
            if (entryIds.length > 0) {
                await tx.entry.updateMany({
                    where: { id: { in: entryIds } },
                    data: { isReconciled: false },
                });
            }

            const reopened = await tx.ticketDay.update({
                where: { id: ticketDayId },
                data: { status: 'OPEN', closedAt: null, closedById: null },
            });

            await tx.auditLog.create({
                data: {
                    userId: actor.userId,
                    workspaceId,
                    action: AuditAction.TICKET_DAY_REOPENED,
                    resource: 'ticket_day',
                    resourceId: ticketDayId,
                    details: {
                        businessDate: day.businessDate.toISOString().slice(0, 10),
                        unreconciledEntries: entryIds.length,
                        reason: dto.notes ?? null,
                    } as any,
                },
            });

            return reopened;
        });
    }

    // ─── Shifts ───────────────────────────────────────

    async openShift(workspaceId: string, actor: DeskActor, dto: OpenShiftDto) {
        const attendantId = dto.attendantId ?? actor.userId;

        if (attendantId !== actor.userId
            && !actor.capabilities.has(WorkspacePermission.MANAGE_TICKETING)) {
            throw new AuthorizationError('Only a supervisor can open a drawer for someone else');
        }

        const settings = await this.requireSettings(workspaceId, { configured: true });
        const clock = await ticketClockFor(this.prisma, workspaceId);
        const businessDate = clock.businessDate(new Date());
        const session = await this.requireSession(workspaceId, clock, businessDate);

        const day = await this.ensureDay(workspaceId, session, businessDate, actor.userId);

        return withFinancialTransaction(this.prisma, async (tx) => {
            const existing = await tx.ticketShift.findFirst({
                where: { ticketDayId: day.id, attendantId, status: 'OPEN' },
            });
            if (existing) {
                throw new AppError(
                    'That drawer is already open for today',
                    409,
                    'SHIFT_ALREADY_OPEN',
                );
            }

            const shift = await tx.ticketShift.create({
                data: {
                    workspaceId,
                    ticketDayId: day.id,
                    attendantId,
                    openingFloat: toDecimal(dto.openingFloat),
                },
            });

            await tx.auditLog.create({
                data: {
                    userId: actor.userId,
                    workspaceId,
                    action: AuditAction.TICKET_SHIFT_OPENED,
                    resource: 'ticket_shift',
                    resourceId: shift.id,
                    details: { attendantId, businessDate, openingFloat: dto.openingFloat } as any,
                },
            });

            void settings;
            return shift;
        });
    }

    /**
     * Count the drawer in.
     *
     * Expected takings are computed per wallet from this shift's non-voided
     * sales and SNAPSHOT onto the shift, so a later reopen-and-void cannot
     * quietly change what the attendant was held to. The variance is recorded
     * whether it balances or not — a shift that only stores clean counts is a
     * shift that teaches nobody anything.
     */
    async closeShift(workspaceId: string, shiftId: string, actor: DeskActor, dto: CloseShiftDto) {
        return withFinancialTransaction(this.prisma, async (tx) => {
            await acquireLocks(tx, [{ target: 'TICKET_SHIFT', ids: [shiftId] }]);

            const shift = await tx.ticketShift.findUnique({ where: { id: shiftId } });
            if (!shift || shift.workspaceId !== workspaceId) throw new NotFoundError('Shift');
            if (shift.status === 'CLOSED') {
                throw new AppError('That drawer is already counted in', 409, 'SHIFT_CLOSED');
            }

            const isOwn = shift.attendantId === actor.userId;
            const canReconcile = actor.capabilities.has(WorkspacePermission.RECONCILE_TICKET_SHIFT);
            if (!isOwn && !canReconcile) {
                throw new AuthorizationError('Only a supervisor can close somebody else’s drawer');
            }

            const sales = await tx.ticketSale.findMany({
                where: { shiftId, status: 'COMPLETED' },
                select: { accountId: true, netAmount: true },
            });

            const wallets = await tx.account.findMany({
                where: { id: { in: [...new Set(sales.map((s) => s.accountId))] } },
                select: { id: true, name: true },
            });
            const walletName = new Map(wallets.map((w) => [w.id, w.name]));

            const expectedByWallet = new Map<string, Decimal>();
            for (const sale of sales) {
                expectedByWallet.set(
                    sale.accountId,
                    (expectedByWallet.get(sale.accountId) ?? ZERO).add(sale.netAmount),
                );
            }

            const countedByWallet = new Map(
                dto.counted.map((c) => [c.accountId, toDecimal(c.amount)]),
            );

            // Every wallet that either took money or was counted appears, so a
            // count against a wallet with no sales shows as an overage rather
            // than being silently dropped.
            const walletIds = new Set([...expectedByWallet.keys(), ...countedByWallet.keys()]);
            const breakdown = [...walletIds].sort().map((accountId) => {
                const expected = expectedByWallet.get(accountId) ?? ZERO;
                const counted = countedByWallet.get(accountId) ?? ZERO;
                return {
                    accountId,
                    accountName: walletName.get(accountId) ?? 'Unknown wallet',
                    expected: expected.toFixed(4),
                    counted: counted.toFixed(4),
                    variance: counted.sub(expected).toFixed(4),
                };
            });

            const expectedTotal = [...expectedByWallet.values()].reduce((a, b) => a.add(b), ZERO);
            const countedTotal = [...countedByWallet.values()].reduce((a, b) => a.add(b), ZERO);

            const closed = await tx.ticketShift.update({
                where: { id: shiftId },
                data: {
                    status: 'CLOSED',
                    closedAt: new Date(),
                    closedById: actor.userId,
                    expectedByMode: breakdown as any,
                    expectedCash: expectedTotal,
                    countedCash: countedTotal,
                    variance: countedTotal.sub(expectedTotal),
                    notes: dto.notes ?? null,
                },
            });

            await tx.auditLog.create({
                data: {
                    userId: actor.userId,
                    workspaceId,
                    action: AuditAction.TICKET_SHIFT_CLOSED,
                    resource: 'ticket_shift',
                    resourceId: shiftId,
                    details: {
                        attendantId: shift.attendantId,
                        closedBySupervisor: !isOwn,
                        expected: expectedTotal.toFixed(4),
                        counted: countedTotal.toFixed(4),
                        variance: countedTotal.sub(expectedTotal).toFixed(4),
                        breakdown,
                        saleCount: sales.length,
                    } as any,
                },
            });

            return closed;
        });
    }

    async listShifts(workspaceId: string, ticketDayId?: string) {
        return this.prisma.ticketShift.findMany({
            where: { workspaceId, ...(ticketDayId ? { ticketDayId } : {}) },
            include: {
                attendant: { select: { id: true, firstName: true, lastName: true } },
                closedBy: { select: { id: true, firstName: true, lastName: true } },
                ticketDay: { select: { id: true, businessDate: true, status: true } },
                _count: { select: { sales: true } },
            },
            orderBy: { openedAt: 'desc' },
            take: 100,
        });
    }

    // ─── Internals ────────────────────────────────────

    private async requireSettings(workspaceId: string, opts: { configured: boolean }) {
        const settings = await this.prisma.ticketSettings.findUnique({ where: { workspaceId } });

        if (!settings) {
            if (opts.configured) {
                throw new AppError(
                    'Ticketing has not been set up yet. An owner or manager needs to choose '
                    + 'which book gate money posts to before the desk can sell.',
                    409,
                    'TICKETING_NOT_CONFIGURED',
                );
            }
            return {
                isConfigured: false,
                cashbookId: null,
                revenueCategoryId: null,
                defaultPaymentModeId: null,
                allowSelfVoid: true,
                dayStartMinutes: 0,
            } as const;
        }

        if (opts.configured && (!settings.isConfigured || !settings.cashbookId)) {
            throw new AppError(
                'Ticketing has not been set up yet. Choose the book gate money posts to first.',
                409,
                'TICKETING_NOT_CONFIGURED',
            );
        }

        return settings;
    }

    /**
     * Which session is running.
     *
     * A date-specific session wins over the weekly pattern, which is how a
     * public holiday gets its own prices without disturbing the weekly rota. The
     * database's partial unique indexes make at most one of each active, so this
     * is a choice between two rows rather than a sort over many.
     */
    private async resolveSession(
        workspaceId: string,
        clock: WorkspaceClock,
        businessDate: BusinessDate,
    ) {
        const include = {
            types: {
                where: { isActive: true },
                orderBy: [{ sortOrder: 'asc' as const }, { name: 'asc' as const }],
            },
        };

        const session =
            await this.prisma.ticketSession.findFirst({
                where: { workspaceId, isActive: true, specificDate: toDateColumn(businessDate) },
                include,
            })
            ?? await this.prisma.ticketSession.findFirst({
                where: {
                    workspaceId,
                    isActive: true,
                    dayOfWeek: sessionDayOfWeek(clock, businessDate),
                },
                include,
            });

        if (!session) return null;

        // Offers are loaded by query rather than through the session's `rules`
        // relation, because a rule with a null sessionId applies to EVERY
        // session — and the relation, by definition, only returns the ones that
        // named this session. Reading it that way silently dropped every
        // org-wide offer, which is a discount that is configured, looks correct
        // in the settings screen, and never fires.
        const rules = await this.prisma.ticketDiscountRule.findMany({
            where: {
                workspaceId,
                isActive: true,
                OR: [{ sessionId: session.id }, { sessionId: null }],
            },
        });

        return { ...session, rules };
    }

    private async requireSession(
        workspaceId: string,
        clock: WorkspaceClock,
        businessDate: BusinessDate,
        expectedId?: string,
    ) {
        const session = await this.resolveSession(workspaceId, clock, businessDate);
        if (!session) {
            throw new AppError(
                'No ticket pricing is set up for today. A manager needs to configure this day '
                + 'before the desk can sell.',
                409,
                'NO_SESSION_TODAY',
            );
        }
        if (expectedId && expectedId !== session.id) {
            // The client is looking at a stale session — prices changed under it.
            throw new ConflictError(
                'The pricing for today changed while you were looking at it. Reload the desk.',
            );
        }
        if (session.types.length === 0) {
            throw new AppError(
                `"${session.name}" has no ticket types yet. A manager needs to add at least one.`,
                409,
                'SESSION_HAS_NO_TYPES',
            );
        }
        return session;
    }

    /**
     * Find or open tonight's day row. Idempotent, so the first sale opens the
     * gate and nobody has to remember to.
     *
     * Deliberately runs OUTSIDE the caller's transaction, and this is the whole
     * subtlety. Two attendants ringing the first sale of the night at the same
     * instant race on the unique constraint, and in Postgres a failed statement
     * aborts the surrounding transaction — every subsequent command returns
     * 25P02 "current transaction is aborted". So the loser cannot recover by
     * reading the winner's row from inside the same transaction; it can only
     * roll the whole sale back.
     *
     * Creating the day first, in its own statement, means the loser reads the
     * winner's row and carries on selling. An opened day with no sales against
     * it is a legitimate state — `openShift` produces one too.
     */
    private async ensureDay(
        workspaceId: string,
        session: { id: string; capacity: number | null },
        businessDate: BusinessDate,
        userId: string,
    ) {
        const key = {
            workspaceId,
            businessDate: toDateColumn(businessDate),
            sessionId: session.id,
        };

        const existing = await this.prisma.ticketDay.findUnique({
            where: { workspaceId_businessDate_sessionId: key },
        });
        if (existing) return existing;

        try {
            const created = await this.prisma.ticketDay.create({
                data: { ...key, capacity: session.capacity, openedById: userId },
            });
            await this.prisma.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.TICKET_DAY_OPENED,
                    resource: 'ticket_day',
                    resourceId: created.id,
                    details: { businessDate, sessionId: session.id } as any,
                },
            });
            return created;
        } catch (error) {
            if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
                return this.prisma.ticketDay.findUniqueOrThrow({
                    where: { workspaceId_businessDate_sessionId: key },
                });
            }
            throw error;
        }
    }

    /**
     * Refuse to oversell.
     *
     * Counted under the day's row lock, so two attendants racing for the last
     * seat cannot both be told yes. Voided tickets are excluded, so reversing a
     * sale really does put the seats back.
     */
    private async assertCapacity(
        tx: Prisma.TransactionClient,
        day: { id: string; capacity: number | null },
        session: { types: { id: string; name: string; capacity: number | null }[] },
        quote: SaleQuote,
        lines: { ticketTypeId: string; quantity: number }[],
    ) {
        if (day.capacity !== null) {
            const issued = await this.countIssued(tx, day.id);
            if (issued + quote.ticketCount > day.capacity) {
                throw new AppError(
                    `Only ${Math.max(0, day.capacity - issued)} ticket(s) left tonight.`,
                    409,
                    'SOLD_OUT',
                );
            }
        }

        const capped = session.types.filter((t) => t.capacity !== null);
        for (const type of capped) {
            const wanted = lines
                .filter((l) => l.ticketTypeId === type.id)
                .reduce((sum, l) => sum + l.quantity, 0);
            if (wanted === 0) continue;

            const issued = await tx.ticket.count({
                where: { ticketDayId: day.id, ticketTypeId: type.id, status: 'ISSUED' },
            });
            if (issued + wanted > type.capacity!) {
                throw new AppError(
                    `Only ${Math.max(0, type.capacity! - issued)} ${type.name} ticket(s) left tonight.`,
                    409,
                    'SOLD_OUT',
                );
            }
        }
    }

    private countIssued(
        db: Pick<PrismaClient, 'ticket'> | Prisma.TransactionClient,
        ticketDayId: string,
    ): Promise<number> {
        return (db as PrismaClient).ticket.count({
            where: { ticketDayId, status: 'ISSUED' },
        });
    }

    /**
     * The card at the desk, if it is real and still valid.
     *
     * An unknown or lapsed number is not an error: the attendant typed something
     * and the queue is waiting. The sale goes through at list price and the
     * response says the card did not apply, which the desk shows.
     */
    private async resolveMembership(
        db: PrismaClient | Prisma.TransactionClient,
        workspaceId: string,
        memberNo: string | undefined,
        businessDate: BusinessDate,
    ): Promise<(MembershipSnapshot & { contactId: string }) | null> {
        if (!memberNo?.trim()) return null;

        const membership = await (db as PrismaClient).membership.findUnique({
            where: { workspaceId_memberNo: { workspaceId, memberNo: memberNo.trim() } },
            include: { tier: { select: { id: true, maxUsesPerDay: true, isActive: true } } },
        });

        if (!membership || membership.status !== 'ACTIVE' || !membership.tier.isActive) return null;

        const now = new Date();
        if (membership.validUntil && membership.validUntil < now) return null;
        if (membership.validFrom > now) return null;

        // Usage is counted per business day across every sale, which is what
        // makes a per-day cap mean anything — otherwise one card discounts a
        // coach party one ticket at a time.
        const used = await (db as PrismaClient).membershipUsage.aggregate({
            where: {
                membershipId: membership.id,
                ticketDay: { businessDate: toDateColumn(businessDate) },
            },
            _sum: { ticketCount: true },
        });

        return {
            id: membership.id,
            tierId: membership.tierId,
            contactId: membership.contactId,
            maxUsesPerDay: membership.tier.maxUsesPerDay,
            usedToday: used._sum.ticketCount ?? 0,
        };
    }

    private typeSnapshots(
        types: { id: string; name: string; patronClass: string; price: Decimal }[],
    ): TicketTypeSnapshot[] {
        return types.map((t) => ({
            id: t.id,
            name: t.name,
            patronClass: t.patronClass as TicketTypeSnapshot['patronClass'],
            price: t.price,
        }));
    }

    private ruleSnapshots(rules: any[]): DiscountRuleSnapshot[] {
        return rules.map((r) => ({
            id: r.id,
            name: r.name,
            type: r.type,
            valueType: r.valueType,
            value: r.value,
            config: (r.config ?? {}) as Record<string, unknown>,
            membershipTierId: r.membershipTierId,
            priority: r.priority,
            stackable: r.stackable,
        }));
    }

    /**
     * What the cashbook entry says.
     *
     * Written for whoever reads the book later, not for the desk: the session,
     * the head count and the tiers. "Ticket sale" alone would make a night of
     * gate takings indistinguishable line by line.
     */
    private describeSale(sessionName: string, quote: SaleQuote, note?: string): string {
        const parts = quote.lines
            .map((l) => `${l.quantity} × ${l.ticketTypeName}`)
            .join(', ');
        const comped = quote.discountAmount.greaterThan(0)
            ? ` (${quote.discountAmount.toFixed(0)} discounted)`
            : '';
        const suffix = note ? ` — ${note}` : '';
        return `${sessionName}: ${parts}${comped}${suffix}`.slice(0, 1000);
    }

    /**
     * Which revenue category the entry counts as.
     *
     * A tier may override the default so a venue can report adult and minor
     * revenue separately. A mixed basket has no single answer, so it falls back
     * to the workspace default rather than picking one tier's category and
     * quietly misreporting the rest.
     */
    private revenueCategoryFor(
        types: { id: string; categoryId: string | null }[],
        quote: SaleQuote,
        settings: { revenueCategoryId: string | null },
    ): string | null {
        const categoryById = new Map(types.map((t) => [t.id, t.categoryId]));
        const used = new Set(quote.lines.map((l) => categoryById.get(l.ticketTypeId) ?? null));
        if (used.size === 1) {
            const [only] = [...used];
            if (only) return only;
        }
        return settings.revenueCategoryId ?? null;
    }

    private findOpenShift(
        workspaceId: string,
        userId: string,
        tx?: Prisma.TransactionClient,
    ) {
        const db = (tx ?? this.prisma) as PrismaClient;
        return db.ticketShift.findFirst({
            where: { workspaceId, attendantId: userId, status: 'OPEN' },
            include: { ticketDay: { select: { id: true, businessDate: true, status: true } } },
        });
    }

    /**
     * The wallet picker.
     *
     * Identity only — never balances. Balances are a finance surface behind
     * VIEW_WALLET_BALANCES, and an attendant holds VIEW_WALLETS at most: they
     * need to say where the money went, not to see the organisation's cash
     * position.
     *
     * Filtered to the gate book's currency, because the entry path refuses a
     * mismatch (there is no FX anywhere in this system). Offering a wallet that
     * can only ever fail turns a configuration problem into an error the
     * attendant hits mid-queue.
     */
    private listWallets(workspaceId: string, currency?: string | null) {
        return this.prisma.account.findMany({
            where: {
                workspaceId,
                archivedAt: null,
                ...(currency ? { currency } : {}),
            },
            select: { id: true, name: true, currency: true, icon: true },
            orderBy: { name: 'asc' },
        });
    }

    private listPaymentModes(workspaceId: string) {
        return this.prisma.paymentMode.findMany({
            where: { workspaceId, isActive: true },
            select: { id: true, name: true },
            orderBy: { name: 'asc' },
        });
    }

    private async dayTotals(workspaceId: string, businessDate: BusinessDate, sessionId?: string) {
        const where: Prisma.TicketSaleWhereInput = {
            workspaceId,
            status: 'COMPLETED',
            ticketDay: {
                businessDate: toDateColumn(businessDate),
                ...(sessionId ? { sessionId } : {}),
            },
        };

        const [agg, voided] = await Promise.all([
            this.prisma.ticketSale.aggregate({
                where,
                _sum: {
                    grossAmount: true, discountAmount: true, netAmount: true, ticketCount: true,
                },
                _count: true,
            }),
            this.prisma.ticketSale.count({
                where: { ...where, status: 'VOIDED' },
            }),
        ]);

        return {
            saleCount: agg._count,
            voidedCount: voided,
            ticketCount: agg._sum.ticketCount ?? 0,
            gross: (agg._sum.grossAmount ?? ZERO).toFixed(4),
            discount: (agg._sum.discountAmount ?? ZERO).toFixed(4),
            net: (agg._sum.netAmount ?? ZERO).toFixed(4),
        };
    }

    private async breakdownByType(workspaceId: string, ticketDayId: string) {
        const rows = await this.prisma.ticket.groupBy({
            by: ['ticketTypeId'],
            where: { workspaceId, ticketDayId, status: 'ISSUED' },
            _count: { _all: true },
            _sum: { grossPrice: true, discountAmount: true, netPrice: true },
        });

        const types = await this.prisma.ticketType.findMany({
            where: { id: { in: rows.map((r) => r.ticketTypeId) } },
            select: { id: true, name: true, patronClass: true },
        });
        const nameById = new Map(types.map((t) => [t.id, t]));

        return rows.map((r) => ({
            ticketTypeId: r.ticketTypeId,
            name: nameById.get(r.ticketTypeId)?.name ?? 'Unknown',
            patronClass: nameById.get(r.ticketTypeId)?.patronClass ?? null,
            count: r._count._all,
            gross: (r._sum.grossPrice ?? ZERO).toFixed(4),
            discount: (r._sum.discountAmount ?? ZERO).toFixed(4),
            net: (r._sum.netPrice ?? ZERO).toFixed(4),
        }));
    }

    private async breakdownByWallet(workspaceId: string, ticketDayId: string) {
        const rows = await this.prisma.ticketSale.groupBy({
            by: ['accountId'],
            where: { workspaceId, ticketDayId, status: 'COMPLETED' },
            _sum: { netAmount: true },
            _count: { _all: true },
        });

        const wallets = await this.prisma.account.findMany({
            where: { id: { in: rows.map((r) => r.accountId) } },
            select: { id: true, name: true },
        });
        const nameById = new Map(wallets.map((w) => [w.id, w.name]));

        return rows.map((r) => ({
            accountId: r.accountId,
            name: nameById.get(r.accountId) ?? 'Unknown wallet',
            saleCount: r._count._all,
            net: (r._sum.netAmount ?? ZERO).toFixed(4),
        }));
    }

    private async breakdownByAttendant(workspaceId: string, ticketDayId: string) {
        const rows = await this.prisma.ticketSale.groupBy({
            by: ['soldById'],
            where: { workspaceId, ticketDayId, status: 'COMPLETED' },
            _sum: { netAmount: true, ticketCount: true },
            _count: { _all: true },
        });

        const users = await this.prisma.user.findMany({
            where: { id: { in: rows.map((r) => r.soldById) } },
            select: { id: true, firstName: true, lastName: true },
        });
        const byId = new Map(users.map((u) => [u.id, u]));

        return rows.map((r) => {
            const user = byId.get(r.soldById);
            return {
                userId: r.soldById,
                name: user ? `${user.firstName} ${user.lastName}` : 'Unknown',
                saleCount: r._count._all,
                ticketCount: r._sum.ticketCount ?? 0,
                net: (r._sum.netAmount ?? ZERO).toFixed(4),
            };
        });
    }
}

/** Decimals cross the wire as strings, as they do everywhere else in this API. */
function serializeQuote(quote: SaleQuote) {
    return {
        tickets: quote.tickets.map((t) => ({
            ticketTypeId: t.ticketTypeId,
            ticketTypeName: t.ticketTypeName,
            patronClass: t.patronClass,
            grossPrice: t.grossPrice.toFixed(4),
            discountAmount: t.discountAmount.toFixed(4),
            netPrice: t.netPrice.toFixed(4),
            appliedRuleId: t.appliedRuleId,
            appliedRuleName: t.appliedRuleName,
        })),
        lines: quote.lines.map((l) => ({
            ticketTypeId: l.ticketTypeId,
            ticketTypeName: l.ticketTypeName,
            quantity: l.quantity,
            unitPrice: l.unitPrice.toFixed(4),
            lineGross: l.lineGross.toFixed(4),
            lineDiscount: l.lineDiscount.toFixed(4),
            lineNet: l.lineNet.toFixed(4),
        })),
        grossAmount: quote.grossAmount.toFixed(4),
        discountAmount: quote.discountAmount.toFixed(4),
        netAmount: quote.netAmount.toFixed(4),
        ticketCount: quote.ticketCount,
        appliedRules: quote.appliedRules.map((r) => ({
            ruleId: r.ruleId,
            ruleName: r.ruleName,
            ticketCount: r.ticketCount,
            discountAmount: r.discountAmount.toFixed(4),
        })),
    };
}

export { serializeQuote };

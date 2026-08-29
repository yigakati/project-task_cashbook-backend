import { injectable, inject } from 'tsyringe';
import {
    Prisma, PrismaClient, PeerLinkStatus, PeerLinkDirection, ObligationStatus,
    ObligationType, ContactType, NotificationType, NotificationEntityType,
    WorkspaceType, CashbookRole, WorkspaceRole,
} from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import { NotFoundError, AppError, AuthorizationError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';
import { resolveInterest } from '../../core/finance/obligation-interest';
import { config } from '../../config';
import { PostingService } from '../../core/ledger/posting.service';
import { buildObligationJournal } from '../../core/ledger/rules/obligation.rules';
import { withFinancialTransaction } from '../../core/db/transaction';
import { acquireLocks } from '../../core/db/locks';
import { NotificationsService, NotificationJobData } from '../notifications/notifications.service';
import {
    CreatePeerLinkDto,
    RespondPeerLinkDto,
    DeclinePeerLinkDto,
    CancelPeerLinkDto,
    SettlementDecisionDto,
    PeerLinkQueryDto,
} from './peer-links.dto';

// Roles whose holders can accept a peer link into a book / see every book in
// the workspace obligations listing. Kept as typed constants so a role rename
// breaks the build here instead of silently widening acceptance.
const ACCEPT_BOOK_ROLES: ReadonlySet<WorkspaceRole> = new Set([
    WorkspaceRole.OWNER,
    WorkspaceRole.ADMIN,
    WorkspaceRole.GENERAL_MANAGER,
    WorkspaceRole.ACCOUNTANT,
]);
const ACCEPT_CASHBOOK_ROLES: ReadonlySet<CashbookRole> = new Set([
    CashbookRole.PRIMARY_ADMIN,
    CashbookRole.ADMIN,
    CashbookRole.BOOK_ADMIN,
]);

/** How a peer link payload is shaped for the client. */
const PEER_LINK_INCLUDE = {
    initiatorUser: { select: { id: true, email: true, firstName: true, lastName: true } },
    counterpartyUser: { select: { id: true, email: true, firstName: true, lastName: true } },
    initiatorCashbook: { select: { id: true, name: true, currency: true, workspaceId: true } },
    counterpartyCashbook: { select: { id: true, name: true, currency: true, workspaceId: true } },
    obligations: {
        select: {
            id: true, type: true, status: true, totalAmount: true, outstandingAmount: true,
            cashbookId: true, title: true,
        },
    },
} satisfies Prisma.PeerLinkInclude;

@injectable()
export class PeerLinksService {
    constructor(
        @inject('PrismaClient') private prisma: PrismaClient,
        private postingService: PostingService,
    ) { }

    // ─── Propose ─────────────────────────────────────────
    /**
     * Nothing touches any book yet. The proposal stores the agreed terms and
     * notifies the counterparty; the mirrored obligations only exist once they
     * accept into a book of their own choosing.
     */
    async createPeerLink(cashbookId: string, userId: string, dto: CreatePeerLinkDto) {
        const cashbook = await this.prisma.cashbook.findUnique({
            where: { id: cashbookId },
            select: { id: true, workspaceId: true, currency: true, isActive: true },
        });
        if (!cashbook || !cashbook.isActive) {
            throw new NotFoundError('Cashbook');
        }

        const counterparty = await this.prisma.user.findUnique({
            where: { email: dto.counterpartyEmail.toLowerCase() },
            select: { id: true, isActive: true },
        });
        if (!counterparty || !counterparty.isActive) {
            // Deliberately the same message as an unmatched email: an exact
            // email lookup must not let anyone enumerate the user base.
            throw new AppError('No active user found with that email', 404, 'USER_NOT_FOUND');
        }
        if (counterparty.id === userId) {
            throw new AppError('You cannot create a peer link with yourself', 400, 'SELF_PEER_LINK');
        }

        const resolved = resolveInterest({
            principalAmount: dto.principalAmount ?? dto.totalAmount!,
            interestRate: dto.interestRate ?? null,
            interestAmount: dto.interestAmount ?? null,
        });

        const peerLink = await this.prisma.$transaction(async (tx) => {
            const created = await tx.peerLink.create({
                data: {
                    status: PeerLinkStatus.PENDING,
                    direction: dto.direction,
                    initiatorUserId: userId,
                    initiatorWorkspaceId: cashbook.workspaceId,
                    initiatorCashbookId: cashbookId,
                    counterpartyUserId: counterparty.id,
                    title: dto.title,
                    description: dto.description || null,
                    currency: cashbook.currency,
                    principalAmount: resolved.principalAmount,
                    interestAmount: resolved.interestAmount,
                    interestRate: resolved.interestRate,
                    totalAmount: resolved.totalAmount,
                    dueDate: dto.dueDate ? new Date(dto.dueDate) : null,
                },
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: cashbook.workspaceId,
                    action: AuditAction.PEER_LINK_CREATED,
                    resource: 'peer_link',
                    resourceId: created.id,
                    details: {
                        direction: dto.direction,
                        counterpartyUserId: counterparty.id,
                        totalAmount: resolved.totalAmount.toString(),
                        title: dto.title,
                    } as any,
                },
            });

            return created;
        });

        NotificationsService.dispatch({
            type: NotificationType.PEER_LINK_RECEIVED,
            userId: counterparty.id,
            workspaceId: cashbook.workspaceId,
            title: 'New Peer Link request',
            body: `You've been asked to confirm a loan agreement: "${dto.title}"`,
            entityType: NotificationEntityType.PEER_LINK,
            entityId: peerLink.id,
            groupKey: `peer-link:${peerLink.id}`,
        });

        return this.getPeerLinkForUser(peerLink.id, userId);
    }

    // ─── Accept ──────────────────────────────────────────
    /**
     * The moment the loan exists on the books: two mirrored obligations are
     * created atomically — the initiator's on their book, the counterparty's on
     * the book they chose — each posting its normal opening journal in its own
     * workspace's chart of accounts. This transaction spans two workspaces by
     * design: either both sides get their proof or neither does.
     */
    async acceptPeerLink(peerLinkId: string, userId: string, dto: RespondPeerLinkDto) {
        // Notifications are collected during the transaction but only dispatched
        // once it commits — a queue message for a rolled-back acceptance would
        // be a lie the counterparty reads.
        const queued: Array<NotificationJobData & { workspaceId: string }> = [];

        const link = await withFinancialTransaction(this.prisma, async (tx) => {
            const pending = await tx.peerLink.findUnique({ where: { id: peerLinkId } });
            if (!pending) throw new NotFoundError('Peer link');
            if (pending.counterpartyUserId !== userId) {
                throw new AuthorizationError('Only the counterparty can respond to this peer link');
            }
            if (pending.status !== PeerLinkStatus.PENDING) {
                throw new AppError(`This peer link is already ${pending.status.toLowerCase()}`, 400, 'INVALID_STATUS');
            }

            const cashbook = await tx.cashbook.findUnique({ where: { id: dto.cashbookId } });
            if (!cashbook || !cashbook.isActive) {
                throw new NotFoundError('Cashbook');
            }
            if (cashbook.id === pending.initiatorCashbookId) {
                throw new AppError('Choose a different book for your side of the loan', 400, 'INVALID_CASHBOOK');
            }
            if (cashbook.currency !== pending.currency) {
                throw new AppError(
                    `This book's currency (${cashbook.currency}) does not match the loan currency (${pending.currency})`,
                    400,
                    'CURRENCY_MISMATCH',
                );
            }

            // The accepter must control the chosen book: its workspace owner,
            // or a member able to manage obligations there. Personal workspaces
            // need no membership row (owner bypass, same as the route guards).
            await this.assertCanManageObligationsIn(tx, cashbook.id, userId);

            // Books are locked before the mirrored rows are created, in global
            // lock order, so a concurrent settlement on either obligation
            // cannot interleave with acceptance.
            await acquireLocks(tx, [
                { target: 'CASHBOOK', ids: [pending.initiatorCashbookId, cashbook.id] },
            ]);

            const initiatorBook = await tx.cashbook.findUniqueOrThrow({
                where: { id: pending.initiatorCashbookId },
            });
            if (!initiatorBook.isActive) {
                throw new AppError('The initiator\'s book is no longer active', 400, 'BOOK_INACTIVE');
            }

            // Each side sees the other as a contact, so existing receivables/
            // payables reports and contact-based flows keep working unchanged.
            const [initiatorContact, counterpartyContact] = await Promise.all([
                this.ensureUserContact(tx, initiatorBook.workspaceId, pending.counterpartyUserId),
                this.ensureUserContact(tx, cashbook.workspaceId, pending.initiatorUserId),
            ]);

            // Direction decides who lends: LENDING → initiator holds the
            // receivable; BORROWING → counterparty holds it.
            const initiatorIsLender = pending.direction === PeerLinkDirection.LENDING;
            const initiatorType = initiatorIsLender ? ObligationType.RECEIVABLE : ObligationType.PAYABLE;
            const counterpartyType = initiatorIsLender ? ObligationType.PAYABLE : ObligationType.RECEIVABLE;

            const initiatorObligation = await this.createMirroredObligation(tx, {
                workspaceId: initiatorBook.workspaceId,
                cashbookId: initiatorBook.id,
                currency: initiatorBook.currency,
                peerLinkId: pending.id,
                type: initiatorType,
                title: pending.title,
                description: pending.description,
                principalAmount: pending.principalAmount,
                interestAmount: pending.interestAmount,
                interestRate: pending.interestRate,
                totalAmount: pending.totalAmount,
                dueDate: pending.dueDate,
                contactId: initiatorContact.id,
                userId: pending.initiatorUserId,
            });

            const counterpartyObligation = await this.createMirroredObligation(tx, {
                workspaceId: cashbook.workspaceId,
                cashbookId: cashbook.id,
                currency: cashbook.currency,
                peerLinkId: pending.id,
                type: counterpartyType,
                title: pending.title,
                description: pending.description,
                principalAmount: pending.principalAmount,
                interestAmount: pending.interestAmount,
                interestRate: pending.interestRate,
                totalAmount: pending.totalAmount,
                dueDate: pending.dueDate,
                contactId: counterpartyContact.id,
                userId,
            });

            const updated = await tx.peerLink.update({
                where: { id: pending.id },
                data: {
                    status: PeerLinkStatus.ACCEPTED,
                    counterpartyWorkspaceId: cashbook.workspaceId,
                    counterpartyCashbookId: cashbook.id,
                    respondedAt: new Date(),
                },
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: cashbook.workspaceId,
                    action: AuditAction.PEER_LINK_ACCEPTED,
                    resource: 'peer_link',
                    resourceId: pending.id,
                    details: {
                        initiatorObligationId: initiatorObligation.id,
                        counterpartyObligationId: counterpartyObligation.id,
                        cashbookId: cashbook.id,
                    } as any,
                },
            });

            queued.push(
                {
                    type: NotificationType.PEER_LINK_DECIDED,
                    userId: pending.initiatorUserId,
                    workspaceId: initiatorBook.workspaceId,
                    title: 'Peer Link accepted',
                    body: `Your loan agreement "${pending.title}" was accepted and is now on your books`,
                    entityType: NotificationEntityType.PEER_LINK,
                    entityId: pending.id,
                    groupKey: `peer-link:${pending.id}:decided`,
                },
                {
                    type: NotificationType.PEER_LINK_DECIDED,
                    userId,
                    workspaceId: cashbook.workspaceId,
                    title: 'Peer Link recorded',
                    body: `"${pending.title}" is now recorded in your book "${cashbook.name}"`,
                    entityType: NotificationEntityType.PEER_LINK,
                    entityId: pending.id,
                    groupKey: `peer-link:${pending.id}:decided`,
                },
            );

            return updated;
        });

        for (const n of queued) NotificationsService.dispatch(n);

        return this.getPeerLinkForUser(link.id, userId);
    }

    // ─── Decline / Cancel ────────────────────────────────
    async declinePeerLink(peerLinkId: string, userId: string, dto: DeclinePeerLinkDto) {
        const link = await this.prisma.peerLink.findUnique({ where: { id: peerLinkId } });
        if (!link) throw new NotFoundError('Peer link');
        if (link.counterpartyUserId !== userId) {
            throw new AuthorizationError('Only the counterparty can decline this peer link');
        }
        if (link.status !== PeerLinkStatus.PENDING) {
            throw new AppError(`This peer link is already ${link.status.toLowerCase()}`, 400, 'INVALID_STATUS');
        }

        const updated = await this.prisma.$transaction(async (tx) => {
            const declined = await tx.peerLink.update({
                where: { id: peerLinkId, status: PeerLinkStatus.PENDING },
                data: {
                    status: PeerLinkStatus.DECLINED,
                    declinedReason: dto.reason || null,
                    respondedAt: new Date(),
                },
            });
            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: link.initiatorWorkspaceId,
                    action: AuditAction.PEER_LINK_DECLINED,
                    resource: 'peer_link',
                    resourceId: peerLinkId,
                    details: { reason: dto.reason ?? null } as any,
                },
            });
            return declined;
        }).catch((error) => {
            if ((error as { code?: string }).code === 'P2025') {
                throw new AppError('This peer link is no longer pending', 400, 'INVALID_STATUS');
            }
            throw error;
        });

        NotificationsService.dispatch({
            type: NotificationType.PEER_LINK_DECIDED,
            userId: link.initiatorUserId,
            workspaceId: link.initiatorWorkspaceId,
            title: 'Peer Link declined',
            body: `Your loan agreement "${link.title}" was declined`,
            entityType: NotificationEntityType.PEER_LINK,
            entityId: link.id,
            groupKey: `peer-link:${link.id}:decided`,
        });

        return updated;
    }

    /**
     * The initiator can withdraw a proposal any time before it is answered.
     * After acceptance the loan exists on both books; cancelling that is a
     * write-off on each obligation, done from the books, not from here.
     */
    async cancelPeerLink(peerLinkId: string, userId: string, dto: CancelPeerLinkDto) {
        const link = await this.prisma.peerLink.findUnique({ where: { id: peerLinkId } });
        if (!link) throw new NotFoundError('Peer link');
        if (link.initiatorUserId !== userId) {
            throw new AuthorizationError('Only the initiator can cancel this peer link');
        }
        if (link.status !== PeerLinkStatus.PENDING) {
            throw new AppError('Only pending peer links can be cancelled. Accepted links are settled or written off from the books.', 400, 'INVALID_STATUS');
        }

        const updated = await this.prisma.$transaction(async (tx) => {
            const cancelled = await tx.peerLink.update({
                where: { id: peerLinkId, status: PeerLinkStatus.PENDING },
                data: { status: PeerLinkStatus.CANCELLED, respondedAt: new Date() },
            });
            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: link.initiatorWorkspaceId,
                    action: AuditAction.PEER_LINK_CANCELLED,
                    resource: 'peer_link',
                    resourceId: peerLinkId,
                    details: { reason: dto.reason ?? null } as any,
                },
            });
            return cancelled;
        }).catch((error) => {
            if ((error as { code?: string }).code === 'P2025') {
                throw new AppError('This peer link is no longer pending', 400, 'INVALID_STATUS');
            }
            throw error;
        });

        NotificationsService.dispatch({
            type: NotificationType.PEER_LINK_DECIDED,
            userId: link.counterpartyUserId,
            workspaceId: link.initiatorWorkspaceId,
            title: 'Peer Link cancelled',
            body: `The loan agreement "${link.title}" was withdrawn by its sender`,
            entityType: NotificationEntityType.PEER_LINK,
            entityId: link.id,
            groupKey: `peer-link:${link.id}:decided`,
        });

        return updated;
    }

    // ─── Query ───────────────────────────────────────────
    async getPeerLinks(userId: string, query: PeerLinkQueryDto) {
        const where: Prisma.PeerLinkWhereInput = {
            OR: [{ initiatorUserId: userId }, { counterpartyUserId: userId }],
        };
        if (query.direction === 'incoming') {
            where.OR = [{ counterpartyUserId: userId }];
        } else if (query.direction === 'outgoing') {
            where.OR = [{ initiatorUserId: userId }];
        }
        if (query.status) where.status = query.status as PeerLinkStatus;

        const [links, total] = await Promise.all([
            this.prisma.peerLink.findMany({
                where,
                include: PEER_LINK_INCLUDE,
                skip: (query.page - 1) * query.limit,
                take: query.limit,
                orderBy: { createdAt: 'desc' },
            }),
            this.prisma.peerLink.count({ where }),
        ]);

        const totalPages = Math.ceil(total / query.limit);
        return {
            data: links.map((l) => serializePeerLink(l, userId)),
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

    async getPeerLinkForUser(peerLinkId: string, userId: string) {
        const link = await this.prisma.peerLink.findUnique({
            where: { id: peerLinkId },
            include: {
                ...PEER_LINK_INCLUDE,
                settlements: {
                    orderBy: { createdAt: 'desc' },
                    include: {
                        recordedByUser: { select: { id: true, firstName: true, lastName: true } },
                    },
                },
            },
        });
        if (!link) throw new NotFoundError('Peer link');
        if (link.initiatorUserId !== userId && link.counterpartyUserId !== userId) {
            throw new AuthorizationError('You are not a party to this peer link');
        }
        return serializePeerLink(link, userId);
    }

    /** Books the counterparty can accept a pending link into. */
    async getAcceptableCashbooks(peerLinkId: string, userId: string) {
        const link = await this.prisma.peerLink.findUnique({ where: { id: peerLinkId } });
        if (!link) throw new NotFoundError('Peer link');
        if (link.counterpartyUserId !== userId) {
            throw new AuthorizationError('Only the counterparty can respond to this peer link');
        }
        if (link.status !== PeerLinkStatus.PENDING) {
            throw new AppError(`This peer link is already ${link.status.toLowerCase()}`, 400, 'INVALID_STATUS');
        }

        // Books the user can actually accept into — the same access the accept
        // check grants: workspace owner, org-wide role, or a CashbookMember row
        // whose role holds MANAGE_OBLIGATIONS. Filtering here keeps the picker
        // from offering a book that accept would then refuse.
        const workspaces = await this.prisma.workspace.findMany({
            where: { OR: [{ ownerId: userId }, { members: { some: { userId } } }] },
            select: { id: true, name: true, type: true, ownerId: true },
        });
        const workspaceIds = workspaces.map((w) => w.id);
        if (workspaceIds.length === 0) return { data: [] };

        const [books, memberships, wsMemberships] = await Promise.all([
            this.prisma.cashbook.findMany({
                where: {
                    workspaceId: { in: workspaceIds },
                    isActive: true,
                    currency: link.currency,
                    id: { not: link.initiatorCashbookId },
                },
                select: { id: true, name: true, currency: true, workspaceId: true },
                orderBy: { name: 'asc' },
            }),
            this.prisma.cashbookMember.findMany({
                where: { userId },
                select: { cashbookId: true, role: true },
            }),
            this.prisma.workspaceMember.findMany({
                where: { userId, workspaceId: { in: workspaceIds } },
                select: { workspaceId: true, role: true },
            }),
        ]);

        const bookRole = new Map(memberships.map((m) => [m.cashbookId, m.role as CashbookRole]));
        const wsRole = new Map(wsMemberships.map((m) => [m.workspaceId, m.role as WorkspaceRole]));

        const acceptable = books.filter((b) => {
            const ws = workspaces.find((w) => w.id === b.workspaceId)!;
            if (ws.ownerId === userId) return true;
            if (ACCEPT_BOOK_ROLES.has(wsRole.get(b.workspaceId)!)) return true;
            return ACCEPT_CASHBOOK_ROLES.has(bookRole.get(b.id)!);
        });

        const wsMap = new Map(workspaces.map((w) => [w.id, w]));
        return {
            data: acceptable.map((b) => ({
                ...b,
                workspaceName: wsMap.get(b.workspaceId)?.name ?? '',
                workspaceType: wsMap.get(b.workspaceId)?.type ?? null,
            })),
        };
    }

    // ─── Settlement decisions ────────────────────────────
    /**
     * The counterparty's answer to a recorded payment: confirm (optionally by
     * matching an entry they already recorded on their own side) or reject.
     *
     * Confirming never writes to anyone's book — the recorder's book already
     * carries the payment, and a matched entry means the decider's does too.
     * Matching links the two entries as the shared proof of that payment.
     */
    async decideSettlement(settlementId: string, userId: string, dto: SettlementDecisionDto) {
        const queued: Array<NotificationJobData & { workspaceId: string }> = [];

        const settlement = await withFinancialTransaction(this.prisma, async (tx) => {
            const existing = await tx.peerLinkSettlement.findUnique({
                where: { id: settlementId },
                include: {
                    peerLink: {
                        include: { obligations: { select: { id: true, cashbookId: true } } },
                    },
                    entry: { select: { id: true, cashbookId: true } },
                },
            }).then(async (s) => {
                if (!s) return s;
                // entry.workspaceId isn't a column; resolve via the cashbook.
                const entryWorkspace = await tx.cashbook.findUnique({
                    where: { id: s.entry.cashbookId },
                    select: { workspaceId: true },
                });
                return { ...s, entryWorkspaceId: entryWorkspace?.workspaceId ?? null };
            });
            if (!existing) throw new NotFoundError('Settlement');
            if (existing.recordedByUserId === userId) {
                throw new AuthorizationError('You recorded this payment; your counterparty decides');
            }
            const link = existing.peerLink;
            if (link.initiatorUserId !== userId && link.counterpartyUserId !== userId) {
                throw new AuthorizationError('You are not a party to this peer link');
            }
            if (existing.status !== 'PENDING') {
                throw new AppError(`This settlement is already ${existing.status.toLowerCase()}`, 400, 'INVALID_STATUS');
            }

            let matchedEntryId: string | null = null;

            if (dto.decision === 'CONFIRM' && dto.matchedEntryId) {
                const matched = await tx.entry.findUnique({ where: { id: dto.matchedEntryId } });
                if (!matched || matched.isDeleted) {
                    throw new NotFoundError('Entry');
                }
                // The matched entry must pay the decider's OWN mirrored
                // obligation — the other side of this loan from the recorder's.
                const deciderObligation = link.obligations.find(
                    (o) => o.id !== existing.obligationId,
                );
                if (!deciderObligation || matched.obligationId !== deciderObligation.id) {
                    throw new AppError('That entry is not a payment on your side of this loan', 400, 'INVALID_MATCH');
                }
                if (!matched.amount.equals(existing.amount)) {
                    throw new AppError(
                        `That entry's amount (${matched.amount.toString()}) does not match the payment (${existing.amount.toString()})`,
                        400,
                        'AMOUNT_MISMATCH',
                    );
                }
                matchedEntryId = matched.id;
            }

            // updateMany (not update) so the PENDING guard is part of the write
            // itself: two concurrent decisions cannot both land, last-write-wins
            // cannot flip a CONFIRMED settlement to REJECTED behind our check.
            const { count } = await tx.peerLinkSettlement.updateMany({
                where: { id: settlementId, status: 'PENDING' },
                data: {
                    status: dto.decision === 'CONFIRM' ? 'CONFIRMED' : 'REJECTED',
                    matchedEntryId,
                    respondedAt: new Date(),
                    responseReason: dto.reason || null,
                },
            });
            if (count !== 1) {
                throw new AppError('This settlement is no longer pending', 400, 'INVALID_STATUS');
            }
            const updated = await tx.peerLinkSettlement.findUniqueOrThrow({
                where: { id: settlementId },
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: existing.entryWorkspaceId,
                    action: dto.decision === 'CONFIRM'
                        ? AuditAction.PEER_LINK_SETTLEMENT_CONFIRMED
                        : AuditAction.PEER_LINK_SETTLEMENT_REJECTED,
                    resource: 'peer_link_settlement',
                    resourceId: settlementId,
                    details: {
                        peerLinkId: link.id,
                        amount: existing.amount.toString(),
                        matchedEntryId,
                        reason: dto.reason ?? null,
                    } as any,
                },
            });

            queued.push({
                type: NotificationType.PEER_LINK_SETTLEMENT_DECIDED,
                userId: existing.recordedByUserId,
                // The notification lands in the recorder's workspace, where
                // the recording entry was posted.
                workspaceId: existing.entryWorkspaceId ?? link.initiatorWorkspaceId,
                title: dto.decision === 'CONFIRM' ? 'Payment confirmed' : 'Payment rejected',
                body: dto.decision === 'CONFIRM'
                    ? `Your payment of ${existing.amount.toString()} on "${link.title}" was confirmed by your counterparty`
                    : `Your payment of ${existing.amount.toString()} on "${link.title}" was rejected${dto.reason ? `: ${dto.reason}` : ''}`,
                entityType: NotificationEntityType.PEER_LINK_SETTLEMENT,
                entityId: settlementId,
                groupKey: `peer-link-settlement:${settlementId}`,
            });

            return updated;
        });

        for (const n of queued) NotificationsService.dispatch(n);

        return settlement;
    }

    /**
     * Hook from EntriesService when an entry paying a peer-linked obligation is
     * created: open the settlement awaiting the counterparty.
     *
     * Static so the entries module can call it without a DI cycle, mirroring
     * InvoicingService.syncInvoiceFromObligation.
     */
    static async onPaymentApplied(
        tx: Prisma.TransactionClient,
        args: {
            obligation: { id: string; peerLinkId: string | null };
            entry: { id: string; amount: Decimal; entryDate: Date; createdById: string };
        },
    ): Promise<void> {
        if (!args.obligation.peerLinkId) return;

        const link = await tx.peerLink.findUnique({ where: { id: args.obligation.peerLinkId } });
        if (!link || link.status !== PeerLinkStatus.ACCEPTED) return;

        // One settlement per payment entry: a retried or duplicated request
        // replays onto the same row instead of stacking confirmation demands.
        // The unique on entryId makes the upsert race-free.
        await tx.peerLinkSettlement.upsert({
            where: { entryId: args.entry.id },
            create: {
                peerLinkId: link.id,
                entryId: args.entry.id,
                obligationId: args.obligation.id,
                recordedByUserId: args.entry.createdById,
                amount: args.entry.amount,
                entryDate: args.entry.entryDate,
            },
            update: {},
        });

        await tx.auditLog.create({
            data: {
                userId: args.entry.createdById,
                workspaceId: null,
                action: AuditAction.PEER_LINK_SETTLEMENT_CREATED,
                resource: 'peer_link_settlement',
                resourceId: args.entry.id,
                details: {
                    peerLinkId: link.id,
                    entryId: args.entry.id,
                    amount: args.entry.amount.toString(),
                } as any,
            },
        });

        // Notify whoever did NOT record this entry.
        const toCounterparty = args.entry.createdById === link.initiatorUserId;
        const counterpartyWorkspaceId = (toCounterparty
            ? link.counterpartyWorkspaceId
            : link.initiatorWorkspaceId);

        NotificationsService.dispatch({
            type: NotificationType.PEER_LINK_PAYMENT_RECORDED,
            userId: toCounterparty ? link.counterpartyUserId : link.initiatorUserId,
            workspaceId: counterpartyWorkspaceId ?? link.initiatorWorkspaceId,
            title: 'Payment recorded on your Peer Link',
            body: `A payment of ${args.entry.amount.toString()} was recorded on "${link.title}". Confirm it to keep your books matched.`,
            entityType: NotificationEntityType.PEER_LINK_SETTLEMENT,
            entityId: args.entry.id,
            groupKey: `peer-link-settlement:${args.entry.id}`,
        });
    }

    /**
     * Hook from EntriesService when an entry paying a peer-linked obligation is
     * reversed: the settlement it opened no longer stands, whether it was still
     * awaiting a decision or already confirmed.
     */
    static async onPaymentReversed(
        tx: Prisma.TransactionClient,
        args: { obligation: { peerLinkId: string | null }; entryId: string },
    ): Promise<void> {
        if (!args.obligation.peerLinkId) return;

        await tx.peerLinkSettlement.updateMany({
            where: { entryId: args.entryId, status: { in: ['PENDING', 'CONFIRMED'] } },
            data: { status: 'CANCELLED', respondedAt: new Date() },
        });
    }

    // ─── User lookup ─────────────────────────────────────
    /**
     * Exact-email user lookup for the peer link form. Returns the bare minimum
     * needed to address a proposal — never a search surface, and no existence
     * oracle beyond what addressing a proposal already requires.
     */
    async lookupUserByEmail(email: string) {
        const user = await this.prisma.user.findUnique({
            where: { email: email.toLowerCase() },
            select: { id: true, firstName: true, lastName: true, email: true, isActive: true },
        });
        if (!user || !user.isActive) {
            throw new AppError('No active user found with that email', 404, 'USER_NOT_FOUND');
        }
        return {
            id: user.id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
        };
    }

    // ─── Workspace-wide obligations (new page) ───────────
    /**
     * Every obligation across the workspace's books, for the new Obligations
     * page. Route-level membership is enforced by the guard; here the books are
     * narrowed to what this member can actually see — org-wide roles see every
     * book, everyone else only the books they hold a CashbookMember row for.
     */
    async getWorkspaceObligations(
        workspaceId: string,
        userId: string,
        workspaceRole: WorkspaceRole | null | undefined,
        query: {
            page: number; limit: number;
            status?: ObligationStatus | 'ACTIVE';
            type?: ObligationType;
            cashbookId?: string;
            search?: string;
        },
    ) {
        const where: Prisma.CashbookObligationWhereInput = {
            workspaceId,
            archivedAt: null,
        };

        // Org-wide access (owner/admin/GM/accountant) reaches every book;
        // sub-accountants and plain members see only their explicit grants.
        const orgWide = workspaceRole != null && ACCEPT_BOOK_ROLES.has(workspaceRole);
        if (!orgWide) {
            const memberBooks = await this.prisma.cashbookMember.findMany({
                where: { userId, cashbook: { workspaceId } },
                select: { cashbookId: true },
            });
            const bookIds = memberBooks.map((m) => m.cashbookId);
            if (bookIds.length === 0 || (query.cashbookId && !bookIds.includes(query.cashbookId))) {
                return {
                    data: [], pagination: {
                        page: query.page, limit: query.limit,
                        total: 0, totalPages: 0, hasNext: false, hasPrevious: false,
                    }
                };
            }
            where.cashbookId = query.cashbookId ?? { in: bookIds };
        } else if (query.cashbookId) {
            where.cashbookId = query.cashbookId;
        }

        if (query.status === 'ACTIVE') {
            where.status = { in: [ObligationStatus.OPEN, ObligationStatus.PARTIAL] };
        } else if (query.status) {
            where.status = query.status;
        }
        if (query.type) where.type = query.type;
        if (query.search) {
            where.OR = [
                { title: { contains: query.search, mode: 'insensitive' } },
                { description: { contains: query.search, mode: 'insensitive' } },
                { contact: { name: { contains: query.search, mode: 'insensitive' } } },
            ];
        }

        const [obligations, total] = await Promise.all([
            this.prisma.cashbookObligation.findMany({
                where,
                include: {
                    cashbook: { select: { id: true, name: true } },
                    contact: { select: { id: true, name: true } },
                    peerLink: { select: { id: true, status: true, direction: true } },
                    _count: { select: { entries: true } },
                },
                skip: (query.page - 1) * query.limit,
                take: query.limit,
                orderBy: { createdAt: 'desc' },
            }),
            this.prisma.cashbookObligation.count({ where }),
        ]);

        const totalPages = Math.ceil(total / query.limit);
        return {
            data: obligations,
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

    // ─── Internal helpers ─────────────────────────────────
    /**
     * May this user manage obligations in the given book? Mirrors the route
     * guard's logic: workspace owner, org-wide access, or an explicit
     * CashbookMember row whose role holds MANAGE_OBLIGATIONS.
     */
    private async assertCanManageObligationsIn(
        tx: Prisma.TransactionClient,
        cashbookId: string,
        userId: string,
    ) {
        const cashbook = await tx.cashbook.findUniqueOrThrow({
            where: { id: cashbookId },
            select: { workspaceId: true },
        });
        const workspace = await tx.workspace.findUniqueOrThrow({
            where: { id: cashbook.workspaceId },
            select: { ownerId: true, type: true },
        });

        if (workspace.ownerId === userId) return;

        // A personal workspace has no member rows at all; the owner check above
        // is the only way in.
        if (workspace.type === WorkspaceType.PERSONAL) {
            throw new AuthorizationError('You do not have access to this cashbook');
        }

        const membership = await tx.cashbookMember.findUnique({
            where: { cashbookId_userId: { cashbookId, userId } },
            select: { role: true },
        });

        if (membership) {
            if (ACCEPT_CASHBOOK_ROLES.has(membership.role as CashbookRole)) return;
            throw new AuthorizationError('You cannot manage obligations in this cashbook');
        }

        // Org-wide roles reach every book without a member row.
        const wsMembership = await tx.workspaceMember.findUnique({
            where: { workspaceId_userId: { workspaceId: cashbook.workspaceId, userId } },
            select: { role: true },
        });
        if (wsMembership && ACCEPT_BOOK_ROLES.has(wsMembership.role as WorkspaceRole)) {
            return;
        }

        throw new AuthorizationError('You do not have access to this cashbook');
    }

    /**
     * The contact standing for a platform user in a workspace, created on
     * first use. Idempotent via (workspaceId, userId), exactly like staff
     * contacts — two peer links accepted at once cannot split the balance
     * across two "Jane Doe" rows.
     */
    private async ensureUserContact(
        tx: Prisma.TransactionClient,
        workspaceId: string,
        userId: string,
    ) {
        const existing = await tx.contact.findUnique({
            where: { workspaceId_userId: { workspaceId, userId } },
        });
        if (existing) return existing;

        const user = await tx.user.findUniqueOrThrow({
            where: { id: userId },
            select: { firstName: true, lastName: true, email: true },
        });

        try {
            return await tx.contact.create({
                data: {
                    workspaceId,
                    userId,
                    type: ContactType.STAFF,
                    name: `${user.firstName} ${user.lastName}`.trim() || user.email,
                    email: user.email,
                },
            });
        } catch (error: any) {
            if (error?.code === 'P2002') {
                return tx.contact.findUniqueOrThrow({
                    where: { workspaceId_userId: { workspaceId, userId } },
                });
            }
            throw error;
        }
    }

    /** One mirrored obligation: the row, its audit log and its opening journal. */
    private async createMirroredObligation(
        tx: Prisma.TransactionClient,
        args: {
            workspaceId: string; cashbookId: string; currency: string; peerLinkId: string;
            type: ObligationType; title: string; description: string | null;
            principalAmount: Decimal; interestAmount: Decimal; interestRate: Decimal | null;
            totalAmount: Decimal; dueDate: Date | null; contactId: string; userId: string;
        },
    ) {
        const obligation = await tx.cashbookObligation.create({
            data: {
                workspaceId: args.workspaceId,
                cashbookId: args.cashbookId,
                peerLinkId: args.peerLinkId,
                type: args.type,
                title: args.title,
                description: args.description,
                totalAmount: args.totalAmount,
                principalAmount: args.principalAmount,
                interestAmount: args.interestAmount,
                interestRate: args.interestRate,
                outstandingAmount: args.totalAmount,
                status: ObligationStatus.OPEN,
                dueDate: args.dueDate,
                contactId: args.contactId,
            },
        });

        await tx.auditLog.create({
            data: {
                userId: args.userId,
                workspaceId: args.workspaceId,
                action: AuditAction.OBLIGATION_CREATED,
                resource: 'obligation',
                resourceId: obligation.id,
                details: {
                    type: args.type,
                    totalAmount: args.totalAmount.toString(),
                    principalAmount: args.principalAmount.toString(),
                    interestAmount: args.interestAmount.toString(),
                    interestRate: args.interestRate?.toString() ?? null,
                    title: args.title,
                    peerLinkId: args.peerLinkId,
                } as any,
            },
        });

        if (config.LEDGER_MODE !== 'off') {
            await this.postingService.post(
                tx,
                buildObligationJournal({
                    workspaceId: args.workspaceId,
                    cashbookId: args.cashbookId,
                    obligationId: obligation.id,
                    version: obligation.version,
                    type: args.type as 'RECEIVABLE' | 'PAYABLE',
                    totalAmount: args.totalAmount,
                    title: args.title,
                    entryDate: args.dueDate ?? new Date(),
                    currency: args.currency,
                    createdById: args.userId,
                    contactId: args.contactId,
                }),
                {
                    applyCaches: config.LEDGER_MODE === 'on',
                    onDuplicate: 'RETURN_EXISTING',
                },
            );
        }

        return obligation;
    }
}

/**
 * Client shape. Each viewer gets the link from their own perspective:
 * counterparty identity, which book is theirs, which obligation is theirs,
 * and LENDING/BORROWING flipped to the viewer's point of view.
 */
function serializePeerLink(link: any, viewerUserId: string) {
    const isInitiator = link.initiatorUserId === viewerUserId;
    const myBookId = isInitiator ? link.initiatorCashbookId : link.counterpartyCashbookId;
    const theirBookId = isInitiator ? link.counterpartyCashbookId : link.initiatorCashbookId;
    const myObligation = (link.obligations ?? []).find((o: any) => o.cashbookId === myBookId);
    const theirObligation = (link.obligations ?? []).find((o: any) => o.cashbookId === theirBookId);

    const toStr = (d: any) => (d === null || d === undefined
        ? null
        : typeof d.toString === 'function' ? d.toString() : String(d));

    return {
        id: link.id,
        status: link.status,
        direction: link.direction,
        viewerIsInitiator: isInitiator,
        /** LENDING/BORROWING from the VIEWER's perspective. */
        viewerDirection: isInitiator
            ? link.direction
            : (link.direction === PeerLinkDirection.LENDING ? 'BORROWING' : 'LENDING'),
        counterparty: isInitiator ? link.counterpartyUser : link.initiatorUser,
        myBook: isInitiator ? link.initiatorCashbook : link.counterpartyCashbook,
        theirBook: isInitiator ? link.counterpartyCashbook : link.initiatorCashbook,
        myObligationId: myObligation?.id ?? null,
        theirObligationId: theirObligation?.id ?? null,
        title: link.title,
        description: link.description ?? null,
        currency: link.currency,
        principalAmount: toStr(link.principalAmount),
        interestAmount: toStr(link.interestAmount),
        interestRate: toStr(link.interestRate),
        totalAmount: toStr(link.totalAmount),
        dueDate: link.dueDate ? new Date(link.dueDate).toISOString() : null,
        declinedReason: link.declinedReason ?? null,
        createdAt: new Date(link.createdAt).toISOString(),
        respondedAt: link.respondedAt ? new Date(link.respondedAt).toISOString() : null,
        obligations: link.obligations ?? [],
        settlements: link.settlements ?? undefined,
    };
}

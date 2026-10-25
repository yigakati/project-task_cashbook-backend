import { inject, injectable } from 'tsyringe';
import { Prisma, PrismaClient } from '@prisma/client';
import { EntriesService } from '../entries/entries.service';
import { AppError, AuthorizationError, ConflictError, NotFoundError } from '../../core/errors/AppError';
import { CashbookRole, WorkspaceRole } from '../../core/types';
import { CashbookPermission, hasPermission } from '../../core/types/permissions';
import { WorkspacePermission, hasWorkspacePermission } from '../../core/types/workspace-permissions';
import { acquireLocks } from '../../core/db/locks';
import { withFinancialTransaction } from '../../core/db/transaction';
import { entryRecipient } from './shared-entries.lifecycle';
import { AcceptSharedEntryDto, SharedEntryQueryDto } from './shared-entries.dto';

const bookInclude = {
    workspace: { include: { members: true } },
    members: true,
} satisfies Prisma.CashbookInclude;
type DestinationBook = Prisma.CashbookGetPayload<{ include: typeof bookInclude }>;

/** Explicit book roles take precedence over implicit organisation access, as
 * on the normal entry route. Personal workspaces remain owner-only. */
function canPost(book: DestinationBook, userId: string, permission = CashbookPermission.CREATE_ENTRY) {
    const ws = book.workspace;
    if (!book.isActive || book.archivedAt || !ws.isActive) return false;
    if (ws.type === 'PERSONAL') return ws.ownerId === userId;
    const role = ws.ownerId === userId ? WorkspaceRole.OWNER
        : ws.members.find(m => m.userId === userId)?.role as WorkspaceRole | undefined;
    if (!role || !hasWorkspacePermission(role, WorkspacePermission.VIEW_WALLETS)) return false;
    const bookRole = book.members.find(m => m.userId === userId)?.role as CashbookRole | undefined;
    return bookRole ? hasPermission(bookRole, permission)
        : hasWorkspacePermission(role, WorkspacePermission.ACCESS_ALL_CASHBOOKS);
}

function canView(book: DestinationBook, userId: string) {
    const ws = book.workspace;
    if (!book.isActive || !ws.isActive) return false;
    if (ws.type === 'PERSONAL') return ws.ownerId === userId;
    const role = ws.ownerId === userId ? WorkspaceRole.OWNER
        : ws.members.find(m => m.userId === userId)?.role as WorkspaceRole | undefined;
    if (!role) return false;
    const bookRole = book.members.find(m => m.userId === userId)?.role as CashbookRole | undefined;
    return bookRole ? hasPermission(bookRole, CashbookPermission.VIEW_ENTRIES)
        : hasWorkspacePermission(role, WorkspacePermission.ACCESS_ALL_CASHBOOKS);
}

const sourceSelect = {
    cashbookId: true, status: true, isDeleted: true, version: true, contactId: true,
    amount: true, type: true, description: true, entryDate: true,
    createdBy: { select: { isActive: true } },
    cashbook: { select: { workspaceId: true, currency: true, isActive: true, workspace: { select: { isActive: true } } } },
} satisfies Prisma.EntrySelect;

@injectable()
export class SharedEntriesService {
    constructor(
        @inject('PrismaClient') private prisma: PrismaClient,
        private entries: EntriesService,
    ) {}

    async list(userId: string, query: SharedEntryQueryDto) {
        const where = { recipientUserId: userId, ...(query.status ? { status: query.status } : {}) };
        const [rows, total, pendingCount] = await Promise.all([
            this.prisma.sharedEntry.findMany({
                where, skip: (query.page - 1) * query.limit, take: query.limit,
                orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
                include: {
                    sourceEntry: { select: sourceSelect },
                    acceptedEntry: { select: { id: true, cashbookId: true, status: true, cashbook: { include: bookInclude } } },
                },
            }),
            this.prisma.sharedEntry.count({ where }),
            this.prisma.sharedEntry.count({ where: { recipientUserId: userId, status: 'PENDING' } }),
        ]);
        return {
            data: rows.map(row => {
                const { sourceEntry: source, acceptedEntry: accepted, recipientUserId: _recipient, sourceContactId: _contact,
                    sourceWorkspaceId: _workspace, ...safe } = row;
                const sourceState = !source ? 'UNAVAILABLE'
                    : source.status === 'REVERSED' || source.isDeleted ? 'REVERSED'
                    : !source.cashbook.isActive || !source.cashbook.workspace.isActive ? 'UNAVAILABLE'
                    : source.contactId !== row.sourceContactId || !source.amount.equals(row.amount)
                        || source.type === row.type || source.description !== row.description
                        || source.entryDate.getTime() !== row.entryDate.getTime()
                        || source.cashbook.currency !== row.currency ? 'CHANGED' : 'UNCHANGED';
                return { ...safe, sourceState, acceptedEntry: accepted && canView(accepted.cashbook, userId) ? {
                    id: accepted.id, status: accepted.status, cashbookId: accepted.cashbookId,
                    cashbookName: accepted.cashbook.name, workspaceId: accepted.cashbook.workspaceId,
                    workspaceName: accepted.cashbook.workspace.name,
                } : null };
            }),
            pendingCount,
            pagination: { page: query.page, limit: query.limit, total, totalPages: Math.ceil(total / query.limit) },
        };
    }

    async count(userId: string) {
        return { pendingCount: await this.prisma.sharedEntry.count({ where: { recipientUserId: userId, status: 'PENDING' } }) };
    }

    private async owned(tx: Pick<Prisma.TransactionClient, 'sharedEntry'>, id: string, userId: string) {
        const share = await tx.sharedEntry.findFirst({ where: { id, recipientUserId: userId } });
        if (!share) throw new NotFoundError('Shared entry');
        return share;
    }

    async destinations(id: string, userId: string) {
        const share = await this.owned(this.prisma, id, userId);
        if (share.status !== 'PENDING') return [];
        const books = await this.prisma.cashbook.findMany({
            where: {
                isActive: true, archivedAt: null, currency: share.currency,
                workspaceId: { not: share.sourceWorkspaceId },
                workspace: { isActive: true, OR: [{ ownerId: userId }, { members: { some: { userId } } }] },
            },
            include: bookInclude, orderBy: { name: 'asc' },
        });
        return books.filter(b => canPost(b, userId)).map(b => ({
            id: b.id, name: b.name, currency: b.currency, allowBackdate: b.allowBackdate,
            workspaceId: b.workspaceId, workspaceName: b.workspace.name, workspaceType: b.workspace.type,
        }));
    }

    private async destination(tx: Prisma.TransactionClient, share: { currency: string; sourceWorkspaceId: string }, bookId: string, userId: string) {
        const book = await tx.cashbook.findUnique({ where: { id: bookId }, include: bookInclude });
        if (!book || !canPost(book, userId)) throw new AuthorizationError('You cannot record entries in this book');
        if (book.workspaceId === share.sourceWorkspaceId) throw new AppError('Choose a workspace other than the sender’s workspace', 400, 'SAME_WORKSPACE');
        if (book.currency !== share.currency) throw new AppError('Choose a book with the same currency', 400, 'CURRENCY_MISMATCH');
        return book;
    }

    async options(id: string, userId: string, cashbookId: string) {
        const share = await this.owned(this.prisma, id, userId);
        const book = await this.destination(this.prisma, share, cashbookId, userId);
        const [accounts, categories, paymentModes, obligations] = await Promise.all([
            this.prisma.account.findMany({
                where: { workspaceId: book.workspaceId, currency: share.currency, archivedAt: null },
                select: { id: true, name: true, currency: true }, orderBy: { name: 'asc' },
            }),
            this.prisma.category.findMany({ where: { workspaceId: book.workspaceId, isActive: true }, select: { id: true, name: true }, orderBy: { name: 'asc' } }),
            this.prisma.paymentMode.findMany({ where: { workspaceId: book.workspaceId, isActive: true }, select: { id: true, name: true }, orderBy: { name: 'asc' } }),
            canPost(book, userId, CashbookPermission.MANAGE_OBLIGATIONS)
                ? this.prisma.cashbookObligation.findMany({
                    where: {
                        cashbookId, archivedAt: null, peerLinkId: null,
                        type: share.type === 'INCOME' ? 'RECEIVABLE' : 'PAYABLE',
                        status: { in: ['OPEN', 'PARTIAL'] }, outstandingAmount: { gte: share.amount },
                    },
                    select: { id: true, title: true, outstandingAmount: true }, orderBy: { createdAt: 'desc' },
                }) : [],
        ]);
        return { accounts, categories, paymentModes, obligations };
    }

    async accept(id: string, userId: string, dto: AcceptSharedEntryDto) {
        return withFinancialTransaction(this.prisma, async tx => {
            const probe = await this.owned(tx, id, userId);
            if (probe.status === 'ACCEPTED') return { entryId: probe.acceptedEntryId, alreadyAccepted: true };
            if (!probe.sourceEntryId) throw new ConflictError('The source entry is no longer available');
            // Fail before locking any destination resources the caller cannot
            // use. Revalidate under the locks below for revocation/archive races.
            const destinationProbe = await this.destination(tx, probe, dto.cashbookId, userId);
            const accountProbe = await tx.account.findUnique({ where: { id: dto.accountId }, select: { workspaceId: true } });
            if (!accountProbe || accountProbe.workspaceId !== destinationProbe.workspaceId) {
                throw new AppError('Invalid account selected', 400, 'INVALID_ACCOUNT');
            }
            const sourceProbe = await tx.entry.findUniqueOrThrow({ where: { id: probe.sourceEntryId }, select: { cashbookId: true } });
            // Source mutations lock their book first too. Hold BOTH books in
            // sorted order so accepting and editing/reversing cannot interleave.
            await acquireLocks(tx, [
                { target: 'CASHBOOK', ids: [sourceProbe.cashbookId, dto.cashbookId] },
                { target: 'WALLET_ACCOUNT', ids: [dto.accountId] },
                { target: 'OBLIGATION', ids: [dto.obligationId] },
                { target: 'ENTRY', ids: [probe.sourceEntryId] },
            ]);
            await tx.$queryRaw`SELECT id FROM shared_entries WHERE id = ${id}::uuid FOR UPDATE`;
            const share = await this.owned(tx, id, userId);
            // Durable idempotency, including retries with a fresh HTTP key.
            if (share.status === 'ACCEPTED') return { entryId: share.acceptedEntryId, alreadyAccepted: true };
            if (share.status !== 'PENDING') throw new ConflictError('This shared entry has already been handled');
            if (!share.sourceEntryId) throw new ConflictError('The source entry is no longer available');
            const source = await tx.entry.findUniqueOrThrow({ where: { id: share.sourceEntryId }, select: sourceSelect });
            if (source.cashbookId !== sourceProbe.cashbookId || source.version !== dto.expectedVersion
                || share.sourceVersion !== dto.expectedVersion) throw new ConflictError('The source entry changed. Refresh and review it again.');
            if (source.status !== 'POSTED' || source.isDeleted || !source.createdBy.isActive || !source.cashbook.isActive || !source.cashbook.workspace.isActive
                || source.contactId !== share.sourceContactId
                || await entryRecipient(tx, share.sourceContactId, share.sourceWorkspaceId) !== userId) {
                throw new ConflictError('The source entry or contact connection is no longer available');
            }
            const book = await this.destination(tx, share, dto.cashbookId, userId);
            if (dto.obligationId) {
                if (!canPost(book, userId, CashbookPermission.MANAGE_OBLIGATIONS)) throw new AuthorizationError('You cannot settle obligations in this book');
                const obligation = await tx.cashbookObligation.findUnique({ where: { id: dto.obligationId }, select: { peerLinkId: true } });
                if (obligation?.peerLinkId) throw new AppError('Use the linked loan settlement flow for this obligation', 400, 'PEER_SETTLEMENT_REQUIRED');
            }
            // Reuse a reciprocal contact only if it already exists in the
            // chosen workspace. Never copy another tenant's contact identifier.
            const contact = await tx.contact.findFirst({
                where: { workspaceId: book.workspaceId, linkedWorkspaceId: share.sourceWorkspaceId, isActive: true },
                select: { id: true },
            });
            const entry = await this.entries.createEntryWithin(tx, book.id, userId, {
                type: share.type, amount: share.amount.toString(), description: share.description,
                entryDate: dto.entryDate || share.entryDate.toISOString(), accountId: dto.accountId,
                categoryId: dto.categoryId, paymentModeId: dto.paymentModeId,
                chargeAmount: dto.chargeAmount, obligationId: dto.obligationId, contactId: contact?.id,
            });
            await tx.sharedEntry.update({
                where: { id }, data: { status: 'ACCEPTED', acceptedEntryId: entry.id, respondedAt: new Date() },
            });
            await tx.entryAudit.create({
                data: { entryId: entry.id, userId, action: 'SHARED_ENTRY_ACCEPTED', newValues: {
                    sharedEntryId: id, sourceEntryId: share.sourceEntryId, sourceVersion: share.sourceVersion,
                    senderName: share.senderName, originalEntryDate: share.entryDate.toISOString(),
                } },
            });
            return { entryId: entry.id, alreadyAccepted: false };
        });
    }

    async decline(id: string, userId: string, reason?: string) {
        await this.owned(this.prisma, id, userId);
        const result = await this.prisma.sharedEntry.updateMany({
            where: { id, recipientUserId: userId, status: 'PENDING' },
            data: { status: 'DECLINED', respondedAt: new Date(), responseReason: reason || null },
        });
        if (!result.count) {
            const share = await this.owned(this.prisma, id, userId);
            if (share.status !== 'DECLINED') throw new ConflictError('This shared entry has already been handled');
        }
        return { id, status: 'DECLINED' };
    }
}

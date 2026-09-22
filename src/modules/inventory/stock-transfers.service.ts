import { injectable, inject } from 'tsyringe';
import {
    Prisma, PrismaClient, StockTransferStatus, InventoryTransactionType,
    InventoryReferenceType, NotificationType, NotificationEntityType, WorkspaceType,
} from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import { assertCashbookWritable } from '../cashbooks/cashbook-state';
import { NotFoundError, AppError, AuthorizationError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';
import { withFinancialTransaction } from '../../core/db/transaction';
import { NotificationsService } from '../notifications/notifications.service';
import { InventoryService } from './inventory.service';
import {
    CreateStockRequestDto, RespondStockRequestDto,
    StockTransferQueryDto, RecordTransferEntryDto,
} from './agreements.dto';

const TRANSFER_INCLUDE = {
    senderUser: { select: { id: true, email: true, firstName: true, lastName: true } },
    recipientUser: { select: { id: true, email: true, firstName: true, lastName: true } },
    senderItem: { select: { id: true, name: true, unit: true, sku: true, currency: true, category: true } },
    senderWorkspace: { select: { id: true, name: true } },
    recipientWorkspace: { select: { id: true, name: true } },
    recipientItem: { select: { id: true, name: true, unit: true } },
    expenseEntry: { select: { id: true } },
    incomeEntry: { select: { id: true } },
} satisfies Prisma.StockTransferInclude;

/**
 * Cross-workspace stock requests — one platform user asking another for
 * stock, with the app as the shared proof of the whole exchange.
 *
 * REQUEST-DRIVEN, mirroring how supply actually happens — and every stage
 * is tied to the workspace that owns it:
 *
 *   1. REQUEST    Made from an ITEM's page in the requester's workspace:
 *                 the request names that item (the goods land back into
 *                 it), so the origin workspace is fixed at creation. The
 *                 VENDOR sees it in their personal workspace only — the
 *                 inbox of requests sent in to them. Nothing moves.
 *   2. SEND       The vendor accepts, naming which of THEIR workspaces
 *                 (and which item) fulfils it. From here the request
 *                 belongs to that workspace on the vendor's side — not
 *                 even their personal workspace shows it anymore. The
 *                 units leave at the vendor's current weighted average.
 *   3. RECEIVE    The requester confirms the goods have arrived. No
 *                 choices: the request already knows its item and
 *                 workspace. TRANSFER_IN posts at exactly the per-unit
 *                 value that left the vendor — both books agree.
 *
 * Column names predate the rework: "sender" = the VENDOR (stock-out),
 * "recipient" = the REQUESTER (stock-in).
 */
@injectable()
export class StockTransfersService {
    constructor(
        @inject('PrismaClient') private prisma: PrismaClient,
        private inventoryService: InventoryService,
    ) { }

    /**
     * The workspace a notification to this user belongs to when the thing
     * it reports is not tied to any of their workspaces — their personal
     * workspace. Notifications are listed per workspace, so targeting the
     * other party's workspace would hide the notification entirely.
     */
    private async personalWorkspaceId(userId: string): Promise<string> {
        const personal = await this.prisma.workspace.findFirst({
            where: { ownerId: userId, type: WorkspaceType.PERSONAL, isActive: true },
            select: { id: true },
            orderBy: { createdAt: 'asc' },
        });
        if (personal) return personal.id;
        const fallback = await this.prisma.workspace.findFirst({
            where: { ownerId: userId, isActive: true },
            select: { id: true },
            orderBy: { createdAt: 'asc' },
        });
        return fallback?.id ?? '';
    }

    // ─── 1. Request (requester) ─────────────────────────
    /**
     * Ask a vendor for stock, from an item's page. The item fixes the
     * origin workspace (its own) and the destination the goods will land
     * back into; the vendor is addressed by a contact (their linked
     * account, or the contact's email) or a raw email. Nothing moves: the
     * request is a question, not a movement.
     */
    async createRequest(requesterWorkspaceId: string, userId: string, dto: CreateStockRequestDto) {
        const requesterWorkspace = await this.prisma.workspace.findUnique({
            where: { id: requesterWorkspaceId },
        });
        if (!requesterWorkspace || !requesterWorkspace.isActive) {
            throw new NotFoundError('Workspace');
        }

        const qty = Math.round(dto.quantity);
        if (qty <= 0) {
            throw new AppError('Quantity must be at least 1', 400, 'INVALID_QUANTITY');
        }

        // The item being stocked — it must be the requester's own, in the
        // workspace the request is made from.
        const item = await this.prisma.inventoryItem.findFirst({
            where: { id: dto.itemId, workspaceId: requesterWorkspaceId, isActive: true },
        });
        if (!item) throw new NotFoundError('Inventory item');

        // Resolve the vendor: preferred by contactId (linked account, then
        // the contact's recorded email), falling back to a raw email.
        let vendor: { id: string; isActive: boolean } | null = null;
        if (dto.contactId) {
            const contact = await this.prisma.contact.findFirst({
                where: { id: dto.contactId, workspaceId: requesterWorkspaceId, isActive: true },
                select: { userId: true, email: true, name: true },
            });
            if (!contact) throw new NotFoundError('Contact');
            if (contact.userId) {
                vendor = await this.prisma.user.findUnique({
                    where: { id: contact.userId },
                    select: { id: true, isActive: true },
                });
            } else if (contact.email) {
                vendor = await this.prisma.user.findUnique({
                    where: { email: contact.email.toLowerCase() },
                    select: { id: true, isActive: true },
                });
            }
            if (!vendor) {
                throw new AppError(
                    `Contact "${contact.name}" does not have an account on the platform — a stock request needs a vendor who can accept it`,
                    400,
                    'CONTACT_HAS_NO_ACCOUNT',
                );
            }
        } else {
            vendor = await this.prisma.user.findUnique({
                where: { email: dto.vendorEmail!.toLowerCase() },
                select: { id: true, isActive: true },
            });
        }
        if (!vendor || !vendor.isActive) {
            throw new AppError('No active user found with that email', 404, 'USER_NOT_FOUND');
        }
        if (vendor.id === userId) {
            throw new AppError('You cannot request stock from yourself', 400, 'SELF_REQUEST');
        }

        const request = await this.prisma.$transaction(async (tx) => {
            const created = await tx.stockTransfer.create({
                data: {
                    status: StockTransferStatus.PENDING,
                    senderUserId: vendor!.id,
                    quantity: qty,
                    proposedUnitCost: new Decimal(0),
                    recipientUserId: userId,
                    // Tied to the origin workspace and its item from the
                    // start — the vendor's workspace/item only exist once
                    // they send.
                    recipientWorkspaceId: requesterWorkspaceId,
                    recipientItemId: item.id,
                    notes: dto.notes || null,
                },
            });
            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: requesterWorkspaceId,
                    action: AuditAction.STOCK_TRANSFER_CREATED,
                    resource: 'stock_transfer',
                    resourceId: created.id,
                    details: {
                        request: true,
                        itemId: item.id,
                        itemName: item.name,
                        quantity: qty,
                        vendorUserId: vendor!.id,
                    } as any,
                },
            });
            return created;
        });

        // The vendor tracks unanswered requests in their personal workspace.
        const vendorInboxId = await this.personalWorkspaceId(vendor.id);
        NotificationsService.dispatch({
            type: NotificationType.STOCK_TRANSFER_RECEIVED,
            userId: vendor.id,
            workspaceId: vendorInboxId,
            title: 'Stock request',
            body: `Someone is asking you for ${qty} × ${item.name} — accept and send when you release the stock`,
            entityType: NotificationEntityType.STOCK_TRANSFER,
            entityId: request.id,
            groupKey: `stock-transfer:${request.id}`,
        });

        return this.getForUser(request.id, userId);
    }

    // ─── 2. Send (vendor) ────────────────────────────────
    /**
     * The vendor accepts and releases the stock: they name which of THEIR
     * items fulfils the request, and the units leave that workspace at
     * their current weighted average. From here the request belongs to the
     * sending workspace on the vendor's side — not even their personal
     * workspace shows it anymore. The requester holds a "confirm receipt"
     * until the goods arrive.
     */
    async send(transferId: string, vendorUserId: string, dto: RespondStockRequestDto) {
        const transfer = await withFinancialTransaction(this.prisma, async (tx) => {
            const pending = await tx.stockTransfer.findUnique({ where: { id: transferId } });
            if (!pending) throw new NotFoundError('Stock request');
            if (pending.senderUserId !== vendorUserId) {
                throw new AuthorizationError('Only the vendor can send this stock');
            }
            if (pending.status !== StockTransferStatus.PENDING) {
                throw new AppError(`This request is already ${pending.status.toLowerCase()}`, 400, 'INVALID_STATUS');
            }
            if (!pending.recipientItemId || !pending.recipientWorkspaceId) {
                throw new AppError('This request is missing its target item — ask the requester to send it again', 400, 'INVALID_STATE');
            }

            const requestedItem = await tx.inventoryItem.findUnique({
                where: { id: pending.recipientItemId },
                select: { name: true, currency: true },
            });
            if (!requestedItem) throw new NotFoundError('Requested inventory item');

            const vendorWorkspaceId = dto.senderWorkspaceId;
            const workspace = await tx.workspace.findUnique({ where: { id: vendorWorkspaceId } });
            if (!workspace || !workspace.isActive) throw new NotFoundError('Workspace');
            if (workspace.ownerId !== vendorUserId) {
                const membership = await tx.workspaceMember.findUnique({
                    where: { workspaceId_userId: { workspaceId: vendorWorkspaceId, userId: vendorUserId } },
                });
                if (!membership || !['OWNER', 'ADMIN'].includes(membership.role)) {
                    throw new AuthorizationError('You can only send stock from a workspace you own or administer');
                }
            }

            const item = await tx.inventoryItem.findUnique({
                where: { id: dto.senderItemId },
                include: { stock: true },
            });
            if (!item || item.workspaceId !== vendorWorkspaceId) {
                throw new NotFoundError('Inventory item');
            }
            if (item.currency !== requestedItem.currency) {
                throw new AppError(
                    `That item's currency (${item.currency}) does not match the requested goods (${requestedItem.currency})`,
                    400,
                    'CURRENCY_MISMATCH',
                );
            }

            const available = (item.stock?.quantityOnHand ?? 0) - (item.stock?.quantityReserved ?? 0);
            if (available < pending.quantity) {
                throw new AppError(
                    `Insufficient stock. Available: ${available}, requested: ${pending.quantity}`,
                    400,
                    'INSUFFICIENT_STOCK',
                );
            }

            // Stock leaves the vendor — real COGS resolution (lots/WAC),
            // provenance pointing at this request.
            const outTx = await this.inventoryService.processStockOut(
                vendorWorkspaceId,
                item.id,
                InventoryTransactionType.TRANSFER_OUT,
                pending.quantity,
                vendorUserId,
                InventoryReferenceType.STOCK_TRANSFER,
                transferId,
                `Stock sent for request ${transferId.slice(0, 8)}`,
                tx,
            );

            // PENDING-guarded transition, with the real vendor fields.
            const { count } = await tx.stockTransfer.updateMany({
                where: { id: transferId, status: StockTransferStatus.PENDING },
                data: {
                    status: StockTransferStatus.SENT,
                    senderWorkspaceId: vendorWorkspaceId,
                    senderItemId: item.id,
                    proposedUnitCost: outTx.unitCost,
                    respondedAt: new Date(),
                    sentAt: new Date(),
                },
            });
            if (count !== 1) {
                throw new AppError('This request is no longer pending', 400, 'INVALID_STATUS');
            }

            await tx.auditLog.create({
                data: {
                    userId: vendorUserId,
                    workspaceId: vendorWorkspaceId,
                    action: AuditAction.STOCK_TRANSFER_ACCEPTED,
                    resource: 'stock_transfer',
                    resourceId: transferId,
                    details: {
                        itemId: item.id,
                        quantity: pending.quantity,
                        unitCost: outTx.unitCost.toString(),
                    } as any,
                },
            });

            return tx.stockTransfer.findUniqueOrThrow({ where: { id: transferId } });
        });

        // The requester tracks the request in the workspace it came from.
        NotificationsService.dispatch({
            type: NotificationType.STOCK_TRANSFER_DECIDED,
            userId: transfer.recipientUserId!,
            workspaceId: transfer.recipientWorkspaceId!,
            title: 'Stock on its way',
            body: `Your requested stock has been released by the vendor — confirm receipt once it reaches you`,
            entityType: NotificationEntityType.STOCK_TRANSFER,
            entityId: transfer.id,
            groupKey: `stock-transfer:${transfer.id}:sent`,
        });

        return transfer;
    }

    // ─── 3. Receive (requester) ──────────────────────────
    /**
     * The goods have arrived: the requester confirms receipt. There is
     * nothing to choose — the request was made from a specific item in a
     * specific workspace, and that is where the stock lands. TRANSFER_IN
     * posts at exactly the per-unit value that left the vendor — the two
     * books can never disagree.
     */
    async receive(transferId: string, requesterUserId: string) {
        const transfer = await withFinancialTransaction(this.prisma, async (tx) => {
            const sent = await tx.stockTransfer.findUnique({ where: { id: transferId } });
            if (!sent) throw new NotFoundError('Stock request');
            if (sent.recipientUserId !== requesterUserId) {
                throw new AuthorizationError('Only the requester can confirm receipt');
            }
            if (sent.status !== StockTransferStatus.SENT) {
                throw new AppError(`This request is ${sent.status.toLowerCase()} — receipt can only be confirmed after the vendor sends`, 400, 'INVALID_STATUS');
            }
            if (!sent.senderWorkspaceId || !sent.senderItemId || !sent.recipientWorkspaceId || !sent.recipientItemId) {
                throw new AppError('This request is missing its movement details', 400, 'INVALID_STATE');
            }

            const target = await tx.inventoryItem.findUnique({
                where: { id: sent.recipientItemId },
            });
            if (!target || target.workspaceId !== sent.recipientWorkspaceId || !target.isActive) {
                throw new NotFoundError('Receiving inventory item');
            }

            // Stock arrives at the same per-unit value that left the vendor.
            await this.inventoryService.processStockIn(
                sent.recipientWorkspaceId,
                sent.recipientItemId,
                InventoryTransactionType.TRANSFER_IN,
                sent.quantity,
                sent.proposedUnitCost,
                requesterUserId,
                InventoryReferenceType.STOCK_TRANSFER,
                transferId,
                `Stock received for request ${transferId.slice(0, 8)}`,
                tx,
            );

            // SENT-guarded transition.
            const { count } = await tx.stockTransfer.updateMany({
                where: { id: transferId, status: StockTransferStatus.SENT },
                data: {
                    status: StockTransferStatus.COMPLETED,
                    receivedAt: new Date(),
                },
            });
            if (count !== 1) {
                throw new AppError('This request is no longer awaiting receipt', 400, 'INVALID_STATUS');
            }

            await tx.auditLog.create({
                data: {
                    userId: requesterUserId,
                    workspaceId: sent.recipientWorkspaceId,
                    action: AuditAction.STOCK_TRANSFER_ACCEPTED,
                    resource: 'stock_transfer',
                    resourceId: transferId,
                    details: {
                        received: true,
                        recipientItemId: sent.recipientItemId,
                        quantity: sent.quantity,
                        unitCost: sent.proposedUnitCost.toString(),
                    } as any,
                },
            });

            return tx.stockTransfer.findUniqueOrThrow({ where: { id: transferId } });
        });

        // The vendor tracks the sent request in the workspace that sent it.
        NotificationsService.dispatch({
            type: NotificationType.STOCK_TRANSFER_DECIDED,
            userId: transfer.senderUserId,
            workspaceId: transfer.senderWorkspaceId!,
            title: 'Stock received',
            body: `The stock you sent has been confirmed received — the exchange is complete`,
            entityType: NotificationEntityType.STOCK_TRANSFER,
            entityId: transfer.id,
            groupKey: `stock-transfer:${transfer.id}:received`,
        });

        return transfer;
    }

    // ─── Decline (vendor) / Cancel (requester) ────────────
    async decline(transferId: string, vendorUserId: string, reason?: string) {
        const transfer = await this.prisma.stockTransfer.findUnique({ where: { id: transferId } });
        if (!transfer) throw new NotFoundError('Stock request');
        if (transfer.senderUserId !== vendorUserId) {
            throw new AuthorizationError('Only the vendor can decline this request');
        }
        if (transfer.status !== StockTransferStatus.PENDING) {
            throw new AppError('Only pending requests can be declined. Sent stock is received — or reversed from the movement history.', 400, 'INVALID_STATUS');
        }

        const { count } = await this.prisma.$transaction(async (tx) => {
            const res = await tx.stockTransfer.updateMany({
                where: { id: transferId, status: StockTransferStatus.PENDING },
                data: { status: StockTransferStatus.DECLINED, respondedAt: new Date() },
            });
            if (res.count === 1) {
                await tx.auditLog.create({
                    data: {
                        userId: vendorUserId,
                        workspaceId: null,
                        action: AuditAction.STOCK_TRANSFER_DECLINED,
                        resource: 'stock_transfer',
                        resourceId: transferId,
                        details: { reason: reason ?? null } as any,
                    },
                });
            }
            return res;
        });
        if (count !== 1) {
            throw new AppError('This request is no longer pending', 400, 'INVALID_STATUS');
        }

        // The requester tracks their request in the workspace it came from.
        NotificationsService.dispatch({
            type: NotificationType.STOCK_TRANSFER_DECIDED,
            userId: transfer.recipientUserId!,
            workspaceId: transfer.recipientWorkspaceId!,
            title: 'Stock request declined',
            body: `Your stock request was declined${reason ? `: ${reason}` : ''}`,
            entityType: NotificationEntityType.STOCK_TRANSFER,
            entityId: transferId,
            groupKey: `stock-transfer:${transferId}:decided`,
        });

        return this.prisma.stockTransfer.findUniqueOrThrow({ where: { id: transferId } });
    }

    async cancel(transferId: string, requesterUserId: string, reason?: string) {
        const transfer = await this.prisma.stockTransfer.findUnique({ where: { id: transferId } });
        if (!transfer) throw new NotFoundError('Stock request');
        if (transfer.recipientUserId !== requesterUserId) {
            throw new AuthorizationError('Only the requester can cancel this request');
        }
        if (transfer.status === StockTransferStatus.SENT) {
            throw new AppError('The stock has already been released — receive it, or coordinate a return with the vendor', 400, 'INVALID_STATUS');
        }
        if (transfer.status !== StockTransferStatus.PENDING) {
            throw new AppError('Only pending requests can be cancelled', 400, 'INVALID_STATUS');
        }

        const { count } = await this.prisma.$transaction(async (tx) => {
            const res = await tx.stockTransfer.updateMany({
                where: { id: transferId, status: StockTransferStatus.PENDING },
                data: { status: StockTransferStatus.CANCELLED, respondedAt: new Date() },
            });
            if (res.count === 1) {
                await tx.auditLog.create({
                    data: {
                        userId: requesterUserId,
                        workspaceId: null,
                        action: AuditAction.STOCK_TRANSFER_CANCELLED,
                        resource: 'stock_transfer',
                        resourceId: transferId,
                        details: { reason: reason ?? null } as any,
                    },
                });
            }
            return res;
        });
        if (count !== 1) {
            throw new AppError('This request is no longer pending', 400, 'INVALID_STATUS');
        }

        // A pending request still lives in the vendor's personal inbox.
        const vendorInboxId = await this.personalWorkspaceId(transfer.senderUserId);
        NotificationsService.dispatch({
            type: NotificationType.STOCK_TRANSFER_DECIDED,
            userId: transfer.senderUserId,
            workspaceId: vendorInboxId,
            title: 'Stock request cancelled',
            body: 'The stock request awaiting you was withdrawn by its requester',
            entityType: NotificationEntityType.STOCK_TRANSFER,
            entityId: transferId,
            groupKey: `stock-transfer:${transferId}:decided`,
        });

        return this.prisma.stockTransfer.findUniqueOrThrow({ where: { id: transferId } });
    }

    // ─── The money legs (one-time each) ──────────────────
    /**
     * The requester's side: record the purchase cost as an EXPENSE in the
     * receiving workspace's book. One-time, guarded and claimed atomically —
     * the same discipline as the rental contract's money legs.
     */
    async recordExpense(transferId: string, userId: string, dto: RecordTransferEntryDto) {
        const { EntriesService } = await import('../entries/entries.service');
        const { container } = await import('tsyringe');

        const transfer = await this.prisma.stockTransfer.findUnique({
            where: { id: transferId },
            select: {
                id: true, status: true, recipientUserId: true, recipientWorkspaceId: true,
                quantity: true, proposedUnitCost: true, expenseEntryId: true,
                senderItem: { select: { name: true, currency: true } },
                senderUser: { select: { firstName: true, lastName: true } },
            },
        });
        if (!transfer) throw new NotFoundError('Stock request');
        if (transfer.recipientUserId !== userId) {
            throw new AuthorizationError('Only the requester can record this expense');
        }
        if (transfer.status !== StockTransferStatus.COMPLETED) {
            throw new AppError('Confirm receipt of the stock before recording its cost', 400, 'INVALID_STATUS');
        }
        if (!transfer.senderItem) {
            throw new AppError('The vendor has not released stock for this request yet', 400, 'INVALID_STATUS');
        }
        if (!transfer.recipientWorkspaceId) {
            throw new AppError('This request is missing its receiving workspace', 400, 'INVALID_STATE');
        }
        const senderItem = transfer.senderItem;
        const recipientWorkspaceId = transfer.recipientWorkspaceId;

        const cashbook = await this.prisma.cashbook.findUnique({ where: { id: dto.cashbookId } });
        if (!cashbook || !cashbook.isActive) throw new NotFoundError('Cashbook');
        assertCashbookWritable(cashbook);
        if (cashbook.workspaceId !== recipientWorkspaceId) {
            throw new AppError(
                'The stock cost can only be recorded in the workspace that received it',
                400,
                'WRONG_WORKSPACE',
            );
        }
        if (cashbook.currency !== senderItem.currency) {
            throw new AppError(
                `This book's currency (${cashbook.currency}) does not match the goods (${senderItem.currency})`,
                400,
                'CURRENCY_MISMATCH',
            );
        }

        const cost = transfer.proposedUnitCost.mul(transfer.quantity);
        if (cost.lessThanOrEqualTo(0)) {
            throw new AppError('This request carries no unit cost — record the purchase manually', 400, 'NO_CHARGE');
        }
        if (transfer.expenseEntryId) {
            throw new AppError('The stock expense has already been recorded for this request', 409, 'ALREADY_RECORDED');
        }

        const vendorName = `${transfer.senderUser.firstName} ${transfer.senderUser.lastName}`.trim();

        return withFinancialTransaction(this.prisma, async (tx) => {
            const entry = await container.resolve(EntriesService).createEntryWithin(
                tx,
                cashbook.id,
                userId,
                {
                    type: 'EXPENSE',
                    amount: cost.toFixed(4),
                    description: `Stock purchase — ${transfer.quantity} × ${senderItem.name} — ${vendorName}`,
                    accountId: dto.accountId,
                    entryDate: dto.entryDate ?? new Date().toISOString(),
                } as any,
            );

            const { count } = await tx.stockTransfer.updateMany({
                where: { id: transferId, expenseEntryId: null },
                data: { expenseEntryId: entry.id },
            });
            if (count !== 1) {
                throw new AppError('The stock expense has already been recorded for this request', 409, 'ALREADY_RECORDED');
            }

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: recipientWorkspaceId,
                    action: AuditAction.STOCK_TRANSFER_EXPENSE_RECORDED,
                    resource: 'stock_transfer',
                    resourceId: transferId,
                    details: { entryId: entry.id, amount: cost.toString() } as any,
                },
            });

            return entry;
        });
    }

    /**
     * The vendor's side: record the sale value as INCOME in their own book.
     * One-time, same guards.
     */
    async recordIncome(transferId: string, userId: string, dto: RecordTransferEntryDto) {
        const { EntriesService } = await import('../entries/entries.service');
        const { container } = await import('tsyringe');

        const transfer = await this.prisma.stockTransfer.findUnique({
            where: { id: transferId },
            select: {
                id: true, status: true, senderUserId: true, senderWorkspaceId: true,
                quantity: true, proposedUnitCost: true, incomeEntryId: true,
                senderItem: { select: { name: true, currency: true } },
                recipientUser: { select: { firstName: true, lastName: true } },
            },
        });
        if (!transfer) throw new NotFoundError('Stock request');
        if (transfer.senderUserId !== userId) {
            throw new AuthorizationError('Only the vendor can record this income');
        }
        // The vendor's income can be recorded once the goods have left (SENT)
        // — the sale happened at send, receipt only completes the exchange.
        if (transfer.status !== StockTransferStatus.SENT && transfer.status !== StockTransferStatus.COMPLETED) {
            throw new AppError('Send the stock before recording its income', 400, 'INVALID_STATUS');
        }
        if (!transfer.senderItem) {
            throw new AppError('The vendor has not released stock for this request yet', 400, 'INVALID_STATUS');
        }
        if (!transfer.senderWorkspaceId) {
            throw new AppError('This request is missing its sending workspace', 400, 'INVALID_STATE');
        }
        const senderItem = transfer.senderItem;
        const senderWorkspaceId = transfer.senderWorkspaceId;

        const cashbook = await this.prisma.cashbook.findUnique({ where: { id: dto.cashbookId } });
        if (!cashbook || !cashbook.isActive) throw new NotFoundError('Cashbook');
        assertCashbookWritable(cashbook);
        if (cashbook.workspaceId !== senderWorkspaceId) {
            throw new AppError(
                'The stock income can only be recorded in the vendor workspace that sent it',
                400,
                'WRONG_WORKSPACE',
            );
        }
        if (cashbook.currency !== senderItem.currency) {
            throw new AppError(
                `This book's currency (${cashbook.currency}) does not match the goods (${senderItem.currency})`,
                400,
                'CURRENCY_MISMATCH',
            );
        }

        const value = transfer.proposedUnitCost.mul(transfer.quantity);
        if (value.lessThanOrEqualTo(0)) {
            throw new AppError('This request carries no unit cost — record the sale manually', 400, 'NO_CHARGE');
        }
        if (transfer.incomeEntryId) {
            throw new AppError('The stock income has already been recorded for this request', 409, 'ALREADY_RECORDED');
        }

        const buyerName = [transfer.recipientUser?.firstName, transfer.recipientUser?.lastName].filter(Boolean).join(' ') || 'the customer';

        return withFinancialTransaction(this.prisma, async (tx) => {
            const entry = await container.resolve(EntriesService).createEntryWithin(
                tx,
                cashbook.id,
                userId,
                {
                    type: 'INCOME',
                    amount: value.toFixed(4),
                    description: `Stock sale — ${transfer.quantity} × ${senderItem.name} — ${buyerName}`,
                    accountId: dto.accountId,
                    entryDate: dto.entryDate ?? new Date().toISOString(),
                } as any,
            );

            const { count } = await tx.stockTransfer.updateMany({
                where: { id: transferId, incomeEntryId: null },
                data: { incomeEntryId: entry.id },
            });
            if (count !== 1) {
                throw new AppError('The stock income has already been recorded for this request', 409, 'ALREADY_RECORDED');
            }

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: senderWorkspaceId,
                    action: AuditAction.STOCK_TRANSFER_INCOME_RECORDED,
                    resource: 'stock_transfer',
                    resourceId: transferId,
                    details: { entryId: entry.id, amount: value.toString() } as any,
                },
            });

            return entry;
        });
    }

    // ─── Query ───────────────────────────────────────────
    async list(userId: string, query: StockTransferQueryDto) {
        const where: Prisma.StockTransferWhereInput = {};
        if (query.workspaceId) {
            /*
             * One workspace's view: the requests it made, and the requests it
             * sent. A pending request addressed to the current user belongs
             * to none of their workspaces yet, so it surfaces only in their
             * personal workspace — the vendor's inbox of sent-in requests.
             */
            const workspace = await this.prisma.workspace.findUnique({
                where: { id: query.workspaceId },
                select: { ownerId: true, type: true },
            });
            where.OR = [
                { recipientUserId: userId, recipientWorkspaceId: query.workspaceId },
                { senderUserId: userId, senderWorkspaceId: query.workspaceId },
            ];
            if (workspace?.type === WorkspaceType.PERSONAL && workspace.ownerId === userId) {
                where.OR.push({ senderUserId: userId, senderWorkspaceId: null, status: StockTransferStatus.PENDING });
            }
        } else if (query.direction === 'sent') {
            // The vendor's view: requests addressed to them.
            where.senderUserId = userId;
        } else if (query.direction === 'received') {
            // The requester's view: requests they made.
            where.recipientUserId = userId;
        } else {
            where.OR = [{ senderUserId: userId }, { recipientUserId: userId }];
        }
        if (query.status) where.status = query.status as StockTransferStatus;

        const [transfers, total] = await Promise.all([
            this.prisma.stockTransfer.findMany({
                where,
                include: TRANSFER_INCLUDE,
                skip: (Math.max(1, query.page || 1) - 1) * (query.limit || 20),
                take: query.limit || 20,
                orderBy: { createdAt: 'desc' },
            }),
            this.prisma.stockTransfer.count({ where }),
        ]);

        const totalPages = Math.ceil(total / (query.limit || 20)) || 1;
        return {
            data: transfers,
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

    async getForUser(transferId: string, userId: string) {
        const transfer = await this.prisma.stockTransfer.findUnique({
            where: { id: transferId },
            include: TRANSFER_INCLUDE,
        });
        if (!transfer) throw new NotFoundError('Stock request');
        if (transfer.senderUserId !== userId && transfer.recipientUserId !== userId) {
            throw new AuthorizationError('You are not a party to this request');
        }
        return transfer;
    }

    /** The vendor's sending options for a pending request: their owned/admin
     *  workspaces, and in each the items that could fulfil it — filtered to
     *  the requested item's currency so only valid picks are offered. */
    async getSendOptions(transferId: string, vendorUserId: string) {
        const transfer = await this.getForUser(transferId, vendorUserId);
        if (transfer.senderUserId !== vendorUserId) {
            throw new AuthorizationError('Only the vendor can respond to this request');
        }
        if (transfer.status !== StockTransferStatus.PENDING) {
            throw new AppError(`This request is already ${transfer.status.toLowerCase()}`, 400, 'INVALID_STATUS');
        }

        const requestedItem = transfer.recipientItemId
            ? await this.prisma.inventoryItem.findUnique({
                where: { id: transfer.recipientItemId },
                select: { id: true, name: true, unit: true, currency: true },
            })
            : null;

        const [owned, adminMemberships] = await Promise.all([
            this.prisma.workspace.findMany({
                where: { ownerId: vendorUserId, isActive: true },
                select: { id: true, name: true, defaultCurrency: true },
            }),
            this.prisma.workspaceMember.findMany({
                where: { userId: vendorUserId, role: { in: ['OWNER', 'ADMIN'] } },
                select: { workspace: { select: { id: true, name: true, defaultCurrency: true, isActive: true } } },
            }),
        ]);
        const admin = adminMemberships.map((m) => m.workspace).filter((w) => w.isActive);
        const seen = new Set<string>();
        const workspaces = [...owned, ...admin].filter((w) => !seen.has(w.id) && seen.add(w.id));

        const wsIds = workspaces.map((w) => w.id);
        const items = wsIds.length
            ? await this.prisma.inventoryItem.findMany({
                where: {
                    workspaceId: { in: wsIds },
                    isActive: true,
                    // Only items that can actually fulfil the request.
                    ...(requestedItem ? { currency: requestedItem.currency } : {}),
                },
                select: { id: true, name: true, unit: true, sku: true, workspaceId: true, currency: true },
                orderBy: { name: 'asc' },
            })
            : [];

        return { workspaces, items, requestedItem };
    }
}

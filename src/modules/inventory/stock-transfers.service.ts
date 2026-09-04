import { injectable, inject } from 'tsyringe';
import {
    Prisma, PrismaClient, StockTransferStatus, InventoryTransactionType,
    InventoryReferenceType, NotificationType, NotificationEntityType,
} from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import { NotFoundError, AppError, AuthorizationError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';
import { withFinancialTransaction } from '../../core/db/transaction';
import { NotificationsService } from '../notifications/notifications.service';
import { InventoryService } from './inventory.service';
import {
    CreateStockTransferDto, RespondStockTransferDto, StockTransferQueryDto,
} from './agreements.dto';

const TRANSFER_INCLUDE = {
    senderUser: { select: { id: true, email: true, firstName: true, lastName: true } },
    recipientUser: { select: { id: true, email: true, firstName: true, lastName: true } },
    senderItem: { select: { id: true, name: true, unit: true, sku: true, currency: true, category: true } },
    recipientWorkspace: { select: { id: true, name: true } },
    recipientItem: { select: { id: true, name: true, unit: true } },
} satisfies Prisma.StockTransferInclude;

/**
 * Cross-workspace stock transfers — one platform user moving stock to
 * another, with the app as the shared proof.
 *
 * Peer-link mechanics, stock instead of money: the sender proposes from one
 * of their items, addressed to the recipient by email; the recipient accepts
 * into a workspace of their own choosing, picking a matching item or letting
 * one be created from the sender's details. On acceptance both movements
 * post atomically — TRANSFER_OUT on the sender's side, TRANSFER_IN on the
 * receiver's at the same per-unit value — so both books agree on what moved
 * and what it was worth.
 */
@injectable()
export class StockTransfersService {
    constructor(
        @inject('PrismaClient') private prisma: PrismaClient,
        private inventoryService: InventoryService,
    ) { }

    // ─── Propose (sender) ────────────────────────────────
    async create(senderWorkspaceId: string, senderItemId: string, userId: string, dto: CreateStockTransferDto) {
        const item = await this.prisma.inventoryItem.findUnique({
            where: { id: senderItemId },
            include: { stock: true },
        });
        if (!item || item.workspaceId !== senderWorkspaceId) {
            throw new NotFoundError('Inventory item');
        }

        const recipient = await this.prisma.user.findUnique({
            where: { email: dto.recipientEmail.toLowerCase() },
            select: { id: true, isActive: true },
        });
        if (!recipient || !recipient.isActive) {
            throw new AppError('No active user found with that email', 404, 'USER_NOT_FOUND');
        }
        if (recipient.id === userId) {
            throw new AppError('You cannot transfer stock to yourself', 400, 'SELF_TRANSFER');
        }

        const qty = Math.round(dto.quantity);
        if (qty <= 0) {
            throw new AppError('Quantity must be at least 1', 400, 'INVALID_QUANTITY');
        }
        const available = (item.stock?.quantityOnHand ?? 0) - (item.stock?.quantityReserved ?? 0);
        if (available < qty) {
            throw new AppError(
                `Insufficient stock. Available: ${available}, requested: ${qty}`,
                400,
                'INSUFFICIENT_STOCK',
            );
        }

        const transfer = await this.prisma.$transaction(async (tx) => {
            const created = await tx.stockTransfer.create({
                data: {
                    status: StockTransferStatus.PENDING,
                    senderUserId: userId,
                    senderWorkspaceId,
                    senderItemId,
                    quantity: qty,
                    // The sender's current average cost — a snapshot of what
                    // the goods are worth today. Informational: the value that
                    // moves is recomputed at acceptance.
                    proposedUnitCost: item.stock?.averageCost ?? new Decimal(0),
                    recipientUserId: recipient.id,
                    notes: dto.notes || null,
                },
            });
            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: senderWorkspaceId,
                    action: AuditAction.STOCK_TRANSFER_CREATED,
                    resource: 'stock_transfer',
                    resourceId: created.id,
                    details: { itemId: senderItemId, quantity: qty, recipientUserId: recipient.id } as any,
                },
            });
            return created;
        });

        NotificationsService.dispatch({
            type: NotificationType.STOCK_TRANSFER_RECEIVED,
            userId: recipient.id,
            workspaceId: senderWorkspaceId,
            title: 'Stock transfer incoming',
            body: `${qty} × ${item.name} is being sent to you — accept to receive it into one of your workspaces`,
            entityType: NotificationEntityType.STOCK_TRANSFER,
            entityId: transfer.id,
            groupKey: `stock-transfer:${transfer.id}`,
        });

        return this.getForUser(transfer.id, userId);
    }

    // ─── Accept (recipient picks destination) ────────────
    /**
     * The moment the stock moves: TRANSFER_OUT on the sender's side and
     * TRANSFER_IN on the receiver's, one transaction, one value. The unit
     * cost that leaves is exactly the unit cost that arrives.
     */
    async accept(transferId: string, userId: string, dto: RespondStockTransferDto) {
        const transfer = await withFinancialTransaction(this.prisma, async (tx) => {
            const pending = await tx.stockTransfer.findUnique({ where: { id: transferId } });
            if (!pending) throw new NotFoundError('Stock transfer');
            if (pending.recipientUserId !== userId) {
                throw new AuthorizationError('Only the recipient can accept this transfer');
            }
            if (pending.status !== StockTransferStatus.PENDING) {
                throw new AppError(`This transfer is already ${pending.status.toLowerCase()}`, 400, 'INVALID_STATUS');
            }

            const workspace = await tx.workspace.findUnique({ where: { id: dto.recipientWorkspaceId } });
            if (!workspace || !workspace.isActive) {
                throw new NotFoundError('Workspace');
            }
            if (workspace.id === pending.senderWorkspaceId) {
                throw new AppError('Choose one of your own workspaces to receive the stock', 400, 'INVALID_WORKSPACE');
            }
            // The recipient must control the chosen workspace.
            if (workspace.ownerId !== userId) {
                const membership = await tx.workspaceMember.findUnique({
                    where: { workspaceId_userId: { workspaceId: workspace.id, userId } },
                });
                if (!membership) {
                    throw new AuthorizationError('You do not have access to that workspace');
                }
            }

            const senderItem = await tx.inventoryItem.findUniqueOrThrow({
                where: { id: pending.senderItemId },
                include: { stock: true },
            });
            // Stock has left since the proposal? The guard below refuses it
            // honestly rather than transferring short.
            const available = (senderItem.stock?.quantityOnHand ?? 0) - (senderItem.stock?.quantityReserved ?? 0);
            if (available < pending.quantity) {
                throw new AppError(
                    `Insufficient stock at the sender. Available: ${available}, promised: ${pending.quantity}`,
                    400,
                    'INSUFFICIENT_STOCK',
                );
            }

            // Resolve the receiving item: an existing one, or a new one
            // created from the sender's details. New items land in the
            // workspace's currency — checked against the goods below.
            let recipientItemId = dto.recipientItemId || null;
            if (recipientItemId) {
                const target = await tx.inventoryItem.findUnique({ where: { id: recipientItemId } });
                if (!target || target.workspaceId !== workspace.id) {
                    throw new NotFoundError('Recipient inventory item');
                }
                if (target.currency !== senderItem.currency) {
                    throw new AppError(
                        `That item's currency (${target.currency}) does not match the transferred goods (${senderItem.currency})`,
                        400,
                        'CURRENCY_MISMATCH',
                    );
                }
            } else {
                const created = await tx.inventoryItem.create({
                    data: {
                        workspaceId: workspace.id,
                        name: senderItem.name,
                        unit: senderItem.unit,
                        category: senderItem.category,
                        // A workspace holds one currency; a receiving item in
                        // another would break every stock valuation that
                        // touches it, so a currency mismatch refuses the
                        // acceptance up front instead.
                        currency: workspace.defaultCurrency,
                        commercialMode: 'SELL_ONLY',
                        allowNegativeStock: false,
                    },
                });
                await tx.inventoryStock.create({
                    data: {
                        itemId: created.id,
                        quantityOnHand: 0,
                        quantityRentedOut: 0,
                        quantityReserved: 0,
                        averageCost: 0,
                    },
                });
                if (workspace.defaultCurrency !== senderItem.currency) {
                    throw new AppError(
                        `That workspace's currency (${workspace.defaultCurrency}) does not match the item's (${senderItem.currency})`,
                        400,
                        'CURRENCY_MISMATCH',
                    );
                }
                recipientItemId = created.id;
            }

            // The sender's stock leaves — real COGS resolution (lots/WAC).
            const outTx = await this.inventoryService.processStockOut(
                pending.senderWorkspaceId,
                pending.senderItemId,
                InventoryTransactionType.TRANSFER_OUT,
                pending.quantity,
                userId,
                InventoryReferenceType.STOCK_TRANSFER,
                transferId,
                `Stock transferred out (agreement ${transferId.slice(0, 8)})`,
                tx,
            );

            // The same per-unit value arrives on the receiver's side.
            await this.inventoryService.processStockIn(
                workspace.id,
                recipientItemId,
                InventoryTransactionType.TRANSFER_IN,
                pending.quantity,
                outTx.unitCost,
                userId,
                InventoryReferenceType.STOCK_TRANSFER,
                transferId,
                `Stock received via transfer (agreement ${transferId.slice(0, 8)})`,
                tx,
            );

            // PENDING-guarded claim: a concurrent decision cannot double-move stock.
            const { count } = await tx.stockTransfer.updateMany({
                where: { id: transferId, status: StockTransferStatus.PENDING },
                data: {
                    status: StockTransferStatus.ACCEPTED,
                    recipientWorkspaceId: workspace.id,
                    recipientItemId,
                    respondedAt: new Date(),
                },
            });
            if (count !== 1) {
                throw new AppError('This transfer is no longer pending', 400, 'INVALID_STATUS');
            }

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: workspace.id,
                    action: AuditAction.STOCK_TRANSFER_ACCEPTED,
                    resource: 'stock_transfer',
                    resourceId: transferId,
                    details: {
                        recipientItemId,
                        quantity: pending.quantity,
                        unitCost: outTx.unitCost.toString(),
                    } as any,
                },
            });

            return tx.stockTransfer.findUniqueOrThrow({ where: { id: transferId } });
        });

        NotificationsService.dispatch({
            type: NotificationType.STOCK_TRANSFER_DECIDED,
            userId: transfer.senderUserId,
            workspaceId: transfer.senderWorkspaceId,
            title: 'Stock transfer accepted',
            body: `${transfer.quantity} units left your inventory and landed in the receiving workspace`,
            entityType: NotificationEntityType.STOCK_TRANSFER,
            entityId: transfer.id,
            groupKey: `stock-transfer:${transfer.id}:decided`,
        });

        return transfer;
    }

    // ─── Decline (recipient) / Cancel (sender) ────────────
    async decline(transferId: string, userId: string, reason?: string) {
        const transfer = await this.prisma.stockTransfer.findUnique({ where: { id: transferId } });
        if (!transfer) throw new NotFoundError('Stock transfer');
        if (transfer.recipientUserId !== userId) {
            throw new AuthorizationError('Only the recipient can decline this transfer');
        }
        if (transfer.status !== StockTransferStatus.PENDING) {
            throw new AppError(`This transfer is already ${transfer.status.toLowerCase()}`, 400, 'INVALID_STATUS');
        }

        const { count } = await this.prisma.$transaction(async (tx) => {
            const res = await tx.stockTransfer.updateMany({
                where: { id: transferId, status: StockTransferStatus.PENDING },
                data: { status: StockTransferStatus.DECLINED, respondedAt: new Date() },
            });
            if (res.count === 1) {
                await tx.auditLog.create({
                    data: {
                        userId,
                        workspaceId: transfer.senderWorkspaceId,
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
            throw new AppError('This transfer is no longer pending', 400, 'INVALID_STATUS');
        }

        NotificationsService.dispatch({
            type: NotificationType.STOCK_TRANSFER_DECIDED,
            userId: transfer.senderUserId,
            workspaceId: transfer.senderWorkspaceId,
            title: 'Stock transfer declined',
            body: `The stock transfer you proposed was declined${reason ? `: ${reason}` : ''}`,
            entityType: NotificationEntityType.STOCK_TRANSFER,
            entityId: transferId,
            groupKey: `stock-transfer:${transferId}:decided`,
        });

        return this.prisma.stockTransfer.findUniqueOrThrow({ where: { id: transferId } });
    }

    async cancel(transferId: string, userId: string, reason?: string) {
        const transfer = await this.prisma.stockTransfer.findUnique({ where: { id: transferId } });
        if (!transfer) throw new NotFoundError('Stock transfer');
        if (transfer.senderUserId !== userId) {
            throw new AuthorizationError('Only the sender can cancel this transfer');
        }
        if (transfer.status !== StockTransferStatus.PENDING) {
            throw new AppError('Only pending transfers can be cancelled. Accepted ones already moved the stock.', 400, 'INVALID_STATUS');
        }

        const { count } = await this.prisma.$transaction(async (tx) => {
            const res = await tx.stockTransfer.updateMany({
                where: { id: transferId, status: StockTransferStatus.PENDING },
                data: { status: StockTransferStatus.CANCELLED, respondedAt: new Date() },
            });
            if (res.count === 1) {
                await tx.auditLog.create({
                    data: {
                        userId,
                        workspaceId: transfer.senderWorkspaceId,
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
            throw new AppError('This transfer is no longer pending', 400, 'INVALID_STATUS');
        }

        NotificationsService.dispatch({
            type: NotificationType.STOCK_TRANSFER_DECIDED,
            userId: transfer.recipientUserId!,
            workspaceId: transfer.senderWorkspaceId,
            title: 'Stock transfer cancelled',
            body: 'The stock transfer awaiting you was withdrawn by its sender',
            entityType: NotificationEntityType.STOCK_TRANSFER,
            entityId: transferId,
            groupKey: `stock-transfer:${transferId}:decided`,
        });

        return this.prisma.stockTransfer.findUniqueOrThrow({ where: { id: transferId } });
    }

    // ─── Query ───────────────────────────────────────────
    async list(userId: string, query: StockTransferQueryDto) {
        const where: Prisma.StockTransferWhereInput = {};
        if (query.direction === 'sent') {
            where.senderUserId = userId;
        } else if (query.direction === 'received') {
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
        if (!transfer) throw new NotFoundError('Stock transfer');
        if (transfer.senderUserId !== userId && transfer.recipientUserId !== userId) {
            throw new AuthorizationError('You are not a party to this transfer');
        }
        return transfer;
    }

    /**
     * The recipient's acceptance options: their workspaces (currency-matched
     * against the goods), and within the chosen one the items that could
     * receive the stock — same name or same unit — plus the fallback of
     * creating a new item.
     */
    async getAcceptanceOptions(transferId: string, userId: string) {
        const transfer = await this.getForUser(transferId, userId);
        if (transfer.recipientUserId !== userId) {
            throw new AuthorizationError('Only the recipient can respond to this transfer');
        }
        if (transfer.status !== StockTransferStatus.PENDING) {
            throw new AppError(`This transfer is already ${transfer.status.toLowerCase()}`, 400, 'INVALID_STATUS');
        }

        const senderItem = await this.prisma.inventoryItem.findUniqueOrThrow({
            where: { id: transfer.senderItemId },
            select: { name: true, unit: true, currency: true, category: true },
        });

        const workspaces = await this.prisma.workspace.findMany({
            where: { OR: [{ ownerId: userId }, { members: { some: { userId } } }], isActive: true },
            select: { id: true, name: true, defaultCurrency: true, type: true },
        });
        const eligible = workspaces.filter(
            (w) => w.id !== transfer.senderWorkspaceId && w.defaultCurrency === senderItem.currency,
        );

        // Suggest matching items across the recipient's eligible workspaces —
        // same name first, same unit as a weaker signal.
        const wsIds = eligible.map((w) => w.id);
        const items = wsIds.length
            ? await this.prisma.inventoryItem.findMany({
                where: {
                    workspaceId: { in: wsIds },
                    isActive: true,
                    OR: [{ name: senderItem.name }, { unit: senderItem.unit }],
                },
                select: { id: true, name: true, unit: true, workspaceId: true, sku: true },
                orderBy: { name: 'asc' },
            })
            : [];

        return { workspaces: eligible, suggestedItems: items, senderItem };
    }
}

import { injectable, inject } from 'tsyringe';
import { PrismaClient, InventoryTransactionType, InventoryReferenceType } from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import { InventoryRepository } from './inventory.repository';
import { AppError, NotFoundError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';
import {
    CreateInventoryItemDto,
    UpdateInventoryItemDto,
    InventoryItemQueryDto,
    CreateInventoryTransactionDto,
    InventoryTransactionQueryDto,
    InventoryLineItemDto,
    CogsReportQueryDto,
} from './inventory.dto';

// Stock-in transaction types (increase quantityOnHand)
const STOCK_IN_TYPES: InventoryTransactionType[] = [
    InventoryTransactionType.PURCHASE,
    InventoryTransactionType.TRANSFER_IN,
    InventoryTransactionType.RETURN_IN,
];

// Stock-out transaction types (decrease quantityOnHand)
const STOCK_OUT_TYPES: InventoryTransactionType[] = [
    InventoryTransactionType.SALE,
    InventoryTransactionType.TRANSFER_OUT,
    InventoryTransactionType.RETURN_OUT,
];

@injectable()
export class InventoryService {
    constructor(
        private repository: InventoryRepository,
        @inject('PrismaClient') private prisma: PrismaClient,
    ) { }

    // ═══════════════════════════════════════════════════════
    // ─── Item CRUD ─────────────────────────────────────────
    // ═══════════════════════════════════════════════════════

    async createItem(workspaceId: string, userId: string, dto: CreateInventoryItemDto) {
        // Unique SKU check (within workspace)
        if (dto.sku) {
            const existing = await this.prisma.inventoryItem.findUnique({
                where: { workspaceId_sku: { workspaceId, sku: dto.sku } },
            });
            if (existing) {
                throw new AppError(`An item with SKU "${dto.sku}" already exists`, 409, 'DUPLICATE_SKU');
            }
        }

        return this.prisma.$transaction(async (tx) => {
            const item = await tx.inventoryItem.create({
                data: {
                    workspaceId,
                    name: dto.name,
                    sku: dto.sku || null,
                    unit: dto.unit,
                    category: dto.category || null,
                    lowStockThreshold: dto.lowStockThreshold ?? null,
                    costMethod: dto.costMethod as any,
                    allowNegativeStock: dto.allowNegativeStock,
                },
            });

            // Auto-create stock record at zero
            await tx.inventoryStock.create({
                data: {
                    itemId: item.id,
                    quantityOnHand: 0,
                    averageCost: 0,
                },
            });

            // Audit
            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.INVENTORY_ITEM_CREATED as any,
                    resource: 'inventory_item',
                    resourceId: item.id,
                    details: { name: item.name, sku: item.sku, unit: item.unit } as any,
                },
            });

            return tx.inventoryItem.findUnique({
                where: { id: item.id },
                include: { stock: true },
            });
        });
    }

    async getItems(workspaceId: string, query: InventoryItemQueryDto) {
        const page = Number(query.page) || 1;
        const limit = Number(query.limit) || 20;
        const skip = (page - 1) * limit;

        const { items, total } = await this.repository.findItemsByWorkspace(workspaceId, {
            skip,
            take: limit,
            category: query.category,
            isActive: query.isActive !== undefined ? query.isActive === 'true' : undefined,
            search: query.search,
        });

        const totalPages = Math.ceil(total / limit);

        return {
            data: items,
            pagination: {
                page,
                limit,
                total,
                totalPages,
                hasNext: page < totalPages,
                hasPrevious: page > 1,
            },
        };
    }

    async getItem(itemId: string, workspaceId: string) {
        const item = await this.repository.findItemById(itemId);
        if (!item || item.workspaceId !== workspaceId) {
            throw new NotFoundError('Inventory Item');
        }
        return item;
    }

    async updateItem(itemId: string, workspaceId: string, userId: string, dto: UpdateInventoryItemDto) {
        const item = await this.repository.findItemById(itemId);
        if (!item || item.workspaceId !== workspaceId) {
            throw new NotFoundError('Inventory Item');
        }

        // SKU uniqueness check if updating sku
        if (dto.sku && dto.sku !== item.sku) {
            const duplicate = await this.prisma.inventoryItem.findUnique({
                where: { workspaceId_sku: { workspaceId, sku: dto.sku } },
            });
            if (duplicate && duplicate.id !== itemId) {
                throw new AppError(`An item with SKU "${dto.sku}" already exists`, 409, 'DUPLICATE_SKU');
            }
        }

        const updated = await this.prisma.$transaction(async (tx) => {
            const result = await tx.inventoryItem.update({
                where: { id: itemId },
                data: {
                    ...(dto.name !== undefined && { name: dto.name }),
                    ...(dto.sku !== undefined && { sku: dto.sku }),
                    ...(dto.unit !== undefined && { unit: dto.unit }),
                    ...(dto.category !== undefined && { category: dto.category }),
                    ...(dto.lowStockThreshold !== undefined && { lowStockThreshold: dto.lowStockThreshold }),
                    ...(dto.allowNegativeStock !== undefined && { allowNegativeStock: dto.allowNegativeStock }),
                    ...(dto.isActive !== undefined && { isActive: dto.isActive }),
                },
                include: { stock: true },
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.INVENTORY_ITEM_UPDATED as any,
                    resource: 'inventory_item',
                    resourceId: itemId,
                    details: { changes: dto } as any,
                },
            });

            return result;
        });

        return updated;
    }

    async deactivateItem(itemId: string, workspaceId: string, userId: string) {
        const item = await this.repository.findItemById(itemId);
        if (!item || item.workspaceId !== workspaceId) {
            throw new NotFoundError('Inventory Item');
        }

        return this.prisma.$transaction(async (tx) => {
            const result = await tx.inventoryItem.update({
                where: { id: itemId },
                data: { isActive: false },
                include: { stock: true },
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.INVENTORY_ITEM_DEACTIVATED as any,
                    resource: 'inventory_item',
                    resourceId: itemId,
                },
            });

            return result;
        });
    }

    // ═══════════════════════════════════════════════════════
    // ─── Manual Inventory Transaction ──────────────────────
    // ═══════════════════════════════════════════════════════

    async createTransaction(workspaceId: string, userId: string, dto: CreateInventoryTransactionDto) {
        const item = await this.repository.findItemById(dto.itemId);
        if (!item || item.workspaceId !== workspaceId) {
            throw new NotFoundError('Inventory Item');
        }
        if (!item.isActive) {
            throw new AppError('Cannot create transactions for an inactive item', 400, 'ITEM_INACTIVE');
        }

        // Immutability guard: manual endpoint can only create MANUAL-referenced transactions
        if (dto.referenceType && dto.referenceType !== 'MANUAL') {
            throw new AppError(
                'Transactions linked to financial records can only be created through the corresponding financial module',
                400,
                'INVALID_REFERENCE_TYPE'
            );
        }

        const transactionType = dto.transactionType as InventoryTransactionType;
        const isStockIn = STOCK_IN_TYPES.includes(transactionType) &&
            !(transactionType === InventoryTransactionType.ADJUSTMENT);
        const isStockOut = STOCK_OUT_TYPES.includes(transactionType) &&
            !(transactionType === InventoryTransactionType.ADJUSTMENT);

        // For ADJUSTMENT, determine direction from context:
        // We always treat manual adjustments as stock-in here; stock-out adjustments
        // go through processStockOut with ADJUSTMENT type and a negative quantity flag.
        // For manual transactions, the user specifies the direction via notes.

        const unitCost = new Decimal(dto.unitCost);

        if (isStockIn || transactionType === InventoryTransactionType.ADJUSTMENT) {
            return this.processStockIn(
                workspaceId,
                dto.itemId,
                transactionType,
                dto.quantity,
                unitCost,
                userId,
                dto.referenceType ? dto.referenceType as InventoryReferenceType : InventoryReferenceType.MANUAL,
                dto.referenceId || null,
                dto.notes || null,
            );
        } else {
            return this.processStockOut(
                workspaceId,
                dto.itemId,
                transactionType,
                dto.quantity,
                userId,
                dto.referenceType ? dto.referenceType as InventoryReferenceType : InventoryReferenceType.MANUAL,
                dto.referenceId || null,
                dto.notes || null,
            );
        }
    }

    async getTransactions(workspaceId: string, query: InventoryTransactionQueryDto) {
        const page = Number(query.page) || 1;
        const limit = Number(query.limit) || 20;
        const skip = (page - 1) * limit;

        const { transactions, total } = await this.repository.findTransactionsByWorkspace(workspaceId, {
            skip,
            take: limit,
            itemId: query.itemId,
            transactionType: query.transactionType,
            startDate: query.startDate,
            endDate: query.endDate,
            sortOrder: query.sortOrder || 'desc',
        });

        const totalPages = Math.ceil(total / limit);

        return {
            data: transactions,
            pagination: {
                page,
                limit,
                total,
                totalPages,
                hasNext: page < totalPages,
                hasPrevious: page > 1,
            },
        };
    }

    // ═══════════════════════════════════════════════════════
    // ─── Core Stock Operations (Atomic) ────────────────────
    // ═══════════════════════════════════════════════════════

    /**
     * Process a stock-in operation (PURCHASE, TRANSFER_IN, RETURN_IN, ADJUSTMENT+).
     * Recalculates weighted average cost and updates quantityOnHand.
     * All updates performed inside an atomic transaction.
     */
    async processStockIn(
        workspaceId: string,
        itemId: string,
        transactionType: InventoryTransactionType,
        quantity: number,
        unitCost: Decimal,
        createdById: string,
        referenceType: InventoryReferenceType,
        referenceId: string | null,
        notes: string | null,
        tx?: any,
    ) {
        const execute = async (prisma: any) => {
            // Lock the stock row for update
            const stock = await prisma.inventoryStock.findUnique({
                where: { itemId },
            });

            if (!stock) {
                throw new AppError('Stock record not found. Item may be corrupted.', 500, 'STOCK_NOT_FOUND');
            }

            const currentQty = stock.quantityOnHand;
            const currentAvgCost = new Decimal(stock.averageCost);
            const incomingCost = unitCost;
            const totalCost = incomingCost.mul(quantity);

            // Weighted Average Cost Recalculation:
            // newAvgCost = (currentQty * currentAvgCost + newQty * newUnitCost) / (currentQty + newQty)
            const totalExistingValue = currentAvgCost.mul(currentQty);
            const newTotalQty = currentQty + quantity;
            const newAvgCost = newTotalQty > 0
                ? totalExistingValue.add(totalCost).div(newTotalQty)
                : new Decimal(0);

            // Update stock
            await prisma.inventoryStock.update({
                where: { itemId },
                data: {
                    quantityOnHand: newTotalQty,
                    averageCost: newAvgCost,
                },
            });

            // Create transaction record
            const invTransaction = await prisma.inventoryTransaction.create({
                data: {
                    workspaceId,
                    itemId,
                    transactionType,
                    quantity, // positive for stock-in
                    unitCost: incomingCost,
                    totalCost,
                    referenceType,
                    referenceId,
                    notes,
                    createdById,
                },
            });

            return invTransaction;
        };

        // If already inside a transaction, reuse it; otherwise create one
        if (tx) {
            return execute(tx);
        }
        return this.prisma.$transaction(async (prisma) => execute(prisma));
    }

    /**
     * Process a stock-out operation (SALE, TRANSFER_OUT, RETURN_OUT, ADJUSTMENT-).
     * Calculates COGS using the weighted average cost method.
     * All updates performed inside an atomic transaction.
     */
    async processStockOut(
        workspaceId: string,
        itemId: string,
        transactionType: InventoryTransactionType,
        quantity: number,
        createdById: string,
        referenceType: InventoryReferenceType,
        referenceId: string | null,
        notes: string | null,
        tx?: any,
    ) {
        const execute = async (prisma: any) => {
            const stock = await prisma.inventoryStock.findUnique({
                where: { itemId },
            });

            if (!stock) {
                throw new AppError('Stock record not found. Item may be corrupted.', 500, 'STOCK_NOT_FOUND');
            }

            const item = await prisma.inventoryItem.findUnique({ where: { id: itemId } });

            // Negative stock guard
            if (!item.allowNegativeStock && stock.quantityOnHand < quantity) {
                throw new AppError(
                    `Insufficient stock. Available: ${stock.quantityOnHand}, Requested: ${quantity}`,
                    400,
                    'INSUFFICIENT_STOCK'
                );
            }

            const avgCost = new Decimal(stock.averageCost);
            const cogs = avgCost.mul(quantity);
            const newQty = stock.quantityOnHand - quantity;

            // Update stock (average cost stays the same on stock-out in weighted average)
            await prisma.inventoryStock.update({
                where: { itemId },
                data: {
                    quantityOnHand: newQty,
                },
            });

            // Create transaction record
            const invTransaction = await prisma.inventoryTransaction.create({
                data: {
                    workspaceId,
                    itemId,
                    transactionType,
                    quantity: -quantity, // negative for stock-out
                    unitCost: avgCost,
                    totalCost: cogs,
                    costOfGoodsSold: cogs,
                    referenceType,
                    referenceId,
                    notes,
                    createdById,
                },
            });

            return invTransaction;
        };

        if (tx) {
            return execute(tx);
        }
        return this.prisma.$transaction(async (prisma) => execute(prisma));
    }

    // ═══════════════════════════════════════════════════════
    // ─── Integration Hooks (Called from Entries/AccTx) ──────
    // ═══════════════════════════════════════════════════════

    /**
     * Process inventory line items attached to a financial Entry.
     * Called within the Entry's own $transaction context.
     *
     * - EXPENSE entry → PURCHASE inventory transaction (stock-in)
     * - INCOME entry  → SALE inventory transaction (stock-out)
     */
    async processEntryInventory(
        tx: any,
        workspaceId: string,
        entryId: string,
        entryType: string,
        entryAmount: Decimal,
        inventoryItems: InventoryLineItemDto[],
        createdById: string,
    ) {
        const isPurchase = entryType === 'EXPENSE';

        for (const lineItem of inventoryItems) {
            // Validate item exists and belongs to workspace
            const item = await tx.inventoryItem.findUnique({
                where: { id: lineItem.itemId },
                include: { stock: true },
            });

            if (!item || item.workspaceId !== workspaceId) {
                throw new AppError(`Inventory item ${lineItem.itemId} not found`, 404, 'ITEM_NOT_FOUND');
            }
            if (!item.isActive) {
                throw new AppError(`Inventory item "${item.name}" is inactive`, 400, 'ITEM_INACTIVE');
            }

            // Determine unit cost: explicit or derived from entry grossAmount / total qty
            let unitCost: Decimal;
            if (lineItem.unitCost) {
                unitCost = new Decimal(lineItem.unitCost);
            } else {
                // Derive: split entry amount evenly among all line items based on quantity ratio
                const totalQty = inventoryItems.reduce((sum, li) => sum + li.quantity, 0);
                unitCost = entryAmount.div(totalQty);
            }

            if (isPurchase) {
                await this.processStockIn(
                    workspaceId,
                    lineItem.itemId,
                    InventoryTransactionType.PURCHASE,
                    lineItem.quantity,
                    unitCost,
                    createdById,
                    InventoryReferenceType.ENTRY,
                    entryId,
                    null,
                    tx,
                );
            } else {
                // INCOME entry = selling stock
                await this.processStockOut(
                    workspaceId,
                    lineItem.itemId,
                    InventoryTransactionType.SALE,
                    lineItem.quantity,
                    createdById,
                    InventoryReferenceType.ENTRY,
                    entryId,
                    null,
                    tx,
                );
            }
        }
    }

    /**
     * Process inventory line items attached to a direct AccountTransaction.
     * Called within the AccountTransaction's own $transaction context.
     */
    async processAccountTransactionInventory(
        tx: any,
        workspaceId: string,
        transactionId: string,
        transactionType: string,
        transactionAmount: Decimal,
        inventoryItems: InventoryLineItemDto[],
        createdById: string,
    ) {
        const isPurchase = transactionType === 'EXPENSE';

        for (const lineItem of inventoryItems) {
            const item = await tx.inventoryItem.findUnique({
                where: { id: lineItem.itemId },
                include: { stock: true },
            });

            if (!item || item.workspaceId !== workspaceId) {
                throw new AppError(`Inventory item ${lineItem.itemId} not found`, 404, 'ITEM_NOT_FOUND');
            }
            if (!item.isActive) {
                throw new AppError(`Inventory item "${item.name}" is inactive`, 400, 'ITEM_INACTIVE');
            }

            let unitCost: Decimal;
            if (lineItem.unitCost) {
                unitCost = new Decimal(lineItem.unitCost);
            } else {
                const totalQty = inventoryItems.reduce((sum, li) => sum + li.quantity, 0);
                unitCost = transactionAmount.div(totalQty);
            }

            if (isPurchase) {
                await this.processStockIn(
                    workspaceId,
                    lineItem.itemId,
                    InventoryTransactionType.PURCHASE,
                    lineItem.quantity,
                    unitCost,
                    createdById,
                    InventoryReferenceType.ACCOUNT_TRANSACTION,
                    transactionId,
                    null,
                    tx,
                );
            } else {
                await this.processStockOut(
                    workspaceId,
                    lineItem.itemId,
                    InventoryTransactionType.SALE,
                    lineItem.quantity,
                    createdById,
                    InventoryReferenceType.ACCOUNT_TRANSACTION,
                    transactionId,
                    null,
                    tx,
                );
            }
        }
    }

    /**
     * Process inventory line items attached to a PAYABLE obligation.
     * Called within the Obligation's own $transaction context.
     * Stocks in goods when a payable obligation is created.
     */
    async processObligationInventory(
        tx: any,
        workspaceId: string,
        obligationId: string,
        obligationAmount: Decimal,
        inventoryItems: InventoryLineItemDto[],
        createdById: string,
    ) {
        for (const lineItem of inventoryItems) {
            const item = await tx.inventoryItem.findUnique({
                where: { id: lineItem.itemId },
                include: { stock: true },
            });

            if (!item || item.workspaceId !== workspaceId) {
                throw new AppError(`Inventory item ${lineItem.itemId} not found`, 404, 'ITEM_NOT_FOUND');
            }
            if (!item.isActive) {
                throw new AppError(`Inventory item "${item.name}" is inactive`, 400, 'ITEM_INACTIVE');
            }

            let unitCost: Decimal;
            if (lineItem.unitCost) {
                unitCost = new Decimal(lineItem.unitCost);
            } else {
                const totalQty = inventoryItems.reduce((sum, li) => sum + li.quantity, 0);
                unitCost = obligationAmount.div(totalQty);
            }

            await this.processStockIn(
                workspaceId,
                lineItem.itemId,
                InventoryTransactionType.PURCHASE,
                lineItem.quantity,
                unitCost,
                createdById,
                InventoryReferenceType.OBLIGATION,
                obligationId,
                null,
                tx,
            );
        }
    }

    /**
     * Reverse all inventory transactions linked to a specific financial reference.
     * Creates compensating transactions (opposite direction) to restore stock.
     * Used when entries/account-transactions are updated or deleted.
     *
     * @param tx - Prisma transaction context
     * @param referenceType - The type of financial reference (ENTRY, ACCOUNT_TRANSACTION, OBLIGATION)
     * @param referenceId - The ID of the financial record
     */
    async reverseInventoryForReference(
        tx: any,
        referenceType: InventoryReferenceType,
        referenceId: string,
    ) {
        // Find all inventory transactions linked to this reference
        const linkedTransactions = await tx.inventoryTransaction.findMany({
            where: { referenceType, referenceId },
            orderBy: { createdAt: 'asc' },
        });

        if (linkedTransactions.length === 0) return;

        for (const invTx of linkedTransactions) {
            const stock = await tx.inventoryStock.findUnique({
                where: { itemId: invTx.itemId },
            });

            if (!stock) continue;

            const absQuantity = Math.abs(invTx.quantity);

            if (invTx.quantity > 0) {
                // Original was stock-in → reverse = stock-out
                const avgCost = new Decimal(stock.averageCost);
                const cogs = avgCost.mul(absQuantity);
                const newQty = stock.quantityOnHand - absQuantity;

                await tx.inventoryStock.update({
                    where: { itemId: invTx.itemId },
                    data: { quantityOnHand: newQty },
                });

                await tx.inventoryTransaction.create({
                    data: {
                        workspaceId: invTx.workspaceId,
                        itemId: invTx.itemId,
                        transactionType: InventoryTransactionType.ADJUSTMENT,
                        quantity: -absQuantity,
                        unitCost: avgCost,
                        totalCost: cogs,
                        costOfGoodsSold: cogs,
                        referenceType,
                        referenceId,
                        notes: `Reversal: ${referenceType} ${referenceId} updated/deleted`,
                        createdById: invTx.createdById,
                    },
                });
            } else {
                // Original was stock-out → reverse = stock-in
                const returnUnitCost = new Decimal(invTx.unitCost);
                const totalCost = returnUnitCost.mul(absQuantity);

                // Recalculate WAC on stock-in reversal
                const currentQty = stock.quantityOnHand;
                const currentAvgCost = new Decimal(stock.averageCost);
                const totalExistingValue = currentAvgCost.mul(currentQty);
                const newTotalQty = currentQty + absQuantity;
                const newAvgCost = newTotalQty > 0
                    ? totalExistingValue.add(totalCost).div(newTotalQty)
                    : new Decimal(0);

                await tx.inventoryStock.update({
                    where: { itemId: invTx.itemId },
                    data: {
                        quantityOnHand: newTotalQty,
                        averageCost: newAvgCost,
                    },
                });

                await tx.inventoryTransaction.create({
                    data: {
                        workspaceId: invTx.workspaceId,
                        itemId: invTx.itemId,
                        transactionType: InventoryTransactionType.ADJUSTMENT,
                        quantity: absQuantity,
                        unitCost: returnUnitCost,
                        totalCost,
                        referenceType,
                        referenceId,
                        notes: `Reversal: ${referenceType} ${referenceId} updated/deleted`,
                        createdById: invTx.createdById,
                    },
                });
            }
        }
    }

    // ═══════════════════════════════════════════════════════
    // ─── Reporting (Read-Only) ─────────────────────────────
    // ═══════════════════════════════════════════════════════

    async getStockLevels(workspaceId: string) {
        const items = await this.repository.getStockLevels(workspaceId);
        return items.map(item => ({
            id: item.id,
            name: item.name,
            sku: item.sku,
            unit: item.unit,
            category: item.category,
            quantityOnHand: item.stock?.quantityOnHand ?? 0,
            averageCost: item.stock?.averageCost?.toString() ?? '0',
            inventoryValue: item.stock
                ? new Decimal(item.stock.averageCost).mul(item.stock.quantityOnHand).toString()
                : '0',
        }));
    }

    async getInventoryValuation(workspaceId: string) {
        const items = await this.repository.getStockLevels(workspaceId);
        let totalValue = new Decimal(0);

        const breakdown = items.map(item => {
            const value = item.stock
                ? new Decimal(item.stock.averageCost).mul(item.stock.quantityOnHand)
                : new Decimal(0);
            totalValue = totalValue.add(value);
            return {
                id: item.id,
                name: item.name,
                sku: item.sku,
                quantityOnHand: item.stock?.quantityOnHand ?? 0,
                averageCost: item.stock?.averageCost?.toString() ?? '0',
                value: value.toString(),
            };
        });

        return {
            totalValue: totalValue.toString(),
            itemCount: items.length,
            breakdown,
        };
    }

    async getStockMovementHistory(workspaceId: string, itemId: string) {
        // Verify item belongs to workspace
        const item = await this.repository.findItemById(itemId);
        if (!item || item.workspaceId !== workspaceId) {
            throw new NotFoundError('Inventory Item');
        }

        const { transactions } = await this.repository.findTransactionsByWorkspace(workspaceId, {
            skip: 0,
            take: 100,
            itemId,
            sortOrder: 'desc',
        });

        return {
            item: {
                id: item.id,
                name: item.name,
                sku: item.sku,
                unit: item.unit,
                currentStock: item.stock?.quantityOnHand ?? 0,
                averageCost: item.stock?.averageCost?.toString() ?? '0',
            },
            movements: transactions,
        };
    }

    async getCogsSummary(workspaceId: string, query: CogsReportQueryDto) {
        const transactions = await this.repository.getCogsSummary(
            workspaceId,
            query.startDate,
            query.endDate,
        );

        let totalCogs = new Decimal(0);
        for (const t of transactions) {
            if (t.costOfGoodsSold) {
                totalCogs = totalCogs.add(new Decimal(t.costOfGoodsSold));
            }
        }

        return {
            totalCostOfGoodsSold: totalCogs.toString(),
            transactionCount: transactions.length,
            transactions: transactions.map(t => ({
                id: t.id,
                itemName: t.item.name,
                itemSku: t.item.sku,
                transactionType: t.transactionType,
                quantity: t.quantity,
                costOfGoodsSold: t.costOfGoodsSold?.toString() ?? '0',
                createdAt: t.createdAt,
            })),
        };
    }

    async getLowStockAlerts(workspaceId: string) {
        const items = await this.repository.getLowStockItems(workspaceId);
        return items.map(item => ({
            id: item.id,
            name: item.name,
            sku: item.sku,
            unit: item.unit,
            quantityOnHand: item.stock?.quantityOnHand ?? 0,
            lowStockThreshold: item.lowStockThreshold,
            deficit: (item.lowStockThreshold ?? 0) - (item.stock?.quantityOnHand ?? 0),
        }));
    }

    // ═══════════════════════════════════════════════════════
    // ─── Helpers ───────────────────────────────────────────
    // ═══════════════════════════════════════════════════════

    private async validateReference(
        referenceType: InventoryReferenceType,
        referenceId: string,
        workspaceId: string,
    ) {
        switch (referenceType) {
            case InventoryReferenceType.ENTRY: {
                const entry = await this.prisma.entry.findUnique({ where: { id: referenceId } });
                if (!entry) throw new AppError('Referenced entry not found', 404, 'REFERENCE_NOT_FOUND');
                break;
            }
            case InventoryReferenceType.ACCOUNT_TRANSACTION: {
                const accTx = await this.prisma.accountTransaction.findUnique({ where: { id: referenceId } });
                if (!accTx || accTx.workspaceId !== workspaceId) {
                    throw new AppError('Referenced account transaction not found', 404, 'REFERENCE_NOT_FOUND');
                }
                break;
            }
            case InventoryReferenceType.OBLIGATION: {
                const obligation = await this.prisma.cashbookObligation.findUnique({ where: { id: referenceId } });
                if (!obligation || obligation.workspaceId !== workspaceId) {
                    throw new AppError('Referenced obligation not found', 404, 'REFERENCE_NOT_FOUND');
                }
                break;
            }
            case InventoryReferenceType.MANUAL:
                // No validation needed
                break;
        }
    }
}

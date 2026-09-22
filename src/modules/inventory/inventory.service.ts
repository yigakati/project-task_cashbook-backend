import { injectable, inject } from 'tsyringe';
import { PrismaClient, InventoryTransactionType, InventoryReferenceType, InventoryCostMethod } from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import { withFinancialTransaction } from '../../core/db/transaction';
import { InventoryRepository } from './inventory.repository';
import { AppError, NotFoundError } from '../../core/errors/AppError';
import { assertCashbookWritable } from '../cashbooks/cashbook-state';
import { AuditAction } from '../../core/types';
import {
    CreateInventoryItemDto,
    UpdateInventoryItemDto,
    InventoryItemQueryDto,
    CreateInventoryTransactionDto,
    InventoryTransactionQueryDto,
    InventoryLineItemDto,
    CogsReportQueryDto,
    AnalyticsQueryDto,
} from './inventory.dto';
import { assertSameCurrency, normalizeCurrency } from '../../core/finance';

// Stock-in transaction types (increase quantityOnHand)
const STOCK_IN_TYPES: InventoryTransactionType[] = [
    InventoryTransactionType.PURCHASE,
    InventoryTransactionType.TRANSFER_IN,
    InventoryTransactionType.RETURN_IN,
    InventoryTransactionType.RENTAL_IN,
];

// Stock-out transaction types (decrease quantityOnHand)
const STOCK_OUT_TYPES: InventoryTransactionType[] = [
    InventoryTransactionType.SALE,
    InventoryTransactionType.TRANSFER_OUT,
    InventoryTransactionType.RETURN_OUT,
    InventoryTransactionType.RENTAL_OUT,
    InventoryTransactionType.RENTAL_LOSS,
];

// ─── Internal cost resolution result ──────────────────────────────────────────
interface CostResolution {
    unitCost: Decimal;         // weighted average unit cost of the outflow
    cogs: Decimal;             // total COGS for the outflow
    lotConsumptions: Array<{   // for FIFO/LIFO audit trail
        lotId: string;
        quantityUsed: number;
        unitCost: Decimal;
    }>;
}

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
        const workspace = await this.prisma.workspace.findUnique({ where: { id: workspaceId } });
        if (!workspace || !workspace.isActive) {
            throw new NotFoundError('Workspace');
        }
        const workspaceCurrency = normalizeCurrency(workspace.defaultCurrency);
        if (dto.currency) {
            assertSameCurrency(workspaceCurrency, dto.currency, 'workspace base vs inventory item');
        }

        if (dto.sku) {
            const existing = await this.prisma.inventoryItem.findUnique({
                where: { workspaceId_sku: { workspaceId, sku: dto.sku } },
            });
            if (existing) {
                throw new AppError(`An item with SKU "${dto.sku}" already exists`, 409, 'DUPLICATE_SKU');
            }
        }

        // Costing is a sale concept: a cost method on a rent-only item is
        // meaningless (it never stocks out for sale) and only invites the
        // question "why is this here?". Refused rather than silently dropped.
        if (dto.commercialMode === 'RENT_ONLY' && dto.costMethod) {
            throw new AppError(
                'Rent-only items do not carry a cost method — costing applies to items that sell',
                400,
                'RENT_ONLY_HAS_NO_COST_METHOD',
            );
        }

        return this.prisma.$transaction(async (tx) => {
            const item = await tx.inventoryItem.create({
                data: {
                    workspaceId,
                    name: dto.name,
                    sku: dto.sku || null,
                    unit: dto.unit,
                    category: dto.category || null,
                    currency: workspaceCurrency,
                    commercialMode: (dto.commercialMode || 'SELL_ONLY') as any,
                    defaultSellingPrice: (dto.sellingPrice || dto.defaultSellingPrice)
                        ? new Decimal(dto.sellingPrice || dto.defaultSellingPrice!)
                        : null,
                    defaultRentalRate: dto.defaultRentalRate
                        ? new Decimal(dto.defaultRentalRate)
                        : null,
                    defaultRentalPeriodUnit: (dto.defaultRentalPeriodUnit as any) || null,
                    lowStockThreshold: dto.lowStockThreshold ?? null,
                    // Rent-only items carry no costing method of their own; the
                    // column stays non-null with its default so any legacy
                    // COGS read remains structurally safe.
                    costMethod: (dto.costMethod || 'WEIGHTED_AVERAGE') as any,
                    allowNegativeStock: dto.allowNegativeStock,
                },
            });

            let productServiceId: string | null = null;
            if (dto.createProductService) {
                const productServiceType = dto.productServiceType
                    || (dto.commercialMode === 'RENT_ONLY' ? 'SERVICE' : 'PRODUCT');
                if (dto.commercialMode !== 'RENT_ONLY' && productServiceType === 'SERVICE') {
                    throw new AppError('Sellable inventory should be catalogued as a PRODUCT', 400, 'SELLABLE_REQUIRES_PRODUCT');
                }
                const price =
                    dto.productServicePrice
                    || dto.sellingPrice
                    || dto.defaultSellingPrice
                    || dto.defaultRentalRate
                    || '0';
                const productService = await tx.productService.create({
                    data: {
                        workspaceId,
                        name: dto.productServiceName || dto.name,
                        description: dto.productServiceDescription || null,
                        price: new Decimal(price),
                        currency: workspaceCurrency,
                        type: productServiceType as any,
                        isSellable: true,
                        isBuyable: false,
                        inventoryItemId: item.id,
                    },
                });
                productServiceId = productService.id;
            }

            await tx.inventoryStock.create({
                data: {
                    itemId: item.id,
                    quantityOnHand: 0,
                    quantityRentedOut: 0,
                    averageCost: 0,
                },
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.INVENTORY_ITEM_CREATED as any,
                    resource: 'inventory_item',
                    resourceId: item.id,
                    details: { name: item.name, sku: item.sku, unit: item.unit, productServiceId } as any,
                },
            });

            return tx.inventoryItem.findUnique({
                where: { id: item.id },
                include: { stock: true, productsServices: true },
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
            isActive: query.isActive !== undefined ? query.isActive === 'true' : true,
            search: query.search,
            currency: query.currency,
            commercialMode: query.commercialMode,
            rentable: query.rentable === 'true' ? true : undefined,
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

    /**
     * The inventory page's metric cards: total active items, how many are
     * low on stock, and how many are rentable. Deliberately OVERLAPPING
     * dimensions, not partitions — a low-stock rentable item counts in all
     * three, because that is what each card asks. Computed server-side so
     * the numbers stay true regardless of any list pagination, and using
     * the same definitions as the reports (low stock = a configured
     * threshold at or below stock; rentable = RENT_ONLY or SELL_AND_RENT).
     */
    async getStats(workspaceId: string) {
        const [totalItems, rentable, lowStockItems] = await Promise.all([
            this.prisma.inventoryItem.count({
                where: { workspaceId, isActive: true },
            }),
            this.prisma.inventoryItem.count({
                where: {
                    workspaceId,
                    isActive: true,
                    commercialMode: { in: ['RENT_ONLY', 'SELL_AND_RENT'] },
                },
            }),
            this.repository.getLowStockItems(workspaceId),
        ]);
        return {
            totalItems,
            rentable,
            lowStock: lowStockItems.length,
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
        // A rent-only item never stocks out for sale, so a cost method on it
        // is meaningless — refuse rather than silently drop.
        if (dto.commercialMode === 'RENT_ONLY' && (dto as { costMethod?: string }).costMethod) {
            throw new AppError(
                'Rent-only items do not carry a cost method — costing applies to items that sell',
                400,
                'RENT_ONLY_HAS_NO_COST_METHOD',
            );
        }

        const item = await this.repository.findItemById(itemId);
        if (!item || item.workspaceId !== workspaceId) {
            throw new NotFoundError('Inventory Item');
        }
        if (dto.currency && dto.currency.toUpperCase() !== item.currency) {
            throw new AppError('Inventory item currency is locked to the workspace base currency', 400, 'BASE_CURRENCY_LOCKED');
        }

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
                    ...(dto.commercialMode !== undefined && { commercialMode: dto.commercialMode as any }),
                    ...(dto.defaultSellingPrice !== undefined && {
                        defaultSellingPrice: dto.defaultSellingPrice
                            ? new Decimal(dto.defaultSellingPrice)
                            : null,
                    }),
                    ...(dto.defaultRentalRate !== undefined && {
                        defaultRentalRate: dto.defaultRentalRate
                            ? new Decimal(dto.defaultRentalRate)
                            : null,
                    }),
                    ...(dto.defaultRentalPeriodUnit !== undefined && {
                        defaultRentalPeriodUnit: dto.defaultRentalPeriodUnit as any,
                    }),
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

        const sellingPrice = dto.sellingPrice ? new Decimal(dto.sellingPrice) : null;

        const refType = dto.referenceType
            ? dto.referenceType as InventoryReferenceType
            : InventoryReferenceType.MANUAL;

        if (isStockIn || transactionType === InventoryTransactionType.ADJUSTMENT) {
            // unitCost is required for stock-in — DTO refinement already enforces this,
            // but we add a runtime guard to maintain a clear error message if bypassed.
            if (!dto.unitCost) {
                throw new AppError(
                    'unitCost is required for stock-in transactions',
                    400,
                    'UNIT_COST_REQUIRED'
                );
            }
            return this.processStockIn(
                workspaceId,
                dto.itemId,
                transactionType,
                dto.quantity,
                new Decimal(dto.unitCost),
                userId,
                refType,
                dto.referenceId || null,
                dto.notes || null,
            );
        } else {
            // Stock-out: unitCost is irrelevant — COGS always comes from the cost method.
            // sellingPrice is optional but encouraged for gross-margin reporting.
            return this.processStockOut(
                workspaceId,
                dto.itemId,
                transactionType,
                dto.quantity,
                userId,
                refType,
                dto.referenceId || null,
                dto.notes || null,
                undefined,   // tx — none for manual transactions
                sellingPrice,
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
    // ─── Core Stock Operations (Atomic, ACID-safe) ─────────
    // ═══════════════════════════════════════════════════════

    /**
     * Process a stock-in operation (PURCHASE, TRANSFER_IN, RETURN_IN, ADJUSTMENT+).
     *
     * Strategy by costMethod:
     *  - WEIGHTED_AVERAGE: recalculates running average cost.
     *  - FIFO / LIFO: records the lot for future consumption tracking.
     *    averageCost is still maintained for stock-level reporting.
     *
     * All updates performed inside an atomic transaction (ACID compliant).
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
            // Use SELECT FOR UPDATE to prevent concurrent modification on the stock row
            await prisma.$queryRaw`
                SELECT id FROM inventory_stock WHERE item_id = ${itemId}::uuid FOR UPDATE
            `;

            const stock = await prisma.inventoryStock.findUnique({ where: { itemId } });
            if (!stock) {
                throw new AppError('Stock record not found. Item may be corrupted.', 500, 'STOCK_NOT_FOUND');
            }

            const item = await prisma.inventoryItem.findUnique({ where: { id: itemId } });
            const costMethod: InventoryCostMethod = item.costMethod;

            const currentQty = stock.quantityOnHand;
            const currentAvgCost = new Decimal(stock.averageCost);
            const isRentalIn = transactionType === InventoryTransactionType.RENTAL_IN;
            const effectiveUnitCost = isRentalIn ? new Decimal(0) : unitCost;
            const totalCost = effectiveUnitCost.mul(quantity);

            // Recalculate running WAC (skip for rental returns — cost unchanged)
            const totalExistingValue = currentAvgCost.mul(currentQty);
            const newTotalQty = currentQty + quantity;
            const newAvgCost = isRentalIn
                ? currentAvgCost
                : (newTotalQty > 0
                    ? totalExistingValue.add(totalCost).div(newTotalQty)
                    : new Decimal(0));

            // Update stock quantity and average cost
            await prisma.inventoryStock.update({
                where: { itemId },
                data: {
                    quantityOnHand: newTotalQty,
                    averageCost: newAvgCost,
                    ...(isRentalIn
                        ? {
                            quantityRentedOut: {
                                decrement: Math.min(quantity, stock.quantityRentedOut || 0),
                            },
                        }
                        : {}),
                },
            });

            // Create the inventory transaction record
            const invTransaction = await prisma.inventoryTransaction.create({
                data: {
                    workspaceId,
                    itemId,
                    transactionType,
                    quantity,           // positive for stock-in
                    unitCost: effectiveUnitCost,
                    totalCost,
                    referenceType,
                    referenceId,
                    notes,
                    createdById,
                },
            });

            // For FIFO/LIFO: record the lot so stock-out can consume in correct order
            // Rental returns do not create new cost lots
            if (
                !isRentalIn &&
                (costMethod === InventoryCostMethod.FIFO || costMethod === InventoryCostMethod.LIFO)
            ) {
                await prisma.inventoryLot.create({
                    data: {
                        workspaceId,
                        itemId,
                        unitCost: effectiveUnitCost,
                        quantityIn: quantity,
                        quantityRemaining: quantity,
                        transactionId: invTransaction.id,
                    },
                });
            }

            return invTransaction;
        };

        if (tx) return execute(tx);
        return this.prisma.$transaction(async (prisma) => execute(prisma));
    }

    /**
     * Process a stock-out operation (SALE, TRANSFER_OUT, RETURN_OUT, ADJUSTMENT-).
     *
     * Strategy by costMethod:
     *  - WEIGHTED_AVERAGE: unitCost = current averageCost. Simple, fast.
     *  - FIFO: consumes lots from oldest to newest (lowest createdAt first).
     *  - LIFO: consumes lots from newest to oldest (highest createdAt first).
     *
     * The `sellingPrice` parameter is purely informational (for gross-margin
     * reporting). It does NOT affect COGS calculation.
     *
     * All updates performed inside an atomic transaction (ACID compliant).
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
        sellingPrice: Decimal | null = null,
    ) {
        const execute = async (prisma: any) => {
            // Lock the stock row to prevent concurrent updates
            await prisma.$queryRaw`
                SELECT id FROM inventory_stock WHERE item_id = ${itemId}::uuid FOR UPDATE
            `;

            const stock = await prisma.inventoryStock.findUnique({ where: { itemId } });
            if (!stock) {
                throw new AppError('Stock record not found. Item may be corrupted.', 500, 'STOCK_NOT_FOUND');
            }

            const item = await prisma.inventoryItem.findUnique({ where: { id: itemId } });
            const costMethod: InventoryCostMethod = item.costMethod;

            // Negative stock guard. Reserved units — promised to pending
            // cross-workspace rental agreements — are on hand but not
            // available: the promise outranks a later sale or rental.
            const availableQty = stock.quantityOnHand - (stock.quantityReserved || 0);
            if (!item.allowNegativeStock && availableQty < quantity) {
                throw new AppError(
                    `Insufficient stock. Available: ${availableQty}, Requested: ${quantity}`,
                    400,
                    'INSUFFICIENT_STOCK'
                );
            }

            let cogsResolution: CostResolution;

            switch (costMethod) {
                case InventoryCostMethod.FIFO:
                    cogsResolution = await this.resolveCostFIFO(prisma, itemId, quantity, 'asc');
                    break;
                case InventoryCostMethod.LIFO:
                    cogsResolution = await this.resolveCostFIFO(prisma, itemId, quantity, 'lifo');
                    break;
                default: // WEIGHTED_AVERAGE
                    cogsResolution = this.resolveCostWAC(stock.averageCost, quantity);
            }

            const newQty = stock.quantityOnHand - quantity;
            const isRentalOut = transactionType === InventoryTransactionType.RENTAL_OUT;
            // Rentals are temporary: COGS not recognized as permanent sale cost
            const cogsForTx = isRentalOut ? new Decimal(0) : cogsResolution.cogs;
            const unitCostForTx = isRentalOut ? new Decimal(0) : cogsResolution.unitCost;

            // Update stock quantity (average cost unchanged on stock-out for all methods)
            await prisma.inventoryStock.update({
                where: { itemId },
                data: {
                    quantityOnHand: newQty,
                    ...(isRentalOut
                        ? { quantityRentedOut: { increment: quantity } }
                        : {}),
                },
            });

            // Create the transaction record
            const invTransaction = await prisma.inventoryTransaction.create({
                data: {
                    workspaceId,
                    itemId,
                    transactionType,
                    quantity: -quantity,            // negative for stock-out
                    unitCost: unitCostForTx,
                    totalCost: cogsForTx,
                    costOfGoodsSold: isRentalOut ? null : cogsForTx,
                    sellingPrice,
                    referenceType,
                    referenceId,
                    notes,
                    createdById,
                },
            });

            // For FIFO/LIFO: persist the lot consumption audit trail and update lot remainders
            if (
                (costMethod === InventoryCostMethod.FIFO || costMethod === InventoryCostMethod.LIFO) &&
                cogsResolution.lotConsumptions.length > 0
            ) {
                for (const consumption of cogsResolution.lotConsumptions) {
                    // Write the consumption record
                    await prisma.lotConsumption.create({
                        data: {
                            lotId: consumption.lotId,
                            transactionId: invTransaction.id,
                            quantityUsed: consumption.quantityUsed,
                            unitCost: consumption.unitCost,
                        },
                    });

                    // Decrement the lot's remaining quantity
                    await prisma.inventoryLot.update({
                        where: { id: consumption.lotId },
                        data: {
                            quantityRemaining: { decrement: consumption.quantityUsed },
                        },
                    });
                }
            }

            return invTransaction;
        };

        if (tx) return execute(tx);
        return this.prisma.$transaction(async (prisma) => execute(prisma));
    }

    // ═══════════════════════════════════════════════════════
    // ─── Private Cost Resolution Strategies ────────────────
    // ═══════════════════════════════════════════════════════

    /**
     * Weighted Average Cost: a single query-free calculation.
     * Pulls the running average from the already-loaded stock row.
     */
    private resolveCostWAC(averageCostRaw: any, quantity: number): CostResolution {
        const avgCost = new Decimal(averageCostRaw);
        const cogs = avgCost.mul(quantity);
        return {
            unitCost: avgCost,
            cogs,
            lotConsumptions: [],  // WAC does not track lots
        };
    }

    /**
     * FIFO / LIFO resolution.
     * Queries open lots sorted by createdAt ASC (FIFO) or DESC (LIFO).
     * Iterates through lots, consuming from each until the requested quantity
     * is satisfied. Returns the weighted average unit cost across all consumed lots
     * plus the individual lot consumption records for the audit trail.
     *
     * Performance: The compound index on (itemId, quantityRemaining) ensures only
     * open lots are returned quickly. We take only as many rows as needed.
     */
    private async resolveCostFIFO(
        prisma: any,
        itemId: string,
        quantity: number,
        order: 'asc' | 'lifo',
    ): Promise<CostResolution> {
        const sortOrder = order === 'lifo' ? 'desc' : 'asc';

        // Only fetch lots that still have remaining units
        const openLots = await prisma.inventoryLot.findMany({
            where: {
                itemId,
                quantityRemaining: { gt: 0 },
            },
            orderBy: { createdAt: sortOrder },
        });

        let remaining = quantity;
        let totalCogs = new Decimal(0);
        const consumptions: CostResolution['lotConsumptions'] = [];

        for (const lot of openLots) {
            if (remaining <= 0) break;

            const fromThisLot = Math.min(remaining, lot.quantityRemaining);
            const lotUnitCost = new Decimal(lot.unitCost);
            const lotCogs = lotUnitCost.mul(fromThisLot);

            consumptions.push({
                lotId: lot.id,
                quantityUsed: fromThisLot,
                unitCost: lotUnitCost,
            });

            totalCogs = totalCogs.add(lotCogs);
            remaining -= fromThisLot;
        }

        if (remaining > 0) {
            // Edge case: not enough lot data (e.g. item migrated from WAC or lots deleted)
            // Fall back to zero cost for the remainder to avoid a hard crash.
            // This can be surfaced as a warning in future iterations.
        }

        // Weighted-average unit cost across all consumed lots (for the unitCost column)
        const effectiveUnitCost = quantity > 0
            ? totalCogs.div(quantity)
            : new Decimal(0);

        return {
            unitCost: effectiveUnitCost,
            cogs: totalCogs,
            lotConsumptions: consumptions,
        };
    }

    // ═══════════════════════════════════════════════════════
    // ─── Integration Hooks (Called from Entries/AccTx) ──────
    // ═══════════════════════════════════════════════════════

    /**
     * Process inventory line items attached to a financial Entry.
     * - EXPENSE entry → PURCHASE (stock-in)
     * - INCOME entry  → SALE (stock-out), selling price = derived entry unit revenue
     */
    async processEntryInventory(
        tx: any,
        workspaceId: string,
        entryId: string,
        entryType: string,
        entryAmount: Decimal,
        inventoryItems: InventoryLineItemDto[],
        createdById: string,
        notes: string | null = null,
        expectedCurrency?: string,
    ) {
        const { assertSameCurrency } = await import('../../core/finance');
        const isPurchase = entryType === 'EXPENSE';
        const totalQtyAllItems = inventoryItems.reduce((sum, li) => sum + li.quantity, 0);

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
            if (expectedCurrency) {
                assertSameCurrency(expectedCurrency, item.currency, `inventory item "${item.name}"`);
            }
            // Cashbook entries are sell/purchase only — rentals go through invoices
            if (item.commercialMode === 'RENT_ONLY') {
                throw new AppError(
                    `Item "${item.name}" is rent-only. Record rentals via invoices, not cashbook entries.`,
                    400,
                    'RENT_VIA_INVOICE_ONLY',
                );
            }
            if (!isPurchase && item.commercialMode === 'RENT_ONLY') {
                throw new AppError(`Item "${item.name}" cannot be sold`, 400, 'ITEM_NOT_SELLABLE');
            }

            // For purchases, unitCost = acquisition cost
            let unitCostForIn: Decimal | null = null;
            if (isPurchase) {
                unitCostForIn = lineItem.unitCost
                    ? new Decimal(lineItem.unitCost)
                    : entryAmount.div(totalQtyAllItems);
            }

            // For sales, sellingPrice is: explicit per-line value > fallback to prorated entry amount
            const sellingPricePerUnit = !isPurchase
                ? (lineItem.sellingPrice
                    ? new Decimal(lineItem.sellingPrice)
                    : lineItem.unitCost
                        ? new Decimal(lineItem.unitCost)
                        : entryAmount.div(totalQtyAllItems))
                : null;

            if (isPurchase) {
                await this.processStockIn(
                    workspaceId,
                    lineItem.itemId,
                    InventoryTransactionType.PURCHASE,
                    lineItem.quantity,
                    unitCostForIn!,
                    createdById,
                    InventoryReferenceType.ENTRY,
                    entryId,
                    notes,
                    tx,
                );
            } else {
                await this.processStockOut(
                    workspaceId,
                    lineItem.itemId,
                    InventoryTransactionType.SALE,
                    lineItem.quantity,
                    createdById,
                    InventoryReferenceType.ENTRY,
                    entryId,
                    notes,
                    tx,
                    sellingPricePerUnit,
                );
            }
        }
    }

    /**
     * Process inventory line items attached to a direct AccountTransaction.
     */
    async processAccountTransactionInventory(
        tx: any,
        workspaceId: string,
        transactionId: string,
        transactionType: string,
        transactionAmount: Decimal,
        inventoryItems: InventoryLineItemDto[],
        createdById: string,
        notes: string | null = null,
        expectedCurrency?: string,
    ) {
        const { assertSameCurrency } = await import('../../core/finance');
        const isPurchase = transactionType === 'EXPENSE';
        const totalQtyAllItems = inventoryItems.reduce((sum, li) => sum + li.quantity, 0);

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
            if (expectedCurrency) {
                assertSameCurrency(expectedCurrency, item.currency, `inventory item "${item.name}"`);
            }
            if (item.commercialMode === 'RENT_ONLY') {
                throw new AppError(
                    `Item "${item.name}" is rent-only. Record rentals via invoices.`,
                    400,
                    'RENT_VIA_INVOICE_ONLY',
                );
            }

            const derivedAmount = lineItem.unitCost
                ? new Decimal(lineItem.unitCost)
                : transactionAmount.div(totalQtyAllItems);

            // sellingPrice: explicit per-line value > fallback to prorated transaction amount
            const sellingPricePerUnit = !isPurchase
                ? (lineItem.sellingPrice
                    ? new Decimal(lineItem.sellingPrice)
                    : derivedAmount)
                : null;

            if (isPurchase) {
                await this.processStockIn(
                    workspaceId,
                    lineItem.itemId,
                    InventoryTransactionType.PURCHASE,
                    lineItem.quantity,
                    derivedAmount,
                    createdById,
                    InventoryReferenceType.ACCOUNT_TRANSACTION,
                    transactionId,
                    notes,
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
                    notes,
                    tx,
                    sellingPricePerUnit,
                );
            }
        }
    }

    /**
     * Process inventory line items attached to a PAYABLE obligation.
     * Stocks in goods when a payable obligation is created.
     */
    async processObligationInventory(
        tx: any,
        workspaceId: string,
        obligationId: string,
        obligationAmount: Decimal,
        inventoryItems: InventoryLineItemDto[],
        createdById: string,
        notes: string | null = null,
        expectedCurrency?: string,
    ) {
        const { assertSameCurrency } = await import('../../core/finance');
        const totalQtyAllItems = inventoryItems.reduce((sum, li) => sum + li.quantity, 0);

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
            if (expectedCurrency) {
                assertSameCurrency(expectedCurrency, item.currency, `inventory item "${item.name}"`);
            }
            if (item.commercialMode === 'RENT_ONLY') {
                throw new AppError(
                    `Item "${item.name}" is rent-only. Record purchases of sellable stock only.`,
                    400,
                    'ITEM_NOT_SELLABLE',
                );
            }

            const unitCost = lineItem.unitCost
                ? new Decimal(lineItem.unitCost)
                : obligationAmount.div(totalQtyAllItems);

            await this.processStockIn(
                workspaceId,
                lineItem.itemId,
                InventoryTransactionType.PURCHASE,
                lineItem.quantity,
                unitCost,
                createdById,
                InventoryReferenceType.OBLIGATION,
                obligationId,
                notes,
                tx,
            );
        }
    }

    /**
     * Reverse all inventory transactions linked to a specific financial reference.
     * Creates compensating transactions (opposite direction) to restore stock.
     * FIFO/LIFO lots are restored by creating new lots with the original cost.
     */
    async reverseInventoryForReference(
        tx: any,
        referenceType: InventoryReferenceType,
        referenceId: string,
    ) {
        // Only original movements, never the compensating rows this function
        // itself writes. Reversal rows carry the SAME referenceType/referenceId
        // as what they undo, so without `isReversal: false` a second call would
        // re-read them and reverse the reversals — doubling stock and skewing
        // average cost. `reversedBy: null` makes the whole function idempotent:
        // reversing twice is a no-op rather than a corruption.
        const linkedTransactions = await tx.inventoryTransaction.findMany({
            where: { referenceType, referenceId, isReversal: false, reversedBy: null },
            orderBy: { createdAt: 'asc' },
        });

        if (linkedTransactions.length === 0) return;

        for (const invTx of linkedTransactions) {
            await tx.$queryRaw`
                SELECT id FROM inventory_stock WHERE item_id = ${invTx.itemId}::uuid FOR UPDATE
            `;

            const stock = await tx.inventoryStock.findUnique({ where: { itemId: invTx.itemId } });
            if (!stock) continue;

            const item = await tx.inventoryItem.findUnique({ where: { id: invTx.itemId } });
            const costMethod: InventoryCostMethod = item.costMethod;

            const absQuantity = Math.abs(invTx.quantity);
            const reversalNotes = `Reversal: ${referenceType} ${referenceId} updated/deleted`;

            if (invTx.quantity > 0) {
                // Original was stock-IN → reversal = stock-OUT
                // Use the transaction's own unitCost to avoid retroactively changing COGS history
                const unitCost = new Decimal(invTx.unitCost);
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
                        isReversal: true,
                        reversesTransactionId: invTx.id,
                        notes: reversalNotes,
                        createdById: invTx.createdById,
                    },
                });

                // For FIFO/LIFO: find and remove the lot that was created by this stock-in
                if (costMethod === InventoryCostMethod.FIFO || costMethod === InventoryCostMethod.LIFO) {
                    const lot = await tx.inventoryLot.findFirst({
                        where: { transactionId: invTx.id },
                    });
                    if (lot) {
                        // Reduce lot by the qty being reversed
                        const reducedRemaining = Math.max(0, lot.quantityRemaining - absQuantity);
                        await tx.inventoryLot.update({
                            where: { id: lot.id },
                            data: { quantityRemaining: reducedRemaining },
                        });
                    }
                }
            } else {
                // Original was stock-OUT → reversal = stock-IN (restore to stock)
                const returnUnitCost = new Decimal(invTx.unitCost);
                const totalCost = returnUnitCost.mul(absQuantity);

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

                const reversalInTx = await tx.inventoryTransaction.create({
                    data: {
                        workspaceId: invTx.workspaceId,
                        itemId: invTx.itemId,
                        transactionType: InventoryTransactionType.ADJUSTMENT,
                        quantity: absQuantity,
                        unitCost: returnUnitCost,
                        totalCost,
                        referenceType,
                        referenceId,
                        isReversal: true,
                        reversesTransactionId: invTx.id,
                        notes: reversalNotes,
                        createdById: invTx.createdById,
                    },
                });

                // For FIFO/LIFO: restore the lot inventory (re-open/create a lot)
                if (costMethod === InventoryCostMethod.FIFO || costMethod === InventoryCostMethod.LIFO) {
                    await tx.inventoryLot.create({
                        data: {
                            workspaceId: invTx.workspaceId,
                            itemId: invTx.itemId,
                            unitCost: returnUnitCost,
                            quantityIn: absQuantity,
                            quantityRemaining: absQuantity,
                            transactionId: reversalInTx.id,
                        },
                    });
                }
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
            costMethod: item.costMethod,
            quantityOnHand: item.stock?.quantityOnHand ?? 0,
            averageCost: item.stock?.averageCost?.toString() ?? '0',
            inventoryValue: item.stock
                ? new Decimal(item.stock.averageCost).mul(item.stock.quantityOnHand).toString()
                : '0',
        }));
    }

    async getInventoryValuation(workspaceId: string) {
        const items = await this.repository.getStockLevels(workspaceId);
        // Never mix currencies into one total (no FX). Prefer primary UGX total + byCurrency.
        const byCurrency = new Map<string, Decimal>();

        const breakdown = items.map(item => {
            const currency = (item as any).currency || 'UGX';
            const value = item.stock
                ? new Decimal(item.stock.averageCost).mul(item.stock.quantityOnHand)
                : new Decimal(0);
            byCurrency.set(currency, (byCurrency.get(currency) || new Decimal(0)).add(value));
            return {
                id: item.id,
                name: item.name,
                sku: item.sku,
                currency,
                costMethod: item.costMethod,
                quantityOnHand: item.stock?.quantityOnHand ?? 0,
                averageCost: item.stock?.averageCost?.toString() ?? '0',
                value: value.toString(),
            };
        });

        const byCurrencyArr = Array.from(byCurrency.entries()).map(([currency, total]) => ({
            currency,
            totalValue: total.toString(),
        }));
        // Primary total: UGX bucket if present, else first currency (honest single-currency figure)
        const ugx = byCurrency.get('UGX');
        const primary = ugx
            ? { currency: 'UGX', total: ugx }
            : byCurrencyArr[0]
                ? { currency: byCurrencyArr[0].currency, total: new Decimal(byCurrencyArr[0].totalValue) }
                : { currency: 'UGX', total: new Decimal(0) };

        return {
            totalValue: primary.total.toString(),
            currency: primary.currency,
            byCurrency: byCurrencyArr,
            mixedCurrencies: byCurrencyArr.length > 1,
            itemCount: items.length,
            breakdown,
        };
    }

    async getStockMovementHistory(workspaceId: string, itemId: string) {
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
                currency: item.currency,
                commercialMode: item.commercialMode,
                costMethod: item.costMethod,
                currentStock: item.stock?.quantityOnHand ?? 0,
                rentedOut: (item.stock as any)?.quantityRentedOut ?? 0,
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
        let totalRevenue = new Decimal(0);

        for (const t of transactions) {
            if (t.costOfGoodsSold) {
                totalCogs = totalCogs.add(new Decimal(t.costOfGoodsSold));
            }
            if ((t as any).sellingPrice) {
                const qty = Math.abs(t.quantity);
                totalRevenue = totalRevenue.add(new Decimal((t as any).sellingPrice).mul(qty));
            }
        }

        const grossProfit = totalRevenue.sub(totalCogs);

        return {
            totalCostOfGoodsSold: totalCogs.toString(),
            totalRevenue: totalRevenue.toString(),
            grossProfit: grossProfit.toString(),
            transactionCount: transactions.length,
            transactions: transactions.map(t => ({
                id: t.id,
                itemName: t.item.name,
                itemSku: t.item.sku,
                transactionType: t.transactionType,
                quantity: t.quantity,
                unitCost: t.unitCost.toString(),
                costOfGoodsSold: t.costOfGoodsSold?.toString() ?? '0',
                sellingPrice: (t as any).sellingPrice?.toString() ?? null,
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
    // ─── Item analytics ────────────────────────────────────
    // ═══════════════════════════════════════════════════════

    async getItemAnalytics(
        workspaceId: string,
        itemId: string,
        query?: { startDate?: string; endDate?: string },
    ) {
        const item = await this.repository.findItemById(itemId);
        if (!item || item.workspaceId !== workspaceId) {
            throw new NotFoundError('Inventory Item');
        }

        const where: any = { itemId, workspaceId };
        if (query?.startDate || query?.endDate) {
            where.createdAt = {};
            if (query.startDate) where.createdAt.gte = new Date(query.startDate);
            if (query.endDate) where.createdAt.lte = new Date(query.endDate);
        }

        const transactions = await this.prisma.inventoryTransaction.findMany({
            where,
            orderBy: { createdAt: 'asc' },
        });

        let unitsIn = 0;
        let unitsOut = 0;
        let totalPurchaseCost = new Decimal(0);
        let totalCogs = new Decimal(0);
        let totalSalesRevenue = new Decimal(0);
        const byTypeMap = new Map<string, { count: number; qty: number }>();

        for (const t of transactions) {
            const qty = Math.abs(t.quantity);
            const type = t.transactionType;
            if (!byTypeMap.has(type)) byTypeMap.set(type, { count: 0, qty: 0 });
            const bucket = byTypeMap.get(type)!;
            bucket.count += 1;
            bucket.qty += qty;

            if (t.quantity > 0) {
                unitsIn += t.quantity;
                if (type === InventoryTransactionType.PURCHASE) {
                    totalPurchaseCost = totalPurchaseCost.add(t.totalCost);
                }
            } else {
                unitsOut += qty;
                if (type === InventoryTransactionType.SALE) {
                    if (t.costOfGoodsSold) totalCogs = totalCogs.add(t.costOfGoodsSold);
                    if (t.sellingPrice) {
                        totalSalesRevenue = totalSalesRevenue.add(
                            new Decimal(t.sellingPrice).mul(qty),
                        );
                    }
                }
            }
        }

        const grossProfit = totalSalesRevenue.sub(totalCogs);
        const marginPct = totalSalesRevenue.greaterThan(0)
            ? grossProfit.div(totalSalesRevenue).mul(100)
            : null;

        const onHand = item.stock?.quantityOnHand ?? 0;
        const rentedOut = (item.stock as any)?.quantityRentedOut ?? 0;

        // Rental revenue from invoice lines of type RENTAL for this item
        const rentalLines = await this.prisma.invoiceItem.findMany({
            where: {
                inventoryItemId: itemId,
                lineType: 'RENTAL' as any,
                invoice: {
                    workspaceId,
                    status: { in: ['SENT', 'PARTIALLY_PAID', 'PAID', 'OVERDUE'] as any },
                },
            },
            select: { total: true, quantity: true },
        });
        let rentalBilled = new Decimal(0);
        for (const rl of rentalLines) {
            rentalBilled = rentalBilled.add(rl.total);
        }

        const activeRentals = await this.prisma.inventoryRentalLine.aggregate({
            where: {
                inventoryItemId: itemId,
                rental: { workspaceId, status: { in: ['ACTIVE', 'OVERDUE'] as any } },
            },
            _sum: { quantity: true },
        });

        return {
            itemId: item.id,
            currency: item.currency,
            period: {
                startDate: query?.startDate || null,
                endDate: query?.endDate || null,
            },
            stock: {
                onHand,
                rentedOut,
                availableToSell: onHand,
                availableToRent: Math.max(0, onHand),
            },
            sales: {
                unitsSold: byTypeMap.get(InventoryTransactionType.SALE)?.qty ?? 0,
                revenue: totalSalesRevenue.toString(),
                cogs: totalCogs.toString(),
                grossProfit: grossProfit.toString(),
                marginPct: marginPct ? marginPct.toFixed(2) : null,
            },
            purchases: {
                unitsIn: byTypeMap.get(InventoryTransactionType.PURCHASE)?.qty ?? 0,
                totalCost: totalPurchaseCost.toString(),
            },
            rentals: {
                activeQty: activeRentals._sum.quantity ?? 0,
                billedRevenue: rentalBilled.toString(),
            },
            movements: {
                unitsIn,
                unitsOut,
                byType: Array.from(byTypeMap.entries()).map(([type, v]) => ({
                    type,
                    count: v.count,
                    qty: v.qty,
                })),
            },
        };
    }

    /**
     * Process rental stock-out for invoice send (invoice-only rental path).
     */
    async processRentalOutForInvoice(
        tx: any,
        workspaceId: string,
        invoiceId: string,
        itemId: string,
        quantity: number,
        userId: string,
        notes: string,
        unitRate: Decimal,
        referenceType: 'INVOICE' | 'RENTAL' = 'INVOICE',
    ) {
        const item = await tx.inventoryItem.findUnique({
            where: { id: itemId },
            include: { stock: true },
        });
        if (!item || item.workspaceId !== workspaceId) {
            throw new AppError('Inventory item not found', 404, 'ITEM_NOT_FOUND');
        }
        if (item.commercialMode === 'SELL_ONLY') {
            throw new AppError(
                `Item "${item.name}" is sell-only and cannot be rented`,
                400,
                'ITEM_NOT_RENTABLE',
            );
        }
        await this.processStockOut(
            workspaceId,
            itemId,
            InventoryTransactionType.RENTAL_OUT,
            quantity,
            userId,
            InventoryReferenceType[referenceType],
            invoiceId,
            notes,
            tx,
            unitRate,
        );
    }

    /**
     * Return units from an active rental. Restores stock via RENTAL_IN.
     * Partial returns supported; full return marks rental RETURNED.
     */
    /**
     * A rental recorded and paid in one step — no invoice, no obligation.
     *
     * The walk-in rental desk: hand over the asset, take the money, done. The
     * rental row, its lines, the RENTAL_OUT stock movement and the INCOME
     * entry (with its journal and wallet movement) commit atomically, so the
     * books can never show stock out without the matching money in, or vice
     * versa. Invoice-driven rentals remain exactly as they were.
     */
    async createDirectRental(
        workspaceId: string,
        userId: string,
        dto: {
            customerId: string;
            cashbookId: string;
            itemId: string;
            quantity: number;
            unitRate: string;
            periodUnit: 'DAY' | 'WEEK' | 'MONTH';
            periodCount: number;
            startDate: string;
            endDate: string;
            /** Optional deposit collected on top of the rental charge. */
            depositAmount?: string;
            notes?: string;
            /** Wallet the payment landed in; omitted = book-cash entry. */
            accountId?: string;
        },
    ) {
        return withFinancialTransaction(this.prisma, async (tx) => {
            const workspace = await tx.workspace.findUniqueOrThrow({
                where: { id: workspaceId },
                select: { defaultCurrency: true, isActive: true },
            });
            if (!workspace.isActive) throw new NotFoundError('Workspace');

            const customer = await tx.contact.findFirst({
                where: { id: dto.customerId, workspaceId },
            });
            if (!customer) throw new NotFoundError('Customer');

            const cashbook = await tx.cashbook.findUnique({ where: { id: dto.cashbookId } });
            if (!cashbook || !cashbook.isActive || cashbook.workspaceId !== workspaceId) {
                throw new NotFoundError('Cashbook');
            }
            assertCashbookWritable(cashbook);

            const item = await tx.inventoryItem.findUnique({
                where: { id: dto.itemId },
                include: { stock: true },
            });
            if (!item || item.workspaceId !== workspaceId) {
                throw new NotFoundError('Inventory item');
            }
            if (item.commercialMode === 'SELL_ONLY') {
                throw new AppError(
                    `Item "${item.name}" is sell-only and cannot be rented`,
                    400,
                    'ITEM_NOT_RENTABLE',
                );
            }

            const rate = new Decimal(dto.unitRate);
            if (rate.lessThanOrEqualTo(0)) {
                throw new AppError('Rental rate must be greater than zero', 400, 'INVALID_RATE');
            }
            const periods = Math.max(1, Math.round(dto.periodCount));
            const qty = Math.round(dto.quantity);
            if (qty <= 0) {
                throw new AppError('Quantity must be at least 1', 400, 'INVALID_QUANTITY');
            }
            if (item.currency !== cashbook.currency) {
                throw new AppError(
                    `Item currency (${item.currency}) does not match cashbook (${cashbook.currency})`,
                    400,
                    'CURRENCY_MISMATCH',
                );
            }

            const lineTotal = rate.mul(qty).mul(periods);
            const deposit = dto.depositAmount ? new Decimal(dto.depositAmount) : new Decimal(0);
            const total = lineTotal.add(deposit);

            const rental = await tx.inventoryRental.create({
                data: {
                    workspaceId,
                    customerId: dto.customerId,
                    // No invoice: this rental was paid up front, in the book.
                    invoiceId: null,
                    status: 'ACTIVE' as any,
                    currency: cashbook.currency,
                    startDate: new Date(dto.startDate),
                    endDate: dto.endDate ? new Date(dto.endDate) : null,
                    depositAmount: deposit.greaterThan(0) ? deposit : null,
                    notes: dto.notes || 'Direct rental (paid on issue)',
                    createdById: userId,
                },
            });

            await tx.inventoryRentalLine.create({
                data: {
                    rentalId: rental.id,
                    inventoryItemId: item.id,
                    quantity: qty,
                    unitRate: rate,
                    periodUnit: dto.periodUnit,
                    periodCount: periods,
                    lineTotal,
                },
            });

            // The stock side: units leave as rented, COGS-free (same as the
            // invoice path's RENTAL_OUT).
            await this.processRentalOutForInvoice(
                tx,
                workspaceId,
                // referenceId doubles as the provenance for stock movement:
                // the rental itself, not an invoice.
                rental.id,
                item.id,
                qty,
                userId,
                `Rental out (direct, paid) for ${customer.name}`,
                rate,
                'RENTAL',
            );

            // The money side: an ordinary income entry through the ordinary
            // path, so the journal, wallet ledger and balances all behave.
            // Authority is enforced by createEntryWithin's own book checks
            // via the caller's route guard.
            // entries.service statically imports InventoryService, so a
            // constructor back-import would be a DI cycle. Resolve lazily from
            // the container (singleton) — the same dodge the entries module
            // uses for invoicing.
            const { container } = await import('tsyringe');
            const { EntriesService } = await import('../entries/entries.service');
            const entry = await container.resolve(EntriesService).createEntryWithin(
                tx,
                cashbook.id,
                userId,
                {
                    type: 'INCOME' as any,
                    amount: total.toFixed(4),
                    description: `Rental — ${item.name} × ${qty} (${periods} ${dto.periodUnit.toLowerCase()}${periods > 1 ? 's' : ''}) — ${customer.name}`,
                    accountId: dto.accountId,
                    contactId: dto.customerId,
                    entryDate: new Date(dto.startDate).toISOString(),
                } as any,
            );

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.INVENTORY_RENTAL_CREATED,
                    resource: 'inventory_rental',
                    resourceId: rental.id,
                    details: {
                        direct: true,
                        itemId: item.id,
                        customerId: dto.customerId,
                        entryId: entry.id,
                        lineTotal: lineTotal.toString(),
                        deposit: deposit.toString(),
                    } as any,
                },
            });

            return { rental, entry };
        });
    }

    async returnRental(
        workspaceId: string,
        rentalId: string,
        userId: string,
        dto?: { lineReturns?: Array<{ lineId: string; quantity: number }>; notes?: string },
    ) {
        const rental = await this.prisma.inventoryRental.findUnique({
            where: { id: rentalId },
            include: { lines: true },
        });
        if (!rental || rental.workspaceId !== workspaceId) {
            throw new NotFoundError('Rental');
        }
        if (rental.status !== 'ACTIVE' && rental.status !== 'OVERDUE') {
            throw new AppError(
                `Rental cannot be returned (status: ${rental.status})`,
                400,
                'RENTAL_NOT_ACTIVE',
            );
        }

        return this.prisma.$transaction(async (tx) => {
            const returns = dto?.lineReturns?.length
                ? dto.lineReturns
                : rental.lines.map((l) => ({
                    lineId: l.id,
                    quantity: l.quantity - l.quantityReturned,
                }));

            for (const ret of returns) {
                const line = rental.lines.find((l) => l.id === ret.lineId);
                if (!line) {
                    throw new AppError(`Rental line ${ret.lineId} not found`, 404, 'RENTAL_LINE_NOT_FOUND');
                }
                const outstanding = line.quantity - line.quantityReturned;
                if (ret.quantity <= 0 || ret.quantity > outstanding) {
                    throw new AppError(
                        `Invalid return qty for line (outstanding: ${outstanding}, requested: ${ret.quantity})`,
                        400,
                        'INVALID_RETURN_QTY',
                    );
                }

                await this.processStockIn(
                    workspaceId,
                    line.inventoryItemId,
                    InventoryTransactionType.RENTAL_IN,
                    ret.quantity,
                    new Decimal(0),
                    userId,
                    InventoryReferenceType.RENTAL,
                    rentalId,
                    dto?.notes || `Rental return for rental ${rentalId}`,
                    tx,
                );

                await tx.inventoryRentalLine.update({
                    where: { id: line.id },
                    data: { quantityReturned: line.quantityReturned + ret.quantity },
                });
            }

            const refreshed = await tx.inventoryRentalLine.findMany({ where: { rentalId } });
            const allReturned = refreshed.every((l) => l.quantityReturned >= l.quantity);

            const updated = await tx.inventoryRental.update({
                where: { id: rentalId },
                data: {
                    status: allReturned ? ('RETURNED' as any) : rental.status,
                    ...(allReturned ? { returnedAt: new Date() } : {}),
                },
                include: { lines: { include: { item: true } }, customer: true },
            });

            return updated;
        });
    }

    async listRentals(
        workspaceId: string,
        query?: { status?: string; itemId?: string; page?: number; limit?: number },
    ) {
        const page = Number(query?.page) || 1;
        const limit = Number(query?.limit) || 20;
        const skip = (page - 1) * limit;

        const where: any = { workspaceId };
        if (query?.status) where.status = query.status;
        if (query?.itemId) {
            where.lines = { some: { inventoryItemId: query.itemId } };
        }

        const [rentals, total] = await Promise.all([
            this.prisma.inventoryRental.findMany({
                where,
                include: {
                    lines: { include: { item: true } },
                    customer: { select: { id: true, name: true, email: true } },
                    invoice: { select: { id: true, invoiceNumber: true, status: true } },
                },
                orderBy: { createdAt: 'desc' },
                skip,
                take: limit,
            }),
            this.prisma.inventoryRental.count({ where }),
        ]);

        return {
            data: rentals,
            pagination: {
                page,
                limit,
                total,
                totalPages: Math.ceil(total / limit),
            },
        };
    }

    // ═══════════════════════════════════════════════════════
    // ─── Analytics ─────────────────────────────────────────
    // ═══════════════════════════════════════════════════════

    async getAnalyticsMetrics(workspaceId: string, query: AnalyticsQueryDto) {
        // High-level summary
        const [totalItemsCount, lowStockItems, valuationData, cogsData] = await Promise.all([
            this.prisma.inventoryItem.count({ where: { workspaceId, isActive: true } }),
            this.getLowStockAlerts(workspaceId),
            this.getInventoryValuation(workspaceId),
            this.getCogsSummary(workspaceId, { startDate: query.startDate, endDate: query.endDate })
        ]);

        return {
            totalInventoryValue: valuationData.totalValue,
            valuationCurrency: valuationData.currency,
            valuationByCurrency: valuationData.byCurrency,
            mixedCurrencies: valuationData.mixedCurrencies,
            totalItems: totalItemsCount,
            lowStockCount: lowStockItems.length,
            totalCogs: cogsData.totalCostOfGoodsSold,
            totalRevenue: cogsData.totalRevenue,
            grossProfit: cogsData.grossProfit,
        };
    }

    async getAnalyticsTrends(workspaceId: string, query: AnalyticsQueryDto) {
        // Fetch all relevant transactions first
        const transactions = await this.repository.getCogsSummary(workspaceId, query.startDate, query.endDate);
        
        // Group by requested interval map
        const trendsMap = new Map<string, {
            revenue: Decimal;
            cogs: Decimal;
            profit: Decimal;
            transactionCount: number;
        }>();

        // Sort ascending for chronological order
        transactions.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());

        for (const t of transactions) {
            const date = t.createdAt;
            let groupKey = '';

            if (query.interval === 'MONTHLY') {
                groupKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
            } else if (query.interval === 'WEEKLY') {
                // approximate ISO week or just start of week
                const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
                d.setUTCDate(d.getUTCDate() - d.getUTCDay() + 1); // Monday
                groupKey = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}`;
            } else {
                // DAILY
                groupKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
            }

            if (!trendsMap.has(groupKey)) {
                trendsMap.set(groupKey, {
                    revenue: new Decimal(0),
                    cogs: new Decimal(0),
                    profit: new Decimal(0),
                    transactionCount: 0,
                });
            }

            const current = trendsMap.get(groupKey)!;
            current.transactionCount += 1;

            if (t.costOfGoodsSold) {
                current.cogs = current.cogs.add(new Decimal(t.costOfGoodsSold));
            }
            if ((t as any).sellingPrice) {
                const qty = Math.abs(t.quantity);
                const rev = new Decimal((t as any).sellingPrice).mul(qty);
                current.revenue = current.revenue.add(rev);
            }

            current.profit = current.revenue.sub(current.cogs);
        }

        const data = Array.from(trendsMap.entries()).map(([label, values]) => ({
            label,
            totalRevenue: values.revenue.toString(),
            totalCogs: values.cogs.toString(),
            grossProfit: values.profit.toString(),
            transactionCount: values.transactionCount,
        }));

        return {
            interval: query.interval || 'DAILY',
            data,
        };
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
                break;
        }
    }
}

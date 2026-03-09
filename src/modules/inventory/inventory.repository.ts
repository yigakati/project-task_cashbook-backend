import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';

@injectable()
export class InventoryRepository {
    constructor(
        @inject('PrismaClient') private prisma: PrismaClient,
    ) { }

    // ─── Items ─────────────────────────────────────────

    async findItemById(id: string) {
        return this.prisma.inventoryItem.findUnique({
            where: { id },
            include: { stock: true },
        });
    }

    async findItemsByWorkspace(
        workspaceId: string,
        options: {
            skip: number;
            take: number;
            category?: string;
            isActive?: boolean;
            search?: string;
        }
    ) {
        const where: any = { workspaceId };

        if (options.category) {
            where.category = options.category;
        }

        if (options.isActive !== undefined) {
            where.isActive = options.isActive;
        }

        if (options.search) {
            where.OR = [
                { name: { contains: options.search, mode: 'insensitive' } },
                { sku: { contains: options.search, mode: 'insensitive' } },
            ];
        }

        const [items, total] = await Promise.all([
            this.prisma.inventoryItem.findMany({
                where,
                skip: options.skip,
                take: options.take,
                orderBy: { createdAt: 'desc' },
                include: { stock: true },
            }),
            this.prisma.inventoryItem.count({ where }),
        ]);

        return { items, total };
    }

    // ─── Transactions ──────────────────────────────────

    async findTransactionsByWorkspace(
        workspaceId: string,
        options: {
            skip: number;
            take: number;
            itemId?: string;
            transactionType?: string;
            startDate?: string;
            endDate?: string;
            sortOrder: 'asc' | 'desc';
        }
    ) {
        const where: any = { workspaceId };

        if (options.itemId) {
            where.itemId = options.itemId;
        }

        if (options.transactionType) {
            where.transactionType = options.transactionType;
        }

        if (options.startDate || options.endDate) {
            where.createdAt = {};
            if (options.startDate) where.createdAt.gte = new Date(options.startDate);
            if (options.endDate) where.createdAt.lte = new Date(options.endDate);
        }

        const [transactions, total] = await Promise.all([
            this.prisma.inventoryTransaction.findMany({
                where,
                skip: options.skip,
                take: options.take,
                orderBy: { createdAt: options.sortOrder },
                include: {
                    item: { select: { id: true, name: true, sku: true, unit: true } },
                },
            }),
            this.prisma.inventoryTransaction.count({ where }),
        ]);

        return { transactions, total };
    }

    // ─── Reports ───────────────────────────────────────

    async getStockLevels(workspaceId: string) {
        return this.prisma.inventoryItem.findMany({
            where: { workspaceId, isActive: true },
            include: { stock: true },
            orderBy: { name: 'asc' },
        });
    }

    async getLowStockItems(workspaceId: string) {
        // Get all items with a threshold configured where stock is at or below threshold
        const items = await this.prisma.inventoryItem.findMany({
            where: {
                workspaceId,
                isActive: true,
                lowStockThreshold: { not: null },
            },
            include: { stock: true },
        });

        return items.filter(item =>
            item.stock && item.lowStockThreshold !== null && item.stock.quantityOnHand <= item.lowStockThreshold
        );
    }

    async getCogsSummary(workspaceId: string, startDate?: string, endDate?: string) {
        const where: any = {
            workspaceId,
            transactionType: { in: ['SALE', 'RETURN_OUT'] },
            costOfGoodsSold: { not: null },
        };

        if (startDate || endDate) {
            where.createdAt = {};
            if (startDate) where.createdAt.gte = new Date(startDate);
            if (endDate) where.createdAt.lte = new Date(endDate);
        }

        const transactions = await this.prisma.inventoryTransaction.findMany({
            where,
            include: {
                item: { select: { id: true, name: true, sku: true, unit: true } },
            },
            orderBy: { createdAt: 'desc' },
        });

        return transactions;
    }
}

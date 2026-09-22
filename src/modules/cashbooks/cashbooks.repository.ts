import { injectable, inject } from 'tsyringe';
import { PrismaClient, Prisma } from '@prisma/client';

@injectable()
export class CashbooksRepository {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    async findById(id: string) {
        return this.prisma.cashbook.findUnique({
            where: { id },
            include: {
                workspace: {
                    select: { id: true, name: true, type: true, ownerId: true },
                },
                _count: {
                    select: {
                        entries: {
                            where: { isDeleted: false },
                        },
                        members: true,
                    },
                },
            },
        });
    }

    async findByWorkspaceId(workspaceId: string, includeArchived = false) {
        return this.prisma.cashbook.findMany({
            where: {
                workspaceId,
                isActive: true,
                // An archived book is retired, not deleted: it stays out of
                // the everyday list but can still be asked for explicitly.
                ...(includeArchived ? {} : { archivedAt: null }),
            },
            include: {
                _count: {
                    select: {
                        entries: { where: { isDeleted: false } },
                        members: true,
                    },
                },
            },
            orderBy: [{ archivedAt: { sort: 'asc', nulls: 'first' } }, { createdAt: 'desc' }],
        });
    }

    async create(data: Prisma.CashbookCreateInput) {
        return this.prisma.cashbook.create({
            data,
            include: {
                workspace: {
                    select: { id: true, name: true },
                },
            },
        });
    }

    async update(id: string, data: Prisma.CashbookUpdateInput) {
        return this.prisma.cashbook.update({
            where: { id },
            data,
            include: {
                workspace: {
                    select: { id: true, name: true },
                },
                _count: {
                    select: {
                        entries: { where: { isDeleted: false } },
                        members: true,
                    },
                },
            },
        });
    }

    async softDelete(id: string) {
        return this.prisma.cashbook.update({
            where: { id },
            data: { isActive: false },
        });
    }

    // NOTE: updateBalance/reverseBalance were removed here. They took `number`
    // amounts, ignored chargeAmount, and ignored wallet linkage, so they
    // contradicted the rules in src/core/finance/money.ts. They had no callers.
    // Cashbook balances are maintained only through cashbookIncrementPayload.

    async getFinancialSummary(cashbookId: string) {
        return this.prisma.cashbook.findUnique({
            where: { id: cashbookId },
            select: {
                id: true,
                name: true,
                currency: true,
                balance: true,
                totalIncome: true,
                totalExpense: true,
            },
        });
    }

    async findByIdWithMembers(id: string) {
        return this.prisma.cashbook.findUnique({
            where: { id },
            include: {
                members: {
                    include: {
                        user: {
                            select: { id: true, email: true, firstName: true, lastName: true },
                        },
                    },
                },
            },
        });
    }

    async isMember(cashbookId: string, userId: string) {
        return this.prisma.cashbookMember.findUnique({
            where: {
                cashbookId_userId: { cashbookId, userId },
            },
        });
    }

    async findUserAccessibleCashbooks(workspaceId: string, userId: string, includeArchived = false) {
        return this.prisma.cashbook.findMany({
            where: {
                workspaceId,
                isActive: true,
                ...(includeArchived ? {} : { archivedAt: null }),
                members: { some: { userId } },
            },
            include: {
                _count: {
                    select: {
                        entries: { where: { isDeleted: false } },
                        members: true,
                    },
                },
            },
            orderBy: [{ archivedAt: { sort: 'asc', nulls: 'first' } }, { createdAt: 'desc' }],
        });
    }

    async getMembers(cashbookId: string) {
        return this.prisma.cashbookMember.findMany({
            where: { cashbookId },
            include: {
                user: {
                    select: { id: true, email: true, firstName: true, lastName: true },
                },
            },
        });
    }

    async findMember(cashbookId: string, userId: string) {
        return this.prisma.cashbookMember.findUnique({
            where: {
                cashbookId_userId: { cashbookId, userId },
            },
        });
    }

    async addMember(cashbookId: string, userId: string, role: string) {
        return this.prisma.cashbookMember.create({
            data: { cashbookId, userId, role: role as any },
            include: {
                user: {
                    select: { id: true, email: true, firstName: true, lastName: true },
                },
            },
        });
    }

    async updateMemberRole(cashbookId: string, userId: string, role: string) {
        return this.prisma.cashbookMember.update({
            where: {
                cashbookId_userId: { cashbookId, userId },
            },
            data: { role: role as any },
            include: {
                user: {
                    select: { id: true, email: true, firstName: true, lastName: true },
                },
            },
        });
    }

    async removeMember(cashbookId: string, userId: string) {
        return this.prisma.cashbookMember.delete({
            where: {
                cashbookId_userId: { cashbookId, userId },
            },
        });
    }
}

import { injectable, inject } from 'tsyringe';
import { PrismaClient, Prisma } from '@prisma/client';

@injectable()
export class EntriesRepository {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }
    async findById(id: string) {
        return this.prisma.entry.findUnique({
            where: { id },
            include: {
                category: true,
                contact: true,
                paymentMode: true,
                createdBy: {
                    select: { id: true, email: true, firstName: true, lastName: true },
                },
                attachments: true,
                accountTransactions: {
                    select: {
                        account: {
                            select: {
                                id: true,
                                name: true,
                                accountType: { select: { id: true, name: true } }
                            }
                        }
                    }
                },
            },
        });
    }

    async findByCashbookId(
        cashbookId: string,
        params: {
            page: number;
            limit: number;
            type?: string;
            categoryId?: string;
            contactId?: string;
            paymentModeId?: string;
            startDate?: string;
            endDate?: string;
            sortBy: string;
            sortOrder: string;
        }
    ) {
        const {
            page: rawPage,
            limit: rawLimit,
            sortBy = 'entryDate',
            sortOrder = 'desc',
            ...filters
        } = params;

        const page = Number(rawPage) || 1;
        const limit = Number(rawLimit) || 20;

        const where: Prisma.EntryWhereInput = {
            cashbookId,
            isDeleted: false,
        };

        if (filters.type) where.type = filters.type as any;
        if (filters.categoryId) where.categoryId = filters.categoryId;
        if (filters.contactId) where.contactId = filters.contactId;
        if (filters.paymentModeId) where.paymentModeId = filters.paymentModeId;

        if (filters.startDate || filters.endDate) {
            where.entryDate = {};
            if (filters.startDate) where.entryDate.gte = new Date(filters.startDate);
            if (filters.endDate) where.entryDate.lte = new Date(filters.endDate);
        }

        const [entries, total] = await Promise.all([
            this.prisma.entry.findMany({
                where,
                include: {
                    category: { select: { id: true, name: true, color: true } },
                    contact: { select: { id: true, name: true } },
                    paymentMode: { select: { id: true, name: true } },
                    createdBy: {
                        select: { id: true, email: true, firstName: true, lastName: true },
                    },
                    _count: { select: { attachments: true } },
                    accountTransactions: {
                        select: {
                            account: {
                                select: {
                                    id: true,
                                    name: true,
                                    accountType: { select: { id: true, name: true } }
                                }
                            }
                        }
                    },
                },
                skip: (page - 1) * limit,
                take: limit,
                orderBy: { [sortBy]: sortOrder },
            }),
            this.prisma.entry.count({ where }),
        ]);

        return { entries, total };
    }

    async createEntryAudit(data: {
        entryId: string;
        userId: string;
        action: string;
        changes?: any;
        oldValues?: any;
        newValues?: any;
    }) {
        return this.prisma.entryAudit.create({ data: data as any });
    }

    async getEntryAudits(entryId: string) {
        return this.prisma.entryAudit.findMany({
            where: { entryId },
            include: {
                user: {
                    select: { id: true, email: true, firstName: true, lastName: true },
                },
            },
            orderBy: { createdAt: 'desc' },
        });
    }

    // ─── Delete Requests ───────────────────────────────
    async createDeleteRequest(data: {
        entryId: string;
        requesterId: string;
        reason: string;
    }) {
        return this.prisma.deleteRequest.create({
            data,
            include: {
                entry: true,
                requester: {
                    select: { id: true, email: true, firstName: true, lastName: true },
                },
            },
        });
    }

    async findDeleteRequestsByEntry(entryId: string) {
        return this.prisma.deleteRequest.findMany({
            where: { entryId },
            include: {
                requester: {
                    select: { id: true, email: true, firstName: true, lastName: true },
                },
                reviewer: {
                    select: { id: true, email: true, firstName: true, lastName: true },
                },
            },
            orderBy: { createdAt: 'desc' },
        });
    }

    async findDeleteRequestsByCashbook(cashbookId: string, status?: string) {
        const where: any = {
            entry: { cashbookId },
        };
        if (status) where.status = status;

        return this.prisma.deleteRequest.findMany({
            where,
            include: {
                entry: {
                    select: { id: true, description: true, amount: true, type: true },
                },
                requester: {
                    select: { id: true, email: true, firstName: true, lastName: true },
                },
                reviewer: {
                    select: { id: true, email: true, firstName: true, lastName: true },
                },
            },
            orderBy: { createdAt: 'desc' },
        });
    }

    async findDeleteRequestById(id: string) {
        return this.prisma.deleteRequest.findUnique({
            where: { id },
            include: {
                entry: {
                    include: {
                        cashbook: true,
                    },
                },
                requester: {
                    select: { id: true, email: true, firstName: true, lastName: true },
                },
            },
        });
    }

    async updateDeleteRequest(id: string, data: {
        status: string;
        reviewerId: string;
        reviewNote?: string;
    }) {
        return this.prisma.deleteRequest.update({
            where: { id },
            data: {
                status: data.status as any,
                reviewerId: data.reviewerId,
                reviewNote: data.reviewNote,
                reviewedAt: new Date(),
            },
        });
    }

    async findPendingDeleteRequest(entryId: string) {
        return this.prisma.deleteRequest.findFirst({
            where: { entryId, status: 'PENDING' },
        });
    }
}

import { injectable, inject } from 'tsyringe';
import { EntryStatus, PrismaClient, Prisma } from '@prisma/client';

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
                    where: { voidedAt: null },
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
            memberId?: string;
            /** A wallet id, or 'none' for entries that go through no wallet. */
            accountId?: string;
            search?: string;
            sortBy: string;
            sortOrder: string;
            /** Include reversed entries. Off by default, matching the old delete UX. */
            includeReversed?: boolean;
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
            // Reversed entries are hidden by default so the list looks exactly as
            // it did when deletes were destructive; they remain queryable, and
            // their journals always count in reports.
            ...(params.includeReversed ? {} : { status: EntryStatus.POSTED }),
        };

        if (filters.type) where.type = filters.type as any;
        if (filters.categoryId) where.categoryId = filters.categoryId;
        if (filters.contactId) where.contactId = filters.contactId;
        if (filters.paymentModeId) where.paymentModeId = filters.paymentModeId;
        if (filters.memberId) where.createdById = filters.memberId;

        // A wallet link is a live account_transactions row; a voided one is
        // history and no longer ties the entry to that wallet.
        if (filters.accountId === 'none') {
            where.accountTransactions = { none: { voidedAt: null } };
        } else if (filters.accountId) {
            where.accountTransactions = { some: { accountId: filters.accountId, voidedAt: null } };
        }

        if (filters.search) {
            const q = filters.search;
            const anyOf: Prisma.EntryWhereInput[] = [
                { description: { contains: q, mode: 'insensitive' } },
                { contact: { name: { contains: q, mode: 'insensitive' } } },
                { category: { name: { contains: q, mode: 'insensitive' } } },
                { paymentMode: { name: { contains: q, mode: 'insensitive' } } },
            ];
            // "25,000" and "25000" both find an entry of 25000.
            const numeric = q.replace(/,/g, '');
            if (/^\d+(\.\d+)?$/.test(numeric)) anyOf.push({ amount: { equals: numeric } });
            where.OR = anyOf;
        }

        if (filters.startDate || filters.endDate) {
            where.entryDate = {};
            if (filters.startDate) where.entryDate.gte = new Date(filters.startDate);
            if (filters.endDate) where.entryDate.lte = new Date(filters.endDate);
        }

        // Tie-breakers make the order total. Ordering by entryDate alone left
        // same-day entries in no defined order, so paging could show one twice
        // and skip another.
        const direction: Prisma.SortOrder = sortOrder === 'asc' ? 'asc' : 'desc';
        const orderBy: Prisma.EntryOrderByWithRelationInput[] = sortBy === 'createdAt'
            ? [{ createdAt: direction }, { id: direction }]
            : [{ [sortBy]: direction }, { createdAt: direction }, { id: direction }];

        const [entries, total, totals] = await Promise.all([
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
                        where: { voidedAt: null },
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
                orderBy,
            }),
            this.prisma.entry.count({ where }),
            // Totals across every matching entry, not just this page. Reversed
            // entries never count, even when they are being shown: a reversal
            // cancels its original, which is exactly how the book's own totals
            // treat it.
            this.prisma.entry.groupBy({
                by: ['type'],
                where: { ...where, status: EntryStatus.POSTED },
                _sum: { amount: true, chargeAmount: true },
                _count: { _all: true },
            }),
        ]);

        return { entries, total, totals };
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

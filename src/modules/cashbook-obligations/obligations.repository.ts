import { injectable, inject } from 'tsyringe';
import { PrismaClient, Prisma, ObligationStatus } from '@prisma/client';

@injectable()
export class ObligationsRepository {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    async findById(id: string) {
        return this.prisma.cashbookObligation.findUnique({
            where: { id },
            include: {
                entries: {
                    where: { isDeleted: false },
                    select: {
                        id: true,
                        amount: true,
                        entryDate: true,
                        description: true,
                    },
                    orderBy: { entryDate: 'desc' }
                }
            }
        });
    }

    async findByCashbookId(cashbookId: string, params: {
        page?: number;
        limit?: number;
        type?: string;
        status?: string;
        isOverdue?: boolean;
        sortBy?: string;
        sortOrder?: string;
        includeArchived?: boolean;
    }) {
        const page = params.page || 1;
        const limit = params.limit || 20;
        const sortBy = params.sortBy || 'createdAt';
        const sortOrder = params.sortOrder || 'desc';

        const where: Prisma.CashbookObligationWhereInput = {
            cashbookId,
        };

        if (!params.includeArchived) {
            where.archivedAt = null;
        }

        if (params.type) where.type = params.type as any;
        if (params.status) where.status = params.status as any;

        if (params.isOverdue) {
            where.dueDate = { lt: new Date() };
            where.status = { notIn: [ObligationStatus.PAID, ObligationStatus.CANCELLED] };
        }

        const [obligations, total] = await Promise.all([
            this.prisma.cashbookObligation.findMany({
                where,
                skip: (page - 1) * limit,
                take: limit,
                orderBy: { [sortBy]: sortOrder },
                include: {
                    _count: {
                        select: { entries: { where: { isDeleted: false } } }
                    }
                }
            }),
            this.prisma.cashbookObligation.count({ where }),
        ]);

        return { obligations, total };
    }

    async create(data: Prisma.CashbookObligationUncheckedCreateInput) {
        return this.prisma.cashbookObligation.create({ data });
    }

    async update(id: string, data: Prisma.CashbookObligationUncheckedUpdateInput) {
        return this.prisma.cashbookObligation.update({
            where: { id },
            data,
        });
    }
}

import { injectable } from 'tsyringe';
import { PrismaClient, Prisma, AccountTransaction, TransactionSourceType } from '@prisma/client';
import { getPrismaClient } from '../../config/database';

@injectable()
export class AccountTransactionsRepository {
    private prisma: PrismaClient;

    constructor() {
        this.prisma = getPrismaClient();
    }

    async findById(id: string): Promise<AccountTransaction | null> {
        return this.prisma.accountTransaction.findUnique({
            where: { id }
        });
    }

    async findAllByAccount(accountId: string, workspaceId: string, pagination?: { skip: number; take: number }): Promise<[number, AccountTransaction[]]> {
        const where = { accountId, workspaceId };

        const [total, data] = await Promise.all([
            this.prisma.accountTransaction.count({ where }),
            this.prisma.accountTransaction.findMany({
                where,
                orderBy: { createdAt: 'desc' },
                skip: pagination?.skip,
                take: pagination?.take,
                include: { accountCategory: true }
            })
        ]);

        return [total, data];
    }
}

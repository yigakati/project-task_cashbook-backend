import { injectable, inject } from 'tsyringe';
import { PrismaClient, Account, Prisma, AccountTransaction } from '@prisma/client';

export type AccountWithDetails = Prisma.AccountGetPayload<{
    include: { accountType: true }
}>;

@injectable()
export class AccountsRepository {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    async create(data: Prisma.AccountUncheckedCreateInput): Promise<AccountWithDetails> {
        return this.prisma.account.create({
            data,
            include: { accountType: true }
        });
    }

    async findAllByWorkspace(workspaceId: string): Promise<AccountWithDetails[]> {
        return this.prisma.account.findMany({
            where: { workspaceId },
            include: { accountType: true },
            orderBy: { name: 'asc' }
        });
    }

    async findById(id: string): Promise<AccountWithDetails | null> {
        return this.prisma.account.findUnique({
            where: { id },
            include: { accountType: true }
        });
    }

    async update(id: string, data: Prisma.AccountUpdateInput): Promise<AccountWithDetails> {
        return this.prisma.account.update({
            where: { id },
            data,
            include: { accountType: true }
        });
    }

    async delete(id: string): Promise<void> {
        await this.prisma.account.delete({
            where: { id }
        });
    }

    async findAccountTransactions(accountId: string, limit: number = 50): Promise<AccountTransaction[]> {
        return this.prisma.accountTransaction.findMany({
            where: { accountId },
            orderBy: { createdAt: 'desc' },
            take: limit
        });
    }

    async countTransactions(accountId: string): Promise<number> {
        return this.prisma.accountTransaction.count({
            where: { accountId }
        });
    }
}

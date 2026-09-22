import { injectable, inject } from 'tsyringe';
import { PrismaClient, Account, Prisma, AccountTransaction } from '@prisma/client';

/**
 * An account plus how much history hangs off it.
 *
 * The counts are what decide whether Delete can be offered at all: an account
 * with any activity can only be archived, so the client should never present
 * a button the server is bound to refuse.
 */
export type AccountWithDetails = Prisma.AccountGetPayload<{
    include: {
        accountType: true,
        _count: {
            select: {
                transactions: true,
                transfersFrom: true,
                transfersTo: true,
                ticketSales: true,
                expenseClaims: true,
            },
        },
    }
}>;

const ACCOUNT_INCLUDE = {
    accountType: true,
    _count: {
        select: {
            transactions: true,
            transfersFrom: true,
            transfersTo: true,
            ticketSales: true,
            expenseClaims: true,
        },
    },
} satisfies Prisma.AccountInclude;

@injectable()
export class AccountsRepository {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    async create(data: Prisma.AccountUncheckedCreateInput): Promise<AccountWithDetails> {
        return this.prisma.account.create({
            data,
            include: ACCOUNT_INCLUDE
        });
    }

    async findAllByWorkspace(workspaceId: string): Promise<AccountWithDetails[]> {
        return this.prisma.account.findMany({
            where: { workspaceId },
            include: ACCOUNT_INCLUDE,
            orderBy: { name: 'asc' }
        });
    }

    async findById(id: string): Promise<AccountWithDetails | null> {
        return this.prisma.account.findUnique({
            where: { id },
            include: ACCOUNT_INCLUDE
        });
    }

    async update(id: string, data: Prisma.AccountUpdateInput): Promise<AccountWithDetails> {
        return this.prisma.account.update({
            where: { id },
            data,
            include: ACCOUNT_INCLUDE
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

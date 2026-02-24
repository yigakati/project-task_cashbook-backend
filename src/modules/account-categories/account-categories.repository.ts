import { injectable, inject } from 'tsyringe';
import { PrismaClient, AccountCategory, Prisma } from '@prisma/client';

@injectable()
export class AccountCategoriesRepository {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    async create(data: Prisma.AccountCategoryUncheckedCreateInput): Promise<AccountCategory> {
        return this.prisma.accountCategory.create({ data });
    }

    async findAllByWorkspace(workspaceId: string): Promise<AccountCategory[]> {
        return this.prisma.accountCategory.findMany({
            where: { workspaceId },
            orderBy: { name: 'asc' }
        });
    }

    async findById(id: string): Promise<AccountCategory | null> {
        return this.prisma.accountCategory.findUnique({
            where: { id }
        });
    }

    async findByNameAndWorkspace(name: string, workspaceId: string): Promise<AccountCategory | null> {
        return this.prisma.accountCategory.findUnique({
            where: {
                name_workspaceId: {
                    name,
                    workspaceId
                }
            }
        });
    }

    async update(id: string, data: Prisma.AccountCategoryUpdateInput): Promise<AccountCategory> {
        return this.prisma.accountCategory.update({
            where: { id },
            data
        });
    }

    async delete(id: string): Promise<void> {
        await this.prisma.accountCategory.delete({
            where: { id }
        });
    }

    async countTransactionsByCategory(accountCategoryId: string): Promise<number> {
        return this.prisma.accountTransaction.count({
            where: { accountCategoryId }
        });
    }
}

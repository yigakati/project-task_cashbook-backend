import { injectable, inject } from 'tsyringe';
import { PrismaClient, AccountType, Prisma } from '@prisma/client';

@injectable()
export class AccountTypesRepository {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    async create(data: Prisma.AccountTypeUncheckedCreateInput): Promise<AccountType> {
        return this.prisma.accountType.create({ data });
    }

    async findAllByWorkspace(workspaceId: string): Promise<AccountType[]> {
        return this.prisma.accountType.findMany({
            where: { workspaceId },
            orderBy: { name: 'asc' }
        });
    }

    async findById(id: string): Promise<AccountType | null> {
        return this.prisma.accountType.findUnique({
            where: { id }
        });
    }

    async findByNameAndWorkspace(name: string, workspaceId: string): Promise<AccountType | null> {
        return this.prisma.accountType.findUnique({
            where: {
                name_workspaceId: {
                    name,
                    workspaceId
                }
            }
        });
    }

    async update(id: string, data: Prisma.AccountTypeUpdateInput): Promise<AccountType> {
        return this.prisma.accountType.update({
            where: { id },
            data
        });
    }

    async delete(id: string): Promise<void> {
        await this.prisma.accountType.delete({
            where: { id }
        });
    }

    async countAccountsByType(accountTypeId: string): Promise<number> {
        return this.prisma.account.count({
            where: { accountTypeId }
        });
    }
}

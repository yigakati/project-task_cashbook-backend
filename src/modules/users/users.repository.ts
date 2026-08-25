import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';

@injectable()
export class UsersRepository {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    async findById(id: string) {
        return this.prisma.user.findUnique({
            where: { id },
            select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                isActive: true,
                isSuperAdmin: true,
                emailVerified: true,
                lastLoginAt: true,
                createdAt: true,
                updatedAt: true,
                // Never returned as-is — users.service.ts#getProfile collapses
                // this to a `hasPassword` boolean before it reaches a response.
                passwordHash: true,
                linkedIdentities: { select: { provider: true } },
            },
        });
    }

    async updateProfile(id: string, data: { firstName?: string; lastName?: string }) {
        return this.prisma.user.update({
            where: { id },
            data,
            select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                isActive: true,
                emailVerified: true,
                lastLoginAt: true,
                createdAt: true,
                updatedAt: true,
                // Same shape as findById — kept identical so the response
                // here can be collapsed through the same hasPassword /
                // linkedProviders mapping in the service, rather than the
                // frontend's cache update silently dropping those fields.
                passwordHash: true,
                linkedIdentities: { select: { provider: true } },
            },
        });
    }

    async findAll(params: { page: number; limit: number; search?: string }) {
        const where: any = {};
        if (params.search) {
            where.OR = [
                { email: { contains: params.search, mode: 'insensitive' } },
                { firstName: { contains: params.search, mode: 'insensitive' } },
                { lastName: { contains: params.search, mode: 'insensitive' } },
            ];
        }

        const [users, total] = await Promise.all([
            this.prisma.user.findMany({
                where,
                select: {
                    id: true,
                    email: true,
                    firstName: true,
                    lastName: true,
                    isActive: true,
                    isSuperAdmin: true,
                    lastLoginAt: true,
                    createdAt: true,
                },
                skip: (params.page - 1) * params.limit,
                take: params.limit,
                orderBy: { createdAt: 'desc' },
            }),
            this.prisma.user.count({ where }),
        ]);

        return { users, total };
    }
}

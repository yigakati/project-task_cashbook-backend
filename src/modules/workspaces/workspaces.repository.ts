import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import { WorkspaceType, WorkspaceRole } from '../../core/types';

@injectable()
export class WorkspacesRepository {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    async findById(id: string) {
        return this.prisma.workspace.findUnique({
            where: { id },
            include: {
                owner: {
                    select: { id: true, email: true, firstName: true, lastName: true },
                },
                _count: { select: { members: true, cashbooks: true } },
            },
        });
    }

    async findByOwnerId(ownerId: string) {
        return this.prisma.workspace.findMany({
            where: { ownerId, isActive: true },
            include: {
                _count: { select: { members: true, cashbooks: true } },
            },
            orderBy: { createdAt: 'desc' },
        });
    }

    async findUserWorkspaces(userId: string) {
        const [owned, memberships] = await Promise.all([
            this.prisma.workspace.findMany({
                where: { ownerId: userId, isActive: true },
                include: {
                    owner: {
                        select: { id: true, email: true, firstName: true, lastName: true },
                    },
                    // What a superadmin has unlocked here. Carried on the
                    // workspace the client already loads, so hiding an action
                    // it was never granted costs no extra request.
                    features: { select: { feature: true, enabledAt: true } },
                    _count: { select: { members: true, cashbooks: true } },
                },
            }),
            this.prisma.workspaceMember.findMany({
                where: { userId },
                include: {
                    workspace: {
                        include: {
                            owner: {
                                select: { id: true, email: true, firstName: true, lastName: true },
                            },
                            features: { select: { feature: true, enabledAt: true } },
                            _count: { select: { members: true, cashbooks: true } },
                        },
                    },
                },
            }),
        ]);

        const memberWorkspaces = memberships
            .filter((m) => m.workspace.isActive)
            .map((m) => ({
                ...m.workspace,
                memberRole: m.role,
            }));

        return {
            owned: owned.map((w) => ({ ...w, memberRole: 'OWNER' })),
            member: memberWorkspaces,
        };
    }

    async create(data: {
        name: string;
        type: WorkspaceType;
        ownerId: string;
        defaultCurrency?: string;
    }) {
        return this.prisma.workspace.create({
            data,
            include: {
                owner: {
                    select: { id: true, email: true, firstName: true, lastName: true },
                },
            },
        });
    }

    async update(id: string, data: { name?: string; defaultCurrency?: string }) {
        return this.prisma.workspace.update({
            where: { id },
            data,
            include: {
                owner: {
                    select: { id: true, email: true, firstName: true, lastName: true },
                },
                _count: { select: { members: true, cashbooks: true } },
            },
        });
    }

    async softDelete(id: string) {
        return this.prisma.workspace.update({
            where: { id },
            data: { isActive: false },
        });
    }

    async getPersonalWorkspace(userId: string) {
        return this.prisma.workspace.findFirst({
            where: {
                ownerId: userId,
                type: WorkspaceType.PERSONAL,
                isActive: true,
            },
        });
    }
}

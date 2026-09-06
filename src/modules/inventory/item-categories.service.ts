import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import { AppError, NotFoundError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';

/**
 * The workspace's item-category vocabulary.
 *
 * Items store categories as free text (the historical column), so this
 * service's job is to curate the vocabulary the item form suggests from —
 * deduplicated, renameable — rather than to enforce a foreign key. A category
 * referenced by items cannot be deleted, because the name is the join.
 */
@injectable()
export class ItemCategoriesService {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    async list(workspaceId: string) {
        return this.prisma.itemCategory.findMany({
            where: { workspaceId },
            orderBy: [{ name: 'asc' }],
        });
    }

    async create(workspaceId: string, userId: string, name: string) {
        const trimmed = name.trim();
        if (!trimmed) {
            throw new AppError('Category name is required', 400, 'CATEGORY_NAME_REQUIRED');
        }
        if (trimmed.length > 60) {
            throw new AppError('Category name must be at most 60 characters', 400, 'CATEGORY_NAME_TOO_LONG');
        }

        const existing = await this.prisma.itemCategory.findUnique({
            where: { workspaceId_name: { workspaceId, name: trimmed } },
        });
        if (existing) {
            // Idempotent by design: the item form's suggestions fire this on
            // every pick, so re-selecting an existing category must not 409.
            return existing;
        }

        const category = await this.prisma.itemCategory.create({
            data: { workspaceId, name: trimmed },
        });

        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.ITEM_CATEGORY_CREATED,
                resource: 'item_category',
                resourceId: category.id,
                details: { name: trimmed } as any,
            },
        });

        return category;
    }

    async rename(categoryId: string, workspaceId: string, userId: string, name: string) {
        const trimmed = name.trim();
        if (!trimmed) {
            throw new AppError('Category name is required', 400, 'CATEGORY_NAME_REQUIRED');
        }
        if (trimmed.length > 60) {
            throw new AppError('Category name must be at most 60 characters', 400, 'CATEGORY_NAME_TOO_LONG');
        }

        const existing = await this.prisma.itemCategory.findUnique({ where: { id: categoryId } });
        if (!existing || existing.workspaceId !== workspaceId) {
            throw new NotFoundError('Item category');
        }

        const clash = await this.prisma.itemCategory.findUnique({
            where: { workspaceId_name: { workspaceId, name: trimmed } },
        });
        if (clash && clash.id !== categoryId) {
            throw new AppError(`Category "${trimmed}" already exists in this workspace`, 409, 'DUPLICATE_CATEGORY');
        }

        return this.prisma.$transaction(async (tx) => {
            const category = await tx.itemCategory.update({
                where: { id: categoryId },
                data: { name: trimmed },
            });

            // Items reference categories by name; a rename keeps them in step
            // so the vocabulary and the items never drift apart.
            if (existing.name !== trimmed) {
                await tx.inventoryItem.updateMany({
                    where: { workspaceId, category: existing.name },
                    data: { category: trimmed },
                });
            }

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.ITEM_CATEGORY_UPDATED,
                    resource: 'item_category',
                    resourceId: categoryId,
                    details: { from: existing.name, to: trimmed } as any,
                },
            });

            return category;
        });
    }

    async remove(categoryId: string, workspaceId: string, userId: string) {
        const existing = await this.prisma.itemCategory.findUnique({ where: { id: categoryId } });
        if (!existing || existing.workspaceId !== workspaceId) {
            throw new NotFoundError('Item category');
        }

        const inUse = await this.prisma.inventoryItem.count({
            where: { workspaceId, category: existing.name },
        });
        if (inUse > 0) {
            throw new AppError(
                `Category "${existing.name}" is used by ${inUse} item${inUse === 1 ? '' : 's'} and cannot be deleted`,
                409,
                'CATEGORY_IN_USE',
            );
        }

        await this.prisma.$transaction(async (tx) => {
            await tx.itemCategory.delete({ where: { id: categoryId } });
            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.ITEM_CATEGORY_DELETED,
                    resource: 'item_category',
                    resourceId: categoryId,
                    details: { name: existing.name } as any,
                },
            });
        });
    }
}

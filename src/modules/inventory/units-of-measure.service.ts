import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import { AppError, NotFoundError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';

/**
 * The workspace's unit-of-measure vocabulary.
 *
 * Items store units as free text (the historical column), so this service's
 * job is to curate the vocabulary the UI suggests from — deduplicated,
 * renameable — rather than to enforce a foreign key. A unit referenced by
 * items cannot be deleted, because the name is the join.
 */
@injectable()
export class UnitsOfMeasureService {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    async list(workspaceId: string) {
        return this.prisma.unitOfMeasure.findMany({
            where: { workspaceId },
            orderBy: [{ name: 'asc' }],
        });
    }

    async create(workspaceId: string, userId: string, name: string) {
        const trimmed = name.trim();
        if (!trimmed) {
            throw new AppError('Unit name is required', 400, 'UNIT_NAME_REQUIRED');
        }
        if (trimmed.length > 50) {
            throw new AppError('Unit name must be at most 50 characters', 400, 'UNIT_NAME_TOO_LONG');
        }

        const existing = await this.prisma.unitOfMeasure.findUnique({
            where: { workspaceId_name: { workspaceId, name: trimmed } },
        });
        if (existing) {
            // Idempotent by design: the item form's suggestions fire this on
            // every pick, so re-selecting an existing unit must not 409.
            return existing;
        }

        const unit = await this.prisma.unitOfMeasure.create({
            data: { workspaceId, name: trimmed },
        });

        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.INVENTORY_UNIT_CREATED,
                resource: 'unit_of_measure',
                resourceId: unit.id,
                details: { name: trimmed } as any,
            },
        });

        return unit;
    }

    async rename(unitId: string, workspaceId: string, userId: string, name: string) {
        const trimmed = name.trim();
        if (!trimmed) {
            throw new AppError('Unit name is required', 400, 'UNIT_NAME_REQUIRED');
        }

        const existing = await this.prisma.unitOfMeasure.findUnique({ where: { id: unitId } });
        if (!existing || existing.workspaceId !== workspaceId) {
            throw new NotFoundError('Unit of measure');
        }

        const clash = await this.prisma.unitOfMeasure.findUnique({
            where: { workspaceId_name: { workspaceId, name: trimmed } },
        });
        if (clash && clash.id !== unitId) {
            throw new AppError(`Unit "${trimmed}" already exists in this workspace`, 409, 'DUPLICATE_UNIT');
        }

        return this.prisma.$transaction(async (tx) => {
            const unit = await tx.unitOfMeasure.update({
                where: { id: unitId },
                data: { name: trimmed },
            });

            // Items reference units by name; a rename keeps them in step so
            // the vocabulary and the items never drift apart.
            if (existing.name !== trimmed) {
                await tx.inventoryItem.updateMany({
                    where: { workspaceId, unit: existing.name },
                    data: { unit: trimmed },
                });
            }

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.INVENTORY_UNIT_UPDATED,
                    resource: 'unit_of_measure',
                    resourceId: unitId,
                    details: { from: existing.name, to: trimmed } as any,
                },
            });

            return unit;
        });
    }

    async remove(unitId: string, workspaceId: string, userId: string) {
        const existing = await this.prisma.unitOfMeasure.findUnique({ where: { id: unitId } });
        if (!existing || existing.workspaceId !== workspaceId) {
            throw new NotFoundError('Unit of measure');
        }

        const inUse = await this.prisma.inventoryItem.count({
            where: { workspaceId, unit: existing.name },
        });
        if (inUse > 0) {
            throw new AppError(
                `Unit "${existing.name}" is used by ${inUse} item${inUse === 1 ? '' : 's'} and cannot be deleted`,
                409,
                'UNIT_IN_USE',
            );
        }

        await this.prisma.$transaction(async (tx) => {
            await tx.unitOfMeasure.delete({ where: { id: unitId } });
            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.INVENTORY_UNIT_DELETED,
                    resource: 'unit_of_measure',
                    resourceId: unitId,
                    details: { name: existing.name } as any,
                },
            });
        });
    }
}

import { injectable, inject } from 'tsyringe';
import { PrismaClient, ObligationStatus, ObligationType, InventoryReferenceType } from '@prisma/client';
import { ObligationsRepository } from './obligations.repository';
import {
    CreateObligationDto,
    UpdateObligationDto,
    ObligationQueryDto,
} from './obligations.dto';
import { NotFoundError, AppError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';
import { Decimal } from '@prisma/client/runtime/library';
import { InventoryService } from '../inventory/inventory.service';

@injectable()
export class ObligationsService {
    constructor(
        private obligationsRepo: ObligationsRepository,
        @inject('PrismaClient') private prisma: PrismaClient,
        private inventoryService: InventoryService,
    ) { }

    // ─── List Obligations ──────────────────────────────
    async getObligations(cashbookId: string, query: ObligationQueryDto) {
        const { obligations, total } = await this.obligationsRepo.findByCashbookId(cashbookId, query);
        const totalPages = Math.ceil(total / query.limit);

        return {
            data: obligations,
            pagination: {
                page: query.page,
                limit: query.limit,
                total,
                totalPages,
                hasNext: query.page < totalPages,
                hasPrevious: query.page > 1,
            }
        };
    }

    // ─── Get Single Obligation ─────────────────────────
    async getObligation(id: string, cashbookId: string) {
        const obligation = await this.obligationsRepo.findById(id);
        if (!obligation) throw new NotFoundError('Obligation');

        // Verify obligation belongs to the cashbook the user has access to
        if (obligation.cashbookId !== cashbookId) {
            throw new NotFoundError('Obligation');
        }

        return obligation;
    }

    // ─── Create Obligation ─────────────────────────────
    async createObligation(cashbookId: string, userId: string, dto: CreateObligationDto) {
        const cashbook = await this.prisma.cashbook.findUnique({
            where: { id: cashbookId },
            select: { workspaceId: true, isActive: true }
        });

        if (!cashbook || !cashbook.isActive) {
            throw new NotFoundError('Cashbook');
        }

        const amount = new Decimal(dto.totalAmount);

        const obligation = await this.prisma.$transaction(async (tx) => {
            const newObligation = await tx.cashbookObligation.create({
                data: {
                    workspaceId: cashbook.workspaceId,
                    cashbookId,
                    type: dto.type as any,
                    title: dto.title,
                    description: dto.description || null,
                    totalAmount: amount,
                    outstandingAmount: amount, // Initialize to total amount
                    status: ObligationStatus.OPEN,
                    dueDate: dto.dueDate ? new Date(dto.dueDate) : null,
                }
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: cashbook.workspaceId,
                    action: AuditAction.OBLIGATION_CREATED,
                    resource: 'obligation',
                    resourceId: newObligation.id,
                    details: {
                        type: dto.type,
                        totalAmount: dto.totalAmount,
                        title: dto.title
                    } as any
                }
            });

            // ─── Inventory Integration ──────────────────────────────
            // For PAYABLE obligations (goods purchases), stock-in the items
            if (dto.inventoryItems && dto.inventoryItems.length > 0 && dto.type === ObligationType.PAYABLE) {
                await this.inventoryService.processObligationInventory(
                    tx,
                    cashbook.workspaceId,
                    newObligation.id,
                    amount,
                    dto.inventoryItems,
                    userId,
                );
            }

            return newObligation;
        });

        return obligation;
    }

    // ─── Update Obligation ─────────────────────────────
    async updateObligation(id: string, cashbookId: string, userId: string, dto: UpdateObligationDto) {
        const existing = await this.obligationsRepo.findById(id);
        if (!existing || existing.archivedAt) {
            throw new NotFoundError('Obligation');
        }

        // Verify obligation belongs to the cashbook the user has access to
        if (existing.cashbookId !== cashbookId) {
            throw new NotFoundError('Obligation');
        }

        const updated = await this.prisma.$transaction(async (tx) => {
            const obligation = await tx.cashbookObligation.update({
                where: { id },
                data: {
                    ...(dto.title && { title: dto.title }),
                    ...(dto.description !== undefined && { description: dto.description }),
                    ...(dto.dueDate !== undefined && { dueDate: dto.dueDate ? new Date(dto.dueDate) : null }),
                }
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: obligation.workspaceId,
                    action: AuditAction.OBLIGATION_UPDATED,
                    resource: 'obligation',
                    resourceId: id,
                    details: dto as any
                }
            });

            return obligation;
        });

        return updated;
    }

    // ─── Archive Obligation ────────────────────────────
    async archiveObligation(id: string, cashbookId: string, userId: string) {
        const existing = await this.obligationsRepo.findById(id);
        if (!existing) {
            throw new NotFoundError('Obligation');
        }

        // Verify obligation belongs to the cashbook the user has access to
        if (existing.cashbookId !== cashbookId) {
            throw new NotFoundError('Obligation');
        }

        if (existing.status !== ObligationStatus.OPEN && existing.status !== ObligationStatus.CANCELLED && existing.status !== ObligationStatus.PAID) {
            // we permit archiving PAID and CANCELLED, but not PARTIAL as it's mid-settlement
            throw new AppError('Cannot archive an obligation that is partially paid', 400, 'INVALID_STATUS');
        }

        if (existing.archivedAt) {
            throw new AppError('Obligation is already archived', 400, 'ALREADY_ARCHIVED');
        }

        const updated = await this.prisma.$transaction(async (tx) => {
            const obligation = await tx.cashbookObligation.update({
                where: { id },
                data: { archivedAt: new Date() }
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId: obligation.workspaceId,
                    action: AuditAction.OBLIGATION_ARCHIVED,
                    resource: 'obligation',
                    resourceId: id,
                }
            });

            return obligation;
        });

        return updated;
    }

    // ─── Reporting ──────────────────────────────────────────

    async getOutstandingReceivables(cashbookId: string) {
        const aggregations = await this.prisma.cashbookObligation.aggregate({
            where: {
                cashbookId,
                type: ObligationType.RECEIVABLE,
                status: { in: [ObligationStatus.OPEN, ObligationStatus.PARTIAL] },
                archivedAt: null
            },
            _sum: { outstandingAmount: true },
            _count: { id: true }
        });
        return {
            totalAmount: aggregations._sum.outstandingAmount || new Decimal(0),
            count: aggregations._count.id
        };
    }

    async getOutstandingPayables(cashbookId: string) {
        const aggregations = await this.prisma.cashbookObligation.aggregate({
            where: {
                cashbookId,
                type: ObligationType.PAYABLE,
                status: { in: [ObligationStatus.OPEN, ObligationStatus.PARTIAL] },
                archivedAt: null
            },
            _sum: { outstandingAmount: true },
            _count: { id: true }
        });
        return {
            totalAmount: aggregations._sum.outstandingAmount || new Decimal(0),
            count: aggregations._count.id
        };
    }
}

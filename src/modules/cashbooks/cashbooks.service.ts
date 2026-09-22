import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import crypto from 'crypto';
import { CashbooksRepository } from './cashbooks.repository';
import {
    NotFoundError,
    ConflictError,
    AuthorizationError,
    AppError,
} from '../../core/errors/AppError';
import {
    AuditAction,
    CashbookRole,
    WorkspaceRole,
    WorkspaceType,
} from '../../core/types';
import {
    WorkspacePermission,
    hasWorkspacePermission,
} from '../../core/types/workspace-permissions';
import { assertSameCurrency, normalizeCurrency } from '../../core/finance';
import {
    ensureCashbookLedgerAccount,
    provisionWorkspaceAccounting,
} from '../../core/ledger/coa.seed';
import {
    CreateCashbookDto,
    UpdateCashbookDto,
    AddCashbookMemberDto,
    UpdateCashbookMemberRoleDto,
} from './cashbooks.dto';

@injectable()
export class CashbooksService {
    constructor(
        private cashbooksRepository: CashbooksRepository,
        @inject('PrismaClient') private prisma: PrismaClient,
    ) { }

    /**
     * Whether each book can still be deleted, and how much history it holds.
     *
     * Deleting is only for a book that never recorded anything, so the
     * question is whether any entry exists at all — including ones since
     * deleted, because a reversed or removed entry is still this book's
     * history. One grouped query answers it for the whole list.
     */
    private async withDeletability<T extends { id: string }>(cashbooks: T[]) {
        if (cashbooks.length === 0) return [];

        const counts = await this.prisma.entry.groupBy({
            by: ['cashbookId'],
            where: { cashbookId: { in: cashbooks.map((c) => c.id) } },
            _count: { _all: true },
        });
        const byId = new Map(counts.map((c) => [c.cashbookId, c._count._all]));

        return cashbooks.map((cashbook) => {
            const totalEntries = byId.get(cashbook.id) ?? 0;
            return { ...cashbook, totalEntries, canDelete: totalEntries === 0 };
        });
    }

    async getCashbooks(
        workspaceId: string,
        userId: string,
        workspaceRole?: WorkspaceRole | null,
        includeArchived = false,
    ) {
        // Check workspace type
        const workspace = await this.prisma.workspace.findUnique({
            where: { id: workspaceId },
        });

        if (!workspace || !workspace.isActive) {
            throw new NotFoundError('Workspace');
        }

        // Personal workspace: return all cashbooks (single owner)
        if (workspace.type === WorkspaceType.PERSONAL) {
            return this.withDeletability(
                await this.cashbooksRepository.findByWorkspaceId(workspaceId, includeArchived),
            );
        }

        // Owners, admins and accountants reach every book without an explicit
        // membership row — requireCashbookMember grants them access to any one
        // of them, so listing only their joined books would show an empty page
        // for books they can in fact open.
        if (hasWorkspacePermission(workspaceRole, WorkspacePermission.ACCESS_ALL_CASHBOOKS)) {
            return this.withDeletability(
                await this.cashbooksRepository.findByWorkspaceId(workspaceId, includeArchived),
            );
        }

        // Everyone else — members and sub-accountants — sees only what they
        // have been assigned to.
        return this.withDeletability(
            await this.cashbooksRepository.findUserAccessibleCashbooks(
                workspaceId, userId, includeArchived,
            ),
        );
    }

    async getCashbook(cashbookId: string) {
        const cashbook = await this.cashbooksRepository.findById(cashbookId);
        if (!cashbook || !cashbook.isActive) {
            throw new NotFoundError('Cashbook');
        }
        const [decorated] = await this.withDeletability([cashbook]);
        return decorated;
    }

    async createCashbook(workspaceId: string, userId: string, dto: CreateCashbookDto) {
        const workspace = await this.prisma.workspace.findUnique({
            where: { id: workspaceId },
        });

        if (!workspace || !workspace.isActive) {
            throw new NotFoundError('Workspace');
        }
        const workspaceCurrency = normalizeCurrency(workspace.defaultCurrency);
        if (dto.currency) {
            assertSameCurrency(workspaceCurrency, dto.currency, 'workspace base vs cashbook');
        }

        const cashbook = await this.prisma.$transaction(async (tx) => {
            const cb = await tx.cashbook.create({
                data: {
                    name: dto.name,
                    description: dto.description,
                    currency: workspaceCurrency,
                    allowBackdate: dto.allowBackdate,
                    workspace: { connect: { id: workspaceId } },
                },
                include: { workspace: true },
            });

            // This book's private "unallocated book cash" account. Routing an
            // unlinked entry's cash leg here — and a wallet-linked entry's leg to
            // the wallet instead — is what preserves the rule that wallet-linked
            // entries do not move the book balance.
            await provisionWorkspaceAccounting(tx, workspaceId, workspaceCurrency);
            await ensureCashbookLedgerAccount(tx, {
                id: cb.id,
                workspaceId,
                name: cb.name,
                currency: cb.currency,
            });

            // For business workspaces, add creator as PRIMARY_ADMIN
            if (workspace.type === WorkspaceType.BUSINESS) {
                await tx.cashbookMember.create({
                    data: {
                        cashbookId: cb.id,
                        userId,
                        role: CashbookRole.PRIMARY_ADMIN,
                    },
                });
            }

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.CASHBOOK_CREATED,
                    resource: 'cashbook',
                    resourceId: cb.id,
                    details: { name: dto.name, currency: workspaceCurrency } as any,
                },
            });

            return cb;
        });

        return cashbook;
    }

    /**
     * Opt a cashbook into the external integration surface.
     *
     * The conditional update is the concurrency boundary: two requests can
     * safely race to activate the same book, but only one creates its immutable
     * reference and the other returns that exact reference. A database unique
     * index remains the authority if a generated reference collides.
     */
    async activateIntegration(cashbookId: string, workspaceId: string, userId: string) {
        const cashbook = await this.prisma.cashbook.findFirst({
            where: { id: cashbookId, workspaceId, isActive: true },
            select: { id: true, bookRef: true },
        });
        if (!cashbook) throw new NotFoundError('Cashbook');
        if (cashbook.bookRef) return { bookRef: cashbook.bookRef, activated: false };

        for (let attempt = 0; attempt < 5; attempt++) {
            const bookRef = `CB-${crypto.randomBytes(12).toString('hex').toUpperCase()}`;
            try {
                const result = await this.prisma.$transaction(async (tx) => {
                    const updated = await tx.cashbook.updateMany({
                        where: { id: cashbookId, workspaceId, bookRef: null, isActive: true },
                        data: { bookRef },
                    });

                    if (updated.count === 0) {
                        return { activated: false as const };
                    }

                    await tx.auditLog.create({
                        data: {
                            userId,
                            workspaceId,
                            action: AuditAction.CASHBOOK_INTEGRATION_ACTIVATED,
                            resource: 'cashbook',
                            resourceId: cashbookId,
                            details: { bookRef } as any,
                        },
                    });
                    return { activated: true as const };
                });

                if (result.activated) return { bookRef, activated: true };

                const activatedBook = await this.prisma.cashbook.findUniqueOrThrow({
                    where: { id: cashbookId },
                    select: { bookRef: true },
                });
                if (activatedBook.bookRef) {
                    return { bookRef: activatedBook.bookRef, activated: false };
                }
            } catch (error: any) {
                // The only expected failure is an exceptionally unlikely global
                // reference collision. Retry with fresh cryptographic entropy.
                if (error?.code !== 'P2002') throw error;
            }
        }

        throw new AppError(
            'Could not allocate a unique integration reference. Please retry.',
            503,
            'BOOK_REF_ALLOCATION_FAILED',
        );
    }

    async updateCashbook(cashbookId: string, userId: string, dto: UpdateCashbookDto) {
        const cashbook = await this.cashbooksRepository.findById(cashbookId);
        if (!cashbook || !cashbook.isActive) {
            throw new NotFoundError('Cashbook');
        }
        if (dto.currency && dto.currency.toUpperCase() !== cashbook.currency) {
            throw new AppError('Cashbook currency is locked to the workspace base currency', 400, 'BASE_CURRENCY_LOCKED');
        }

        const updated = await this.cashbooksRepository.update(cashbookId, {
            ...(dto.name && { name: dto.name }),
            ...(dto.description !== undefined && { description: dto.description }),
            ...(dto.allowBackdate !== undefined && { allowBackdate: dto.allowBackdate }),
        });

        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId: cashbook.workspaceId,
                action: AuditAction.CASHBOOK_UPDATED,
                resource: 'cashbook',
                resourceId: cashbookId,
                details: dto as any,
            },
        });

        return updated;
    }

    /**
     * Archive a book, or restore an archived one.
     *
     * This is how a book that has recorded anything is retired: it keeps every
     * entry, leaves the active list, refuses new entries, and can be brought
     * back. Deleting is reserved for a book that never recorded anything.
     */
    async setArchived(cashbookId: string, userId: string, archive: boolean) {
        const cashbook = await this.cashbooksRepository.findById(cashbookId);
        if (!cashbook || !cashbook.isActive) {
            throw new NotFoundError('Cashbook');
        }

        // Already where the caller wants it: no write, and no second audit row
        // claiming it was archived twice.
        if (Boolean(cashbook.archivedAt) === archive) {
            const [unchanged] = await this.withDeletability([cashbook]);
            return unchanged;
        }

        const updated = await this.cashbooksRepository.update(cashbookId, {
            archivedAt: archive ? new Date() : null,
        });

        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId: cashbook.workspaceId,
                action: archive ? AuditAction.CASHBOOK_ARCHIVED : AuditAction.CASHBOOK_UNARCHIVED,
                resource: 'cashbook',
                resourceId: cashbookId,
                details: { name: cashbook.name } as any,
            },
        });

        const [decorated] = await this.withDeletability([updated]);
        return decorated;
    }

    async deleteCashbook(cashbookId: string, userId: string) {
        const cashbook = await this.cashbooksRepository.findById(cashbookId);
        if (!cashbook || !cashbook.isActive) {
            throw new NotFoundError('Cashbook');
        }

        // A book that has recorded anything is archived, never deleted — its
        // entries are financial history, and the ledger, invoices and
        // obligations that reference them stay pointing at it. Entries since
        // deleted still count: a reversed entry is part of that history.
        const totalEntries = await this.prisma.entry.count({ where: { cashbookId } });
        if (totalEntries > 0) {
            throw new AppError(
                `"${cashbook.name}" has ${totalEntries} ${totalEntries === 1 ? 'entry' : 'entries'}, `
                + 'so it cannot be deleted. Archive it instead — it keeps its history, leaves your '
                + 'active books, and can be restored.',
                400,
                'DELETE_RESTRICTED',
            );
        }

        await this.cashbooksRepository.softDelete(cashbookId);

        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId: cashbook.workspaceId,
                action: AuditAction.CASHBOOK_DELETED,
                resource: 'cashbook',
                resourceId: cashbookId,
            },
        });
    }

    // ─── Cashbook Members ──────────────────────────────
    async getCashbookMembers(cashbookId: string) {
        return this.cashbooksRepository.getMembers(cashbookId);
    }

    async addCashbookMember(cashbookId: string, addedByUserId: string, dto: AddCashbookMemberDto) {
        const cashbook = await this.cashbooksRepository.findById(cashbookId);
        if (!cashbook || !cashbook.isActive) {
            throw new NotFoundError('Cashbook');
        }

        const targetUser = await this.prisma.user.findUnique({
            where: { email: dto.email },
        });

        if (!targetUser) {
            throw new NotFoundError('User with this email');
        }

        // For business workspaces, user must be a workspace member
        if (cashbook.workspace.type === WorkspaceType.BUSINESS) {
            const wsMembership = await this.prisma.workspaceMember.findUnique({
                where: {
                    workspaceId_userId: {
                        workspaceId: cashbook.workspaceId,
                        userId: targetUser.id,
                    },
                },
            });

            if (!wsMembership && cashbook.workspace.ownerId !== targetUser.id) {
                throw new AppError(
                    'User must be a workspace member before adding to a cashbook',
                    400,
                    'INVALID_OPERATION'
                );
            }
        }

        // Check if already a cashbook member
        const existing = await this.cashbooksRepository.findMember(cashbookId, targetUser.id);
        if (existing) {
            throw new ConflictError('User is already a member of this cashbook');
        }

        const member = await this.cashbooksRepository.addMember(cashbookId, targetUser.id, dto.role);

        await this.prisma.auditLog.create({
            data: {
                userId: addedByUserId,
                workspaceId: cashbook.workspaceId,
                action: AuditAction.CASHBOOK_MEMBER_ADDED,
                resource: 'cashbook_member',
                resourceId: member.id,
                details: { email: dto.email, role: dto.role, cashbookId } as any,
            },
        });

        return member;
    }

    async updateCashbookMemberRole(
        cashbookId: string,
        targetUserId: string,
        updatedByUserId: string,
        dto: UpdateCashbookMemberRoleDto
    ) {
        const membership = await this.cashbooksRepository.findMember(cashbookId, targetUserId);
        if (!membership) {
            throw new NotFoundError('Cashbook member');
        }

        if (membership.role === 'PRIMARY_ADMIN') {
            throw new AppError(
                'Cannot change the role of the primary admin',
                400,
                'INVALID_OPERATION'
            );
        }

        const oldRole = membership.role;
        const updated = await this.cashbooksRepository.updateMemberRole(cashbookId, targetUserId, dto.role);

        const cashbook = await this.prisma.cashbook.findUnique({
            where: { id: cashbookId },
            select: { workspaceId: true },
        });

        await this.prisma.auditLog.create({
            data: {
                userId: updatedByUserId,
                workspaceId: cashbook?.workspaceId,
                action: AuditAction.CASHBOOK_MEMBER_ROLE_CHANGED,
                resource: 'cashbook_member',
                resourceId: membership.id,
                details: { oldRole, newRole: dto.role, targetUserId, cashbookId } as any,
            },
        });

        return updated;
    }

    async removeCashbookMember(cashbookId: string, targetUserId: string, removedByUserId: string) {
        const membership = await this.cashbooksRepository.findMember(cashbookId, targetUserId);
        if (!membership) {
            throw new NotFoundError('Cashbook member');
        }

        if (membership.role === 'PRIMARY_ADMIN') {
            throw new AppError(
                'Cannot remove the primary admin from the cashbook',
                400,
                'INVALID_OPERATION'
            );
        }

        await this.cashbooksRepository.removeMember(cashbookId, targetUserId);

        const cashbook = await this.prisma.cashbook.findUnique({
            where: { id: cashbookId },
            select: { workspaceId: true },
        });

        await this.prisma.auditLog.create({
            data: {
                userId: removedByUserId,
                workspaceId: cashbook?.workspaceId,
                action: AuditAction.CASHBOOK_MEMBER_REMOVED,
                resource: 'cashbook_member',
                details: { targetUserId, cashbookId } as any,
            },
        });
    }

    // ─── Financial Summary ─────────────────────────────
    async getFinancialSummary(cashbookId: string) {
        const summary = await this.cashbooksRepository.getFinancialSummary(cashbookId);
        if (!summary) {
            throw new NotFoundError('Cashbook');
        }
        return summary;
    }

    // ─── Balance Recalculation ─────────────────────────
    /**
     * Recompute cashbook caches from non-deleted entries (same formulas as the write path):
     * - totalIncome / totalExpense = full activity (including wallet-linked entries)
     * - balance = book cash only (entries WITHOUT a non-voided wallet AccountTransaction)
     *
     * Wallet detection uses a dedicated lookup of CASHBOOK_ENTRY account_transactions
     * (not only the Prisma relation include) so links are not missed.
     */
    async recalculateBalance(cashbookId: string, userId: string) {
        const { recomputeCashbookFromEntries } = await import('../../core/finance');

        const cashbook = await this.cashbooksRepository.findById(cashbookId);
        if (!cashbook || !cashbook.isActive) {
            throw new NotFoundError('Cashbook');
        }

        const oldBalance = cashbook.balance;
        const oldTotalIncome = cashbook.totalIncome;
        const oldTotalExpense = cashbook.totalExpense;

        const entries = await this.prisma.entry.findMany({
            where: { cashbookId, isDeleted: false },
            select: {
                id: true,
                type: true,
                amount: true,
                chargeAmount: true,
            },
        });

        const entryIds = entries.map((e) => e.id);

        // Robust wallet-link set: any non-voided CASHBOOK_ENTRY AT for these entries
        const linkedRows =
            entryIds.length === 0
                ? []
                : await this.prisma.accountTransaction.findMany({
                    where: {
                        sourceType: 'CASHBOOK_ENTRY',
                        voidedAt: null,
                        sourceId: { in: entryIds },
                    },
                    select: { sourceId: true },
                });

        const walletLinkedIds = new Set(
            linkedRows.map((r) => r.sourceId).filter((id): id is string => Boolean(id)),
        );

        const computed = recomputeCashbookFromEntries(
            entries.map((e) => ({
                type: e.type,
                amount: e.amount,
                chargeAmount: e.chargeAmount,
                hasWalletLink: walletLinkedIds.has(e.id),
            })),
        );

        await this.prisma.cashbook.update({
            where: { id: cashbookId },
            data: {
                balance: computed.balance,
                totalIncome: computed.totalIncome,
                totalExpense: computed.totalExpense,
            },
        });

        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId: cashbook.workspaceId,
                action: AuditAction.CASHBOOK_UPDATED,
                resource: 'cashbook',
                resourceId: cashbookId,
                details: {
                    action: 'BALANCE_RECALCULATED',
                    oldBalance: oldBalance.toString(),
                    oldTotalIncome: oldTotalIncome.toString(),
                    oldTotalExpense: oldTotalExpense.toString(),
                    newBalance: computed.balance.toString(),
                    newTotalIncome: computed.totalIncome.toString(),
                    newTotalExpense: computed.totalExpense.toString(),
                    bookIncome: computed.bookIncome.toString(),
                    bookExpense: computed.bookExpense.toString(),
                    walletLinkedCount: computed.walletLinkedCount,
                    unallocatedCount: computed.unallocatedCount,
                } as any,
            },
        });

        return {
            cashbookId,
            /** Book cash (unallocated only) — never income − expense when wallets are used */
            oldBalance: oldBalance.toString(),
            newBalance: computed.balance.toString(),
            /** Full cashbook activity (includes wallet-linked entries) */
            totalIncome: computed.totalIncome.toString(),
            totalExpense: computed.totalExpense.toString(),
            /** Activity that moved book cash only */
            bookIncome: computed.bookIncome.toString(),
            bookExpense: computed.bookExpense.toString(),
            walletLinkedCount: computed.walletLinkedCount,
            unallocatedCount: computed.unallocatedCount,
            drifted:
                !oldBalance.equals(computed.balance) ||
                !oldTotalIncome.equals(computed.totalIncome) ||
                !oldTotalExpense.equals(computed.totalExpense),
        };
    }

    // ─── Reconciliation Toggle ────────────────────────
    async toggleReconciliation(entryId: string, cashbookId: string, userId: string) {
        const entry = await this.prisma.entry.findUnique({
            where: { id: entryId },
        });

        if (!entry || entry.isDeleted || entry.cashbookId !== cashbookId) {
            throw new NotFoundError('Entry');
        }

        const updated = await this.prisma.entry.update({
            where: { id: entryId },
            data: { isReconciled: !entry.isReconciled },
        });

        return {
            entryId,
            isReconciled: updated.isReconciled,
        };
    }
}

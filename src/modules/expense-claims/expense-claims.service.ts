/**
 * Expenses incurred doing a task, and what approving one posts to the ledger.
 *
 * The claim itself is an operational document — it is not accounting until
 * somebody approves it. Approval is where money moves, and what moves depends
 * on who paid:
 *
 *   ORG_WALLET  the money already left an organisation wallet, so this is an
 *               ordinary EXPENSE entry linked to that wallet. Because it is
 *               wallet-linked the book balance does not move while money-out
 *               does — the existing rule, inherited rather than re-implemented.
 *
 *   OWN_MONEY   the member is out of pocket, so the organisation owes them. That
 *               is a PAYABLE obligation against their staff contact, which posts
 *               Dr Deferred Purchases / Cr Accounts Payable. The expense hits
 *               the P&L when the reimbursement is actually paid, which is what
 *               "cash basis" means here, and until then it sits in AP aging
 *               under their name.
 *
 * Nothing in this file does its own arithmetic: it delegates to EntriesService
 * and ObligationsService so there is one posting path, not two.
 */
import { injectable, inject } from 'tsyringe';
import { ApprovalStatus, ContactType, ExpensePaymentSource, PrismaClient } from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import {
    AppError,
    AuthorizationError,
    ConflictError,
    NotFoundError,
} from '../../core/errors/AppError';
import { AuditAction, WorkspaceRole } from '../../core/types';
import {
    WorkspacePermission,
    hasWorkspacePermission,
} from '../../core/types/workspace-permissions';
import { workspaceUserCan, resolveWorkspaceRole } from '../../core/authz/workspace-access';
import { CashbookPermission, hasPermission } from '../../core/types/permissions';
import { assertSameCurrency } from '../../core/finance';
import { EntriesService } from '../entries/entries.service';
import { ObligationsService } from '../cashbook-obligations/obligations.service';
import { FilesService } from '../files/files.service';
import { notificationsQueue } from '../../config/queues';
import type {
    CreateExpenseClaimDto,
    ExpenseClaimQueryDto,
    ReviewExpenseClaimDto,
} from './expense-claims.dto';

@injectable()
export class ExpenseClaimsService {
    constructor(
        @inject('PrismaClient') private prisma: PrismaClient,
        private entriesService: EntriesService,
        private obligationsService: ObligationsService,
        private filesService: FilesService,
    ) { }

    private can(workspaceId: string, userId: string, permission: WorkspacePermission) {
        return workspaceUserCan(this.prisma, workspaceId, userId, permission);
    }

    // ─── Submitting ───────────────────────────────────────────

    /**
     * File a claim. It starts with no attachments and cannot be reviewed until
     * at least one is uploaded — proof is mandatory, and the check lives at
     * submit time because a CHECK constraint cannot see across tables.
     */
    async createClaim(workspaceId: string, userId: string, dto: CreateExpenseClaimDto) {
        const workspace = await this.prisma.workspace.findUnique({
            where: { id: workspaceId },
            select: { isActive: true, defaultCurrency: true },
        });
        if (!workspace?.isActive) throw new NotFoundError('Workspace');

        let projectId = dto.projectId ?? null;

        if (dto.taskId) {
            const task = await this.prisma.task.findUnique({
                where: { id: dto.taskId },
                include: { assignments: { select: { userId: true } } },
            });
            if (!task || task.workspaceId !== workspaceId) throw new NotFoundError('Task');

            // Only somebody actually doing the work can claim against it. A
            // manager who spent money files it against the project instead.
            const isAssignee = task.assignments.some((a) => a.userId === userId);
            if (!isAssignee) {
                throw new AuthorizationError(
                    'Only someone assigned to this task can claim an expense against it.',
                );
            }
            projectId = task.projectId ?? projectId;
        }

        if (dto.paymentSource === ExpensePaymentSource.ORG_WALLET) {
            const account = await this.prisma.account.findUnique({
                where: { id: dto.accountId! },
                select: { workspaceId: true, currency: true, archivedAt: true },
            });
            if (!account || account.workspaceId !== workspaceId) {
                throw new AppError('Unknown wallet', 400, 'INVALID_ACCOUNT');
            }
            if (account.archivedAt) {
                throw new AppError('That wallet is archived', 400, 'ACCOUNT_ARCHIVED');
            }
            // Fail here rather than at approval, when the approver would be the
            // one seeing an error about somebody else's mistake.
            assertSameCurrency(dto.currency, account.currency, 'expense claim wallet');
        }

        const claim = await this.prisma.$transaction(async (tx) => {
            const created = await tx.taskExpenseClaim.create({
                data: {
                    workspaceId,
                    taskId: dto.taskId ?? null,
                    projectId,
                    claimantId: userId,
                    amount: new Decimal(dto.amount),
                    currency: dto.currency,
                    description: dto.description,
                    incurredOn: new Date(`${dto.incurredOn}T00:00:00.000Z`),
                    paymentSource: dto.paymentSource,
                    accountId: dto.accountId ?? null,
                },
            });
            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.EXPENSE_CLAIM_SUBMITTED,
                    resource: 'expense_claim',
                    resourceId: created.id,
                    details: { amount: dto.amount, paymentSource: dto.paymentSource } as any,
                },
            });
            return created;
        });

        await this.notifyApprovers(workspaceId, userId, {
            type: 'EXPENSE_CLAIM_SUBMITTED',
            title: 'An expense needs approving',
            body: `${dto.currency} ${dto.amount} — ${dto.description}`,
            entityType: 'EXPENSE_CLAIM',
            entityId: claim.id,
            groupKey: `expense-claim:${claim.id}`,
        });

        return claim;
    }

    async listClaims(workspaceId: string, userId: string, query: ExpenseClaimQueryDto) {
        const canApprove = await this.can(
            workspaceId, userId, WorkspacePermission.APPROVE_EXPENSE_CLAIM,
        );
        return this.prisma.taskExpenseClaim.findMany({
            where: {
                workspaceId,
                status: query.status,
                taskId: query.taskId,
                // Everyone reads their own; only approvers see the queue.
                claimantId: canApprove && !query.mine ? undefined : userId,
            },
            include: {
                claimant: { select: { id: true, firstName: true, lastName: true, email: true } },
                reviewer: { select: { id: true, firstName: true, lastName: true } },
                task: { select: { id: true, title: true } },
                account: { select: { id: true, name: true, currency: true } },
                attachments: {
                    where: { isDeleted: false },
                    select: { id: true, fileName: true, mimeType: true, fileSize: true },
                },
            },
            orderBy: { createdAt: 'desc' },
            take: 100,
        });
    }

    async getClaim(claimId: string, workspaceId: string, userId: string) {
        const claim = await this.prisma.taskExpenseClaim.findUnique({
            where: { id: claimId },
            include: {
                claimant: { select: { id: true, firstName: true, lastName: true, email: true } },
                reviewer: { select: { id: true, firstName: true, lastName: true } },
                task: { select: { id: true, title: true } },
                account: { select: { id: true, name: true, currency: true } },
                attachments: {
                    where: { isDeleted: false },
                    select: { id: true, fileName: true, mimeType: true, fileSize: true },
                },
            },
        });
        if (!claim || claim.workspaceId !== workspaceId) throw new NotFoundError('Expense claim');

        if (claim.claimantId !== userId
            && !(await this.can(workspaceId, userId, WorkspacePermission.APPROVE_EXPENSE_CLAIM))) {
            throw new AuthorizationError('You cannot view this claim');
        }
        return claim;
    }

    /** Take back a claim nobody has decided yet. */
    async withdrawClaim(claimId: string, workspaceId: string, userId: string) {
        const claimed = await this.prisma.taskExpenseClaim.updateMany({
            where: { id: claimId, workspaceId, claimantId: userId, status: ApprovalStatus.PENDING },
            data: { status: ApprovalStatus.WITHDRAWN },
        });
        if (claimed.count === 0) throw new NotFoundError('Pending claim');
        return this.prisma.taskExpenseClaim.findUniqueOrThrow({ where: { id: claimId } });
    }

    // ─── Deciding ─────────────────────────────────────────────

    /**
     * Approve or decline a claim.
     *
     * Approving is the only method here that writes to the ledger. The order is
     * deliberate: claim the row first with a compare-and-swap, then post, then
     * record the posting on the claim — so a second approver arriving mid-flight
     * finds the row already taken and never reaches the posting call at all.
     */
    async reviewClaim(
        claimId: string,
        workspaceId: string,
        userId: string,
        dto: ReviewExpenseClaimDto,
    ) {
        await this.assertCanApprove(workspaceId, userId);

        const claim = await this.prisma.taskExpenseClaim.findUnique({ where: { id: claimId } });
        if (!claim || claim.workspaceId !== workspaceId) throw new NotFoundError('Expense claim');
        if (claim.status !== ApprovalStatus.PENDING) {
            throw new ConflictError('That claim has already been decided.');
        }

        if (!dto.approve) {
            if (!dto.reviewNote?.trim()) {
                throw new AppError(
                    'Say why the claim is being declined.',
                    400,
                    'REVIEW_NOTE_REQUIRED',
                );
            }
            return this.decline(claim.id, claim.version, workspaceId, userId, dto.reviewNote.trim());
        }

        return this.approve(claim, workspaceId, userId, dto);
    }

    private async decline(
        claimId: string,
        version: number,
        workspaceId: string,
        userId: string,
        reviewNote: string,
    ) {
        const declined = await this.prisma.$transaction(async (tx) => {
            const claimed = await tx.taskExpenseClaim.updateMany({
                where: { id: claimId, status: ApprovalStatus.PENDING, version },
                data: {
                    status: ApprovalStatus.REJECTED,
                    reviewerId: userId,
                    reviewNote,
                    reviewedAt: new Date(),
                    version: { increment: 1 },
                },
            });
            if (claimed.count === 0) throw new ConflictError('That claim has already been decided.');

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.EXPENSE_CLAIM_REJECTED,
                    resource: 'expense_claim',
                    resourceId: claimId,
                    details: { reviewNote } as any,
                },
            });
            return tx.taskExpenseClaim.findUniqueOrThrow({ where: { id: claimId } });
        });

        void this.notifyClaimant(declined, 'Your expense claim was declined', reviewNote);
        return declined;
    }

    private async approve(
        claim: { id: string; version: number; claimantId: string; amount: Decimal; currency: string; description: string; incurredOn: Date; paymentSource: ExpensePaymentSource; accountId: string | null; taskId: string | null },
        workspaceId: string,
        userId: string,
        dto: ReviewExpenseClaimDto,
    ) {
        if (!dto.cashbookId) {
            throw new AppError('Choose the book this expense belongs to.', 400, 'CASHBOOK_REQUIRED');
        }

        // Proof is not optional. Checked here rather than at submit so a claim
        // can be filed and the receipt attached a moment later, but never
        // approved without one.
        const attachmentCount = await this.prisma.attachment.count({
            where: { expenseClaimId: claim.id, isDeleted: false },
        });
        if (attachmentCount === 0) {
            throw new AppError(
                'This claim has no receipt attached. It cannot be approved without proof.',
                400,
                'PROOF_REQUIRED',
            );
        }

        const cashbook = await this.assertCanPostToCashbook(dto.cashbookId, workspaceId, userId);
        assertSameCurrency(claim.currency, cashbook.currency, 'expense claim book');

        const amount = claim.amount.toString();
        const description = `${claim.description} (expense claim)`;

        // Claim the row BEFORE posting. A second approver arriving now gets zero
        // rows and stops, rather than posting a duplicate entry we would then
        // have to reverse.
        const claimed = await this.prisma.taskExpenseClaim.updateMany({
            where: { id: claim.id, status: ApprovalStatus.PENDING, version: claim.version },
            data: { version: { increment: 1 } },
        });
        if (claimed.count === 0) throw new ConflictError('That claim has already been decided.');

        try {
            const posting = claim.paymentSource === ExpensePaymentSource.ORG_WALLET
                ? await this.postWalletExpense(claim, dto.cashbookId, userId, amount, description)
                : await this.postReimbursementPayable(claim, dto.cashbookId, workspaceId, userId, amount, description);

            const approved = await this.prisma.$transaction(async (tx) => {
                await tx.taskExpenseClaim.update({
                    where: { id: claim.id },
                    data: {
                        status: ApprovalStatus.APPROVED,
                        reviewerId: userId,
                        reviewNote: dto.reviewNote ?? null,
                        reviewedAt: new Date(),
                        cashbookId: dto.cashbookId,
                        ...posting,
                    },
                });
                await tx.auditLog.create({
                    data: {
                        userId,
                        workspaceId,
                        action: AuditAction.EXPENSE_CLAIM_APPROVED,
                        resource: 'expense_claim',
                        resourceId: claim.id,
                        details: {
                            cashbookId: dto.cashbookId,
                            paymentSource: claim.paymentSource,
                            ...posting,
                        } as any,
                    },
                });
                return tx.taskExpenseClaim.findUniqueOrThrow({ where: { id: claim.id } });
            });

            void this.notifyClaimant(
                approved,
                'Your expense claim was approved',
                claim.paymentSource === ExpensePaymentSource.OWN_MONEY
                    ? `${claim.currency} ${amount} is now recorded as owed to you.`
                    : `${claim.currency} ${amount} was recorded against the book.`,
            );
            return approved;
        } catch (error) {
            // Posting failed after the row was claimed. Hand it back so the
            // claim does not become permanently un-approvable.
            await this.prisma.taskExpenseClaim.updateMany({
                where: { id: claim.id, status: ApprovalStatus.PENDING },
                data: { version: { increment: 1 } },
            });
            throw error;
        }
    }

    /** Money that already left a wallet: one wallet-linked EXPENSE entry. */
    private async postWalletExpense(
        claim: { accountId: string | null; incurredOn: Date },
        cashbookId: string,
        userId: string,
        amount: string,
        description: string,
    ) {
        const entry = await this.entriesService.createEntry(cashbookId, userId, {
            type: 'EXPENSE',
            amount,
            description,
            entryDate: claim.incurredOn.toISOString(),
            // Wallet-linked, so the book balance is untouched while money-out
            // moves and the wallet decreases.
            accountId: claim.accountId!,
        } as any);
        return { entryId: (entry as { id: string }).id };
    }

    /**
     * Money the member fronted: a payable owed to them.
     *
     * Not an expense entry — on a cash basis the expense is recognised when the
     * reimbursement is actually paid, and that payment is an ordinary entry
     * settling this obligation.
     */
    private async postReimbursementPayable(
        claim: { claimantId: string; incurredOn: Date },
        cashbookId: string,
        workspaceId: string,
        userId: string,
        amount: string,
        description: string,
    ) {
        const contact = await this.ensureStaffContact(workspaceId, claim.claimantId);
        const obligation = await this.obligationsService.createObligation(cashbookId, userId, {
            type: 'PAYABLE',
            contactId: contact.id,
            title: description,
            totalAmount: amount,
        } as any);
        return { obligationId: (obligation as { id: string }).id };
    }

    /**
     * The contact standing for a member, created on first use.
     *
     * Idempotent via the unique on (workspaceId, userId) — two claims approved
     * at once cannot produce two "Jane Doe" contacts and split her balance
     * across both.
     */
    private async ensureStaffContact(workspaceId: string, userId: string) {
        const existing = await this.prisma.contact.findUnique({
            where: { workspaceId_userId: { workspaceId, userId } },
        });
        if (existing) return existing;

        const user = await this.prisma.user.findUniqueOrThrow({
            where: { id: userId },
            select: { firstName: true, lastName: true, email: true },
        });

        try {
            return await this.prisma.contact.create({
                data: {
                    workspaceId,
                    userId,
                    type: ContactType.STAFF,
                    name: `${user.firstName} ${user.lastName}`.trim() || user.email,
                    email: user.email,
                },
            });
        } catch (error: any) {
            if (error?.code === 'P2002') {
                return this.prisma.contact.findUniqueOrThrow({
                    where: { workspaceId_userId: { workspaceId, userId } },
                });
            }
            throw error;
        }
    }

    // ─── Receipts ─────────────────────────────────────────────

    /**
     * Attach proof to a claim.
     *
     * The claimant may add to their own while it is still pending; an approver
     * may look but not add, because a receipt supplied by the person approving
     * the spend is not proof of anything.
     */
    async attachReceipt(
        claimId: string,
        workspaceId: string,
        userId: string,
        file: Express.Multer.File,
    ) {
        const claim = await this.prisma.taskExpenseClaim.findUnique({ where: { id: claimId } });
        if (!claim || claim.workspaceId !== workspaceId) throw new NotFoundError('Expense claim');
        if (claim.claimantId !== userId) {
            throw new AuthorizationError('Only the person claiming can attach the receipt');
        }
        if (claim.status !== ApprovalStatus.PENDING) {
            throw new ConflictError('This claim has already been decided.');
        }
        return this.filesService.uploadOwnedAttachment(workspaceId, { expenseClaimId: claimId }, userId, file);
    }

    async listReceipts(claimId: string, workspaceId: string, userId: string) {
        // Reuses the read guard on the claim itself.
        await this.getClaim(claimId, workspaceId, userId);
        return this.filesService.listOwnedAttachments({ expenseClaimId: claimId });
    }

    // ─── Authorization ────────────────────────────────────────

    private async assertCanApprove(workspaceId: string, userId: string) {
        if (!(await this.can(workspaceId, userId, WorkspacePermission.APPROVE_EXPENSE_CLAIM))) {
            throw new AuthorizationError('You cannot approve expense claims in this workspace');
        }
    }

    /**
     * The approver must be able to post to the book they chose.
     *
     * This is what makes the book picker honest for a PROJECT_MANAGER: they hold
     * no ACCESS_ALL_CASHBOOKS, so only books they were explicitly added to pass
     * here — the same check requireCashbookMember(CREATE_ENTRY) performs, run
     * in-service because the book id arrives in the body rather than the path.
     */
    private async assertCanPostToCashbook(cashbookId: string, workspaceId: string, userId: string) {
        const cashbook = await this.prisma.cashbook.findUnique({
            where: { id: cashbookId },
            select: { id: true, workspaceId: true, isActive: true, currency: true },
        });
        if (!cashbook || !cashbook.isActive || cashbook.workspaceId !== workspaceId) {
            throw new NotFoundError('Cashbook');
        }

        const orgRole = await resolveWorkspaceRole(this.prisma, workspaceId, userId);
        if (hasWorkspacePermission(orgRole, WorkspacePermission.ACCESS_ALL_CASHBOOKS)) {
            return cashbook;
        }

        const membership = await this.prisma.cashbookMember.findUnique({
            where: { cashbookId_userId: { cashbookId, userId } },
            select: { role: true },
        });
        if (!membership || !hasPermission(membership.role as any, CashbookPermission.CREATE_ENTRY)) {
            throw new AuthorizationError(
                'You cannot record entries in that book. Choose one you have access to.',
            );
        }
        return cashbook;
    }

    // ─── Notifications ────────────────────────────────────────

    private dispatch(data: Record<string, unknown>) {
        return notificationsQueue.add(data.type as string, data).catch(() => { });
    }

    private async notifyClaimant(
        claim: { id: string; claimantId: string; workspaceId: string; taskId: string | null },
        title: string,
        body: string,
    ) {
        return this.dispatch({
            userId: claim.claimantId,
            workspaceId: claim.workspaceId,
            type: 'EXPENSE_CLAIM_DECIDED',
            title,
            body,
            taskId: claim.taskId ?? undefined,
            entityType: 'EXPENSE_CLAIM',
            entityId: claim.id,
            groupKey: `expense-claim-decided:${claim.id}`,
        });
    }

    private async notifyApprovers(
        workspaceId: string,
        actorId: string,
        payload: Record<string, unknown>,
    ) {
        const [workspace, members] = await Promise.all([
            this.prisma.workspace.findUnique({
                where: { id: workspaceId },
                select: { ownerId: true },
            }),
            this.prisma.workspaceMember.findMany({
                where: { workspaceId },
                select: { userId: true, role: true },
            }),
        ]);

        const recipients = new Set<string>();
        if (workspace?.ownerId) recipients.add(workspace.ownerId);
        for (const m of members) {
            if (hasWorkspacePermission(
                m.role as WorkspaceRole, WorkspacePermission.APPROVE_EXPENSE_CLAIM,
            )) {
                recipients.add(m.userId);
            }
        }
        recipients.delete(actorId);

        await Promise.all(
            [...recipients].map((userId) => this.dispatch({ ...payload, userId, workspaceId })),
        );
    }
}

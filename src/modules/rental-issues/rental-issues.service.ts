import { inject, injectable } from 'tsyringe';
import { Prisma, PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { issueSchema, messageSchema, issueQuerySchema } from './rental-issues.dto';
import { housingLabel } from '../housing/housing-properties.service';
import { housingWorkspace, rentalNotify } from '../housing/housing-access';
import { entryRecipient } from '../shared-entries/shared-entries.lifecycle';
import { AppError, ConflictError, NotFoundError } from '../../core/errors/AppError';
import { withFinancialTransaction } from '../../core/db/transaction';

@injectable()
export class RentalIssuesService {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) {}
    private async subject(
        tx: Prisma.TransactionClient,
        target: { tenancyId?: string | null; rentalId?: string | null },
        userId: string,
    ) {
        if (!(await tx.user.findFirst({ where: { id: userId, isActive: true, deletedAt: null } })))
            throw new NotFoundError('Rental');
        if (Boolean(target.tenancyId) === Boolean(target.rentalId))
            throw new NotFoundError('Rental');
        let workspaceId: string;
        let tenantId: string | null;
        let subjectLabel = 'Item rental';
        if (target.tenancyId) {
            const t = await tx.housingTenancy.findUnique({
                where: { id: target.tenancyId },
                include: { unit: { include: { property: true } } },
            });
            if (!t) throw new NotFoundError('Tenancy');
            workspaceId = t.workspaceId;
            subjectLabel = housingLabel(t.unit);
            tenantId = t.invitationStatus === 'ACCEPTED' ? t.tenantUserId : null;
        } else {
            const r = await tx.inventoryRental.findUnique({
                where: { id: target.rentalId! },
                include: { agreement: true },
            });
            if (!r) throw new NotFoundError('Rental');
            workspaceId = r.workspaceId;
            tenantId =
                r.agreement?.status === 'ACCEPTED'
                    ? r.agreement.borrowerUserId
                    : await entryRecipient(tx, r.customerId, workspaceId);
        }
        const ws = await tx.workspace.findFirst({
            where: { id: workspaceId, isActive: true },
            select: { ownerId: true },
        });
        if (!ws) throw new NotFoundError('Rental');
        if (tenantId === userId)
            return {
                workspaceId,
                tenantId,
                ownerId: ws.ownerId,
                subjectLabel,
                side: 'TENANT' as const,
            };
        try {
            await housingWorkspace(tx, workspaceId, userId, true);
        } catch (error) {
            if (error instanceof AppError && [403, 404].includes(error.statusCode))
                throw new NotFoundError('Rental');
            throw error;
        }
        return {
            workspaceId,
            tenantId,
            ownerId: ws.ownerId,
            subjectLabel,
            side: 'LANDLORD' as const,
        };
    }
    async rentals(userId: string) {
        // Also works for legacy manual rentals whose customer is a linked user.
        const rows = await this.prisma.inventoryRental.findMany({
            where: {
                workspace: { isActive: true },
                OR: [
                    { agreement: { borrowerUserId: userId, status: 'ACCEPTED' } },
                    { customer: { userId, isActive: true } },
                    {
                        customer: {
                            email: {
                                equals:
                                    (await this.prisma.user.findUnique({ where: { id: userId } }))
                                        ?.email ?? '',
                                mode: 'insensitive',
                            },
                            isActive: true,
                        },
                    },
                ],
            },
            include: { lines: { select: { item: { select: { name: true } } } } },
            orderBy: { createdAt: 'desc' },
            take: 100,
        });
        const visible = [];
        for (const r of rows) {
            try {
                const access = await this.subject(this.prisma, { rentalId: r.id }, userId);
                if (access.side === 'TENANT')
                    visible.push({
                        id: r.id,
                        name: r.lines.map((l) => l.item.name).join(', '),
                        status: r.status,
                        startDate: r.startDate,
                        endDate: r.endDate,
                    });
            } catch (e) {
                if (!(e instanceof NotFoundError)) throw e;
            }
        }
        return visible;
    }
    async list(userId: string, input: z.infer<typeof issueQuerySchema>) {
        const q = issueQuerySchema.parse(input);
        await this.subject(this.prisma, q, userId);
        const where = { tenancyId: q.tenancyId, rentalId: q.rentalId };
        const [data, total] = await Promise.all([
            this.prisma.rentalIssue.findMany({
                where,
                select: {
                    id: true,
                    title: true,
                    kind: true,
                    priority: true,
                    status: true,
                    createdAt: true,
                    version: true,
                },
                orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
                skip: (q.page - 1) * q.limit,
                take: q.limit,
            }),
            this.prisma.rentalIssue.count({ where }),
        ]);
        return { data, total, page: q.page, limit: q.limit };
    }
    async detail(id: string, userId: string, q: { page: number; limit: number }) {
        const issue = await this.prisma.rentalIssue.findUnique({ where: { id } });
        if (!issue) throw new NotFoundError('Issue');
        const access = await this.subject(this.prisma, issue, userId);
        const [messages, total] = await Promise.all([
            this.prisma.rentalIssueMessage.findMany({
                where: { issueId: id },
                orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
                skip: (q.page - 1) * q.limit,
                take: q.limit,
                select: { id: true, authorSide: true, body: true, status: true, createdAt: true },
            }),
            this.prisma.rentalIssueMessage.count({ where: { issueId: id } }),
        ]);
        const { workspaceId, createdById, ...safe } = issue;
        return {
            ...safe,
            subjectLabel: access.subjectLabel,
            side: access.side,
            messages,
            totalMessages: total,
            page: q.page,
            limit: q.limit,
        };
    }
    async create(userId: string, input: z.infer<typeof issueSchema>) {
        const dto = issueSchema.parse(input);
        return withFinancialTransaction(this.prisma, async (tx) => {
            const access = await this.subject(tx, dto, userId);
            const issue = await tx.rentalIssue.create({
                data: { ...dto, workspaceId: access.workspaceId, createdById: userId },
            });
            await tx.auditLog.create({
                data: {
                    workspaceId: access.workspaceId,
                    userId,
                    action: 'RENTAL_ISSUE_CREATED',
                    resource: 'rental_issue',
                    resourceId: issue.id,
                    details: { kind: issue.kind },
                },
            });
            await rentalNotify(
                tx,
                access.side === 'TENANT' ? access.ownerId : access.tenantId,
                {
                    type: 'RENTAL_ISSUE_UPDATED',
                    entityType: 'RENTAL_ISSUE',
                    entityId: issue.id,
                    title: 'New rental issue',
                    body: `${access.subjectLabel}: ${issue.title}`,
                    groupKey: `rental-issue:${issue.id}:1`,
                },
                access.side === 'TENANT' ? access.workspaceId : undefined,
            );
            return { id: issue.id };
        });
    }
    async respond(id: string, userId: string, input: z.infer<typeof messageSchema>) {
        const dto = messageSchema.parse(input);
        return withFinancialTransaction(this.prisma, async (tx) => {
            await tx.$queryRaw`SELECT id FROM rental_issues WHERE id = ${id}::uuid FOR UPDATE`;
            const issue = await tx.rentalIssue.findUnique({ where: { id } });
            if (!issue) throw new NotFoundError('Issue');
            const access = await this.subject(tx, issue, userId);
            if (issue.version !== dto.expectedVersion)
                throw new ConflictError('This issue has a new response. Refresh before replying');
            if (access.side === 'TENANT' && dto.status && !['OPEN', 'CLOSED'].includes(dto.status))
                throw new AppError(
                    'Tenants can close an issue or reopen it for review',
                    400,
                    'INVALID_ISSUE_STATUS',
                );
            if (issue.status === 'CLOSED' && dto.status !== 'OPEN')
                throw new ConflictError('Reopen the issue before replying');
            await tx.rentalIssueMessage.create({
                data: {
                    issueId: id,
                    authorId: userId,
                    authorSide: access.side,
                    body: dto.body,
                    status: dto.status,
                },
            });
            await tx.rentalIssue.update({
                where: { id },
                data: { status: dto.status, version: { increment: 1 } },
            });
            await tx.auditLog.create({
                data: {
                    workspaceId: access.workspaceId,
                    userId,
                    action: 'RENTAL_ISSUE_RESPONDED',
                    resource: 'rental_issue',
                    resourceId: id,
                    details: { status: dto.status ?? issue.status },
                },
            });
            await rentalNotify(
                tx,
                access.side === 'TENANT' ? access.ownerId : access.tenantId,
                {
                    type: 'RENTAL_ISSUE_UPDATED',
                    entityType: 'RENTAL_ISSUE',
                    entityId: id,
                    title: 'Rental issue updated',
                    body: `${access.subjectLabel}: ${issue.title}`,
                    groupKey: `rental-issue:${id}:${issue.version + 1}`,
                },
                access.side === 'TENANT' ? access.workspaceId : undefined,
            );
            return { responded: true };
        });
    }
}

import { inject, injectable } from 'tsyringe';
import { HousingTenancy, Prisma, PrismaClient } from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import { DateTime } from 'luxon';
import { createHash } from 'node:crypto';
import { AppError, ConflictError, NotFoundError } from '../../core/errors/AppError';
import { withFinancialTransaction } from '../../core/db/transaction';
import { EntriesService } from '../entries/entries.service';
import { entryRecipient, syncSharedEntry } from '../shared-entries/shared-entries.lifecycle';
import { housingWorkspace, rentalNotify, rentBook } from './housing-access';
import { dbDate, isoDate, monthlySchedule } from './housing-schedule';
import {
    TenancyInput,
    UnitInput,
    PaymentInput,
    unitSchema,
    updateUnitSchema,
    tenancySchema,
    paymentSchema,
    endTenancySchema,
    periodUpdateSchema,
    inviteSchema,
} from './housing.dto';
import { z } from 'zod';
import {
    HousingPropertiesService,
    housingConflict,
    housingLabel,
    lockHousingUnit,
    propertySelect,
} from './housing-properties.service';

const photoSelect = { id: true, fileName: true, mimeType: true } satisfies Prisma.AttachmentSelect;
const tenancyInclude = {
    workspace: { select: { name: true, profile: { select: { displayName: true } } } },
    unit: {
        include: {
            property: { select: propertySelect },
            photos: { where: { isDeleted: false }, select: photoSelect },
        },
    },
} satisfies Prisma.HousingTenancyInclude;
const livePayment = { entry: { status: 'POSTED' as const, isDeleted: false } };
export async function periodPaid(tx: Prisma.TransactionClient, periodId: string) {
    return (
        (
            await tx.rentAllocation.aggregate({
                where: { periodId, payment: livePayment },
                _sum: { amount: true },
            })
        )._sum.amount ?? new Decimal(0)
    );
}
async function audit(
    tx: Prisma.TransactionClient,
    workspaceId: string,
    userId: string,
    resourceId: string,
    action: string,
    details: Prisma.InputJsonValue,
) {
    await tx.auditLog.create({
        data: { workspaceId, userId, action, resource: 'housing', resourceId, details },
    });
}

@injectable()
export class HousingService {
    constructor(
        @inject('PrismaClient') private prisma: PrismaClient,
        private entries: EntriesService,
        private properties: HousingPropertiesService,
    ) {}

    async units(
        workspaceId: string,
        userId: string,
        q: { page: number; limit: number; search?: string; archived?: string; propertyId?: string },
    ) {
        const workspace = await housingWorkspace(this.prisma, workspaceId, userId);
        const today = DateTime.now().setZone(workspace.timezone).toISODate()!;
        if (q.propertyId) await this.properties.property(this.prisma, workspaceId, q.propertyId);
        const where: Prisma.HousingUnitWhereInput = {
            workspaceId,
            ...(q.propertyId ? { propertyId: q.propertyId } : { property: { archivedAt: null } }),
            archivedAt: q.archived === 'true' ? { not: null } : null,
            ...(q.search
                ? {
                      OR: [
                          { name: { contains: q.search, mode: 'insensitive' } },
                          { property: { name: { contains: q.search, mode: 'insensitive' } } },
                      ],
                  }
                : {}),
        };
        const [data, total] = await Promise.all([
            this.prisma.housingUnit.findMany({
                where,
                skip: (q.page - 1) * q.limit,
                take: q.limit,
                orderBy: [{ name: 'asc' }, { id: 'asc' }],
                include: {
                    property: { select: propertySelect },
                    photos: { where: { isDeleted: false }, select: photoSelect },
                    tenancies: {
                        where: { status: 'ACTIVE' },
                        select: { id: true, tenantName: true, startDate: true, endDate: true },
                    },
                },
            }),
            this.prisma.housingUnit.count({ where }),
        ]);
        return {
            data: data.map((u) => ({
                ...u,
                tenancies: u.tenancies.map((t) => ({
                    ...t,
                    scheduled: isoDate(t.startDate) > today,
                })),
                propertyName: u.property.name,
                address: u.property.address,
            })),
            total,
            page: q.page,
            limit: q.limit,
        };
    }
    async summary(workspaceId: string, userId: string, propertyId?: string) {
        const ws = await housingWorkspace(this.prisma, workspaceId, userId);
        const today = DateTime.now().setZone(ws.timezone).toISODate()!;
        if (propertyId) await this.properties.property(this.prisma, workspaceId, propertyId);
        const unitWhere = {
            workspaceId,
            archivedAt: null,
            ...(propertyId ? { propertyId } : { property: { archivedAt: null } }),
        };
        const [units, assigned, overdue, properties] = await Promise.all([
            this.prisma.housingUnit.count({ where: unitWhere }),
            this.prisma.housingTenancy.count({
                where: { workspaceId, status: 'ACTIVE', unit: unitWhere },
            }),
            this.prisma.$queryRaw<Array<{ currency: string; amount: Decimal }>>`
                SELECT t.currency, SUM(GREATEST(p.amount - COALESCE(a.paid, 0), 0)) AS amount
                FROM rent_periods p JOIN housing_tenancies t ON t.id = p.tenancy_id
                JOIN housing_units u ON u.id = t.unit_id
                LEFT JOIN LATERAL (
                    SELECT SUM(ra.amount) AS paid FROM rent_allocations ra
                    JOIN rent_payments rp ON rp.id = ra.payment_id JOIN entries e ON e.id = rp.entry_id
                    WHERE ra.period_id = p.id AND e.status = 'POSTED' AND NOT e.is_deleted
                ) a ON TRUE
                WHERE t.workspace_id = ${workspaceId}::uuid AND t.status <> 'CANCELLED'
                    AND (${propertyId ?? null}::uuid IS NULL OR u.property_id = ${propertyId ?? null}::uuid)
                    AND p.cancelled_at IS NULL AND p.due_date < ${today}::date
                GROUP BY t.currency`,
            this.prisma.housingProperty.count({ where: { workspaceId, archivedAt: null } }),
        ]);
        return {
            properties,
            units,
            assigned,
            unassigned: units - assigned,
            overdue: overdue.map((r) => ({ currency: r.currency, amount: r.amount.toString() })),
        };
    }
    async createUnit(workspaceId: string, userId: string, input: UnitInput) {
        return this.properties.createUnit(workspaceId, userId, input);
    }
    async updateUnit(
        workspaceId: string,
        userId: string,
        id: string,
        input: z.infer<typeof updateUnitSchema>,
    ) {
        const { expectedVersion, archived, ...dto } = updateUnitSchema.parse(input);
        try {
            return await withFinancialTransaction(this.prisma, async (tx) => {
                await housingWorkspace(tx, workspaceId, userId, true);
                const unit = await lockHousingUnit(tx, workspaceId, id);
                if (unit.property.archivedAt)
                    throw new ConflictError('Restore the property before changing its units');
                if (
                    archived &&
                    (await tx.housingTenancy.count({ where: { unitId: id, status: 'ACTIVE' } }))
                )
                    throw new ConflictError('End the active tenancy before archiving this unit');
                if (unit.version !== expectedVersion)
                    throw new ConflictError('The unit changed. Refresh and try again');
                const changed = await tx.housingUnit.update({
                    where: { id },
                    data: {
                        ...dto,
                        ...(archived === undefined
                            ? {}
                            : { archivedAt: archived ? new Date() : null }),
                        version: { increment: 1 },
                    },
                });
                await tx.housingProperty.update({
                    where: { id: unit.propertyId },
                    data: { version: { increment: 1 } },
                });
                await audit(tx, workspaceId, userId, id, 'HOUSING_UNIT_UPDATED', {
                    before: {
                        name: unit.name,
                        kind: unit.kind,
                        monthlyRent: unit.monthlyRent.toString(),
                    },
                    changes: { ...dto, archived: archived ?? null },
                });
                return changed;
            });
        } catch (error) {
            housingConflict(error);
        }
    }
    async location(id: string, userId: string) {
        const t = await this.prisma.housingTenancy.findUnique({ where: { id } });
        if (!t) throw new NotFoundError('Tenancy');
        if (t.tenantUserId === userId) {
            await this.access(this.prisma, id, userId, null);
            return { tenant: true };
        }
        await housingWorkspace(this.prisma, t.workspaceId, userId);
        return { tenant: false, workspaceId: t.workspaceId };
    }
    async tenancies(
        workspaceId: string | null,
        userId: string,
        q: { page: number; limit: number; propertyId?: string },
    ) {
        if (
            !(await this.prisma.user.findFirst({
                where: { id: userId, isActive: true, deletedAt: null },
            }))
        )
            throw new NotFoundError('User');
        if (workspaceId) {
            await housingWorkspace(this.prisma, workspaceId, userId);
            if (q.propertyId)
                await this.properties.property(this.prisma, workspaceId, q.propertyId);
        }
        const where: Prisma.HousingTenancyWhereInput = workspaceId
            ? { workspaceId, ...(q.propertyId ? { unit: { propertyId: q.propertyId } } : {}) }
            : { tenantUserId: userId, workspace: { isActive: true } };
        const [rows, total] = await Promise.all([
            this.prisma.housingTenancy.findMany({
                where,
                include: tenancyInclude,
                skip: (q.page - 1) * q.limit,
                take: q.limit,
                orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
            }),
            this.prisma.housingTenancy.count({ where }),
        ]);
        return {
            data: rows.map((row) => this.safeTenancy(row, Boolean(workspaceId))),
            total,
            page: q.page,
            limit: q.limit,
        };
    }
    private safeTenancy(
        row: Prisma.HousingTenancyGetPayload<{ include: typeof tenancyInclude }>,
        landlord: boolean,
    ) {
        const {
            unit,
            workspace,
            tenantUserId,
            contactId,
            createdById,
            notes,
            workspaceId,
            ...tenancy
        } = row;
        return {
            ...tenancy,
            landlordName: workspace.profile?.displayName || workspace.name,
            ...(landlord ? { workspaceId, tenantUserId, contactId, notes } : {}),
            unit: {
                id: unit.id,
                name: unit.name,
                propertyId: unit.propertyId,
                property: {
                    id: unit.property.id,
                    name: unit.property.name,
                    address: unit.property.address,
                },
                propertyName: unit.property.name,
                address: unit.property.address,
                kind: unit.kind,
                photos: unit.photos,
            },
        };
    }
    async access(
        tx: Prisma.TransactionClient,
        id: string,
        userId: string,
        workspaceId: string | null,
        write = false,
    ) {
        if (!(await tx.user.findFirst({ where: { id: userId, isActive: true, deletedAt: null } })))
            throw new NotFoundError('Tenancy');
        const row = await tx.housingTenancy.findUnique({ where: { id }, include: tenancyInclude });
        if (!row || (workspaceId && row.workspaceId !== workspaceId))
            throw new NotFoundError('Tenancy');
        if (workspaceId) await housingWorkspace(tx, workspaceId, userId, write);
        else if (
            row.tenantUserId !== userId ||
            !(await tx.workspace.findFirst({ where: { id: row.workspaceId, isActive: true } }))
        )
            throw new NotFoundError('Tenancy');
        return row;
    }
    async detail(
        id: string,
        userId: string,
        workspaceId: string | null,
        page = { page: 1, limit: 20 },
    ) {
        const row = await this.access(this.prisma, id, userId, workspaceId);
        const terms = this.safeTenancy(row, Boolean(workspaceId));
        if (!workspaceId && row.invitationStatus !== 'ACCEPTED')
            return { ...terms, periods: [], payments: [], paymentsTotal: 0 };
        const [periods, payments, ws, paymentsTotal] = await Promise.all([
            this.prisma.rentPeriod.findMany({
                where: { tenancyId: id },
                orderBy: { startDate: 'asc' },
                include: {
                    allocations: { where: { payment: livePayment }, select: { amount: true } },
                },
            }),
            this.prisma.rentPayment.findMany({
                where: { tenancyId: id },
                skip: (page.page - 1) * page.limit,
                take: page.limit,
                orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
                include: {
                    allocations: { select: { periodId: true, amount: true } },
                    entry: {
                        select: {
                            entryDate: true,
                            status: true,
                            cashbookId: true,
                            sharedEntries: {
                                select: { id: true, status: true, recipientUserId: true },
                            },
                        },
                    },
                },
            }),
            this.prisma.workspace.findUniqueOrThrow({
                where: { id: row.workspaceId },
                select: { timezone: true },
            }),
            this.prisma.rentPayment.count({ where: { tenancyId: id } }),
        ]);
        const visibleBooks = new Map<string, string>();
        if (workspaceId)
            for (const bookId of [
                ...new Set(payments.flatMap((p) => (p.entry ? [p.entry.cashbookId] : []))),
            ]) {
                try {
                    const book = await rentBook(
                        this.prisma,
                        bookId,
                        workspaceId,
                        userId,
                        row.currency,
                    );
                    visibleBooks.set(book.id, book.name);
                } catch (error) {
                    if (!(error instanceof AppError) || ![403, 404].includes(error.statusCode))
                        throw error;
                }
            }
        const today = DateTime.now().setZone(ws.timezone).toISODate()!;
        return {
            ...terms,
            paymentsTotal,
            periods: periods.map(({ allocations, ...p }) => {
                const paid = allocations.reduce((sum, a) => sum.add(a.amount), new Decimal(0));
                const remaining = p.amount.sub(paid);
                return {
                    ...p,
                    paid: paid.toString(),
                    outstanding: remaining.toString(),
                    state: p.cancelledAt
                        ? 'CANCELLED'
                        : remaining.lte(0)
                          ? 'PAID'
                          : isoDate(p.dueDate) < today
                            ? 'OVERDUE'
                            : paid.gt(0)
                              ? 'PARTIAL'
                              : 'DUE',
                };
            }),
            payments: payments.map((p) => ({
                id: p.id,
                amount: p.amount,
                entryDate: p.entry?.entryDate ?? p.createdAt,
                status: p.entry?.status ?? 'UNAVAILABLE',
                allocations: p.allocations,
                ...(workspaceId
                    ? {
                          entryId: p.entryId,
                          cashbookId:
                              p.entry && visibleBooks.has(p.entry.cashbookId)
                                  ? p.entry.cashbookId
                                  : null,
                          cashbookName: p.entry
                              ? (visibleBooks.get(p.entry.cashbookId) ?? null)
                              : null,
                          sharingStatus: p.entry?.sharedEntries[0]?.status ?? null,
                      }
                    : {
                          sharedEntryId:
                              p.entry?.sharedEntries.find((s) => s.recipientUserId === userId)
                                  ?.id ?? null,
                      }),
            })),
        };
    }
    private async recipient(tx: Prisma.TransactionClient, workspaceId: string, contactId?: string) {
        if (!contactId) return null;
        const contact = await tx.contact.findFirst({
            where: { id: contactId, workspaceId, isActive: true, type: { not: 'STAFF' } },
        });
        if (!contact)
            throw new AppError(
                'Choose an active customer contact in this workspace',
                400,
                'INVALID_CONTACT',
            );
        return entryRecipient(tx, contactId, workspaceId);
    }
    private async inviteNotice(
        tx: Prisma.TransactionClient,
        tenancy: HousingTenancy,
        unitName: string,
    ) {
        await rentalNotify(tx, tenancy.tenantUserId, {
            type: 'HOUSING_INVITATION',
            entityType: 'HOUSING_TENANCY',
            entityId: tenancy.id,
            title: 'Review your housing tenancy',
            body: `You have been assigned ${unitName}. Review the dates and rent in My tenancies.`,
            groupKey: `tenancy:${tenancy.id}:invite:${tenancy.version}`,
        });
    }
    async createTenancy(workspaceId: string, userId: string, input: TenancyInput) {
        const dto = tenancySchema.parse(input);
        return withFinancialTransaction(this.prisma, async (tx) => {
            await housingWorkspace(tx, workspaceId, userId, true);
            const unit = await lockHousingUnit(tx, workspaceId, dto.unitId);
            if (unit.archivedAt || unit.property.archivedAt)
                throw new NotFoundError('Available unit');
            if (await tx.housingTenancy.count({ where: { unitId: unit.id, status: 'ACTIVE' } }))
                throw new ConflictError('This unit already has an active or scheduled tenancy');
            const previous = await tx.housingTenancy.findFirst({
                where: {
                    unitId: unit.id,
                    status: 'ENDED',
                    actualEndDate: { gt: dbDate(dto.startDate) },
                    ...(dto.endDate ? { startDate: { lt: dbDate(dto.endDate) } } : {}),
                },
            });
            if (previous) throw new ConflictError('These dates overlap the unit’s tenancy history');
            const tenantUserId = await this.recipient(tx, workspaceId, dto.contactId);
            if (tenantUserId === userId)
                throw new AppError('Choose a tenant other than yourself', 400, 'SELF_TENANCY');
            const terms = {
                startDate: dbDate(dto.startDate),
                endDate: dto.endDate ? dbDate(dto.endDate) : null,
                monthlyRent: new Decimal(dto.monthlyRent),
                firstPeriodAmount:
                    dto.firstPeriodAmount === undefined ? null : new Decimal(dto.firstPeriodAmount),
                finalPeriodAmount:
                    dto.finalPeriodAmount === undefined ? null : new Decimal(dto.finalPeriodAmount),
                dueDay: dto.dueDay,
            };
            // Validate the final partial period immediately, even for a long lease.
            if (dto.endDate) monthlySchedule(terms, dto.endDate);
            const tenancy = await tx.housingTenancy.create({
                data: {
                    ...terms,
                    workspaceId,
                    unitId: unit.id,
                    currency: unit.currency,
                    tenantName: dto.tenantName,
                    contactId: dto.contactId,
                    tenantUserId,
                    invitationStatus: tenantUserId ? 'PENDING' : null,
                    notes: dto.notes,
                    createdById: userId,
                },
            });
            const through = DateTime.fromISO(dto.startDate).plus({ months: 11 }).toISODate()!;
            await this.ensurePeriods(tx, tenancy, through);
            await audit(tx, workspaceId, userId, tenancy.id, 'HOUSING_TENANCY_CREATED', dto);
            await this.inviteNotice(tx, tenancy, housingLabel(unit));
            return tenancy;
        });
    }
    async ensurePeriods(tx: Prisma.TransactionClient, tenancy: HousingTenancy, through: string) {
        if (tenancy.status !== 'ACTIVE') return;
        const data = monthlySchedule(tenancy, through).map((p) => ({
            ...p,
            tenancyId: tenancy.id,
        }));
        if (data.length) await tx.rentPeriod.createMany({ data, skipDuplicates: true });
    }
    async generate(id: string, workspaceId: string, userId: string, through: string) {
        return withFinancialTransaction(this.prisma, async (tx) => {
            await tx.$queryRaw`SELECT id FROM housing_tenancies WHERE id = ${id}::uuid FOR UPDATE`;
            const tenancy = await this.access(tx, id, userId, workspaceId, true);
            const horizon = DateTime.now().plus({ years: 2 }).toISODate()!;
            if (through > horizon)
                throw new AppError('Generate at most two years ahead', 400, 'SCHEDULE_HORIZON');
            await this.ensurePeriods(tx, tenancy, through);
            return { generated: true };
        });
    }
    async invite(
        id: string,
        workspaceId: string,
        userId: string,
        input: z.infer<typeof inviteSchema>,
    ) {
        const dto = inviteSchema.parse(input);
        return withFinancialTransaction(this.prisma, async (tx) => {
            await tx.$queryRaw`SELECT id FROM housing_tenancies WHERE id = ${id}::uuid FOR UPDATE`;
            const tenancy = await this.access(tx, id, userId, workspaceId, true);
            if (tenancy.version !== dto.expectedVersion)
                throw new ConflictError('The tenancy changed. Refresh first');
            if (tenancy.invitationStatus === 'ACCEPTED')
                throw new ConflictError(
                    'An accepted tenant cannot be replaced. End this tenancy and create another',
                );
            const recipient = await this.recipient(tx, workspaceId, dto.contactId);
            if (!recipient || recipient === userId)
                throw new AppError(
                    'This contact needs a verified, active tenant account',
                    400,
                    'TENANT_NOT_LINKED',
                );
            const changed = await tx.housingTenancy.update({
                where: { id },
                data: {
                    contactId: dto.contactId,
                    tenantUserId: recipient,
                    invitationStatus: 'PENDING',
                    version: { increment: 1 },
                },
            });
            await audit(tx, workspaceId, userId, id, 'HOUSING_TENANT_INVITED', {
                contactId: dto.contactId,
            });
            await this.inviteNotice(tx, changed, housingLabel(tenancy.unit));
            return changed;
        });
    }
    async respond(id: string, userId: string, accept: boolean) {
        return withFinancialTransaction(this.prisma, async (tx) => {
            await tx.$queryRaw`SELECT id FROM housing_tenancies WHERE id = ${id}::uuid FOR UPDATE`;
            const tenancy = await this.access(tx, id, userId, null);
            if (tenancy.invitationStatus !== 'PENDING')
                throw new ConflictError('This invitation has already been handled');
            // A stale invitation from a removed/reassigned contact cannot grant access.
            if (
                !tenancy.contactId ||
                (await entryRecipient(tx, tenancy.contactId, tenancy.workspaceId)) !== userId
            )
                throw new ConflictError('This tenant connection is no longer available');
            await tx.housingTenancy.update({
                where: { id },
                data: {
                    invitationStatus: accept ? 'ACCEPTED' : 'DECLINED',
                    version: { increment: 1 },
                },
            });
            await audit(tx, tenancy.workspaceId, userId, id, 'HOUSING_INVITATION_DECIDED', {
                accept,
            });
            const ws = await tx.workspace.findUniqueOrThrow({ where: { id: tenancy.workspaceId } });
            await rentalNotify(
                tx,
                ws.ownerId,
                {
                    type: 'HOUSING_UPDATED',
                    entityType: 'HOUSING_TENANCY',
                    entityId: id,
                    title: accept ? 'Tenant accepted invitation' : 'Tenant declined invitation',
                    body: `${tenancy.tenantName} responded to the tenancy for ${housingLabel(tenancy.unit)}.`,
                    groupKey: `tenancy:${id}:decision:${tenancy.version}`,
                },
                tenancy.workspaceId,
            );
            return { accepted: accept };
        });
    }
    async updatePeriod(
        id: string,
        periodId: string,
        workspaceId: string,
        userId: string,
        input: z.infer<typeof periodUpdateSchema>,
    ) {
        const dto = periodUpdateSchema.parse(input);
        return withFinancialTransaction(this.prisma, async (tx) => {
            await tx.$queryRaw`SELECT id FROM housing_tenancies WHERE id = ${id}::uuid FOR UPDATE`;
            const tenancy = await this.access(tx, id, userId, workspaceId, true);
            const p = await tx.rentPeriod.findFirst({
                where: { id: periodId, tenancyId: id, cancelledAt: null },
            });
            if (!p) throw new NotFoundError('Rent period');
            if (p.version !== dto.expectedVersion)
                throw new ConflictError('The period changed. Refresh first');
            if (new Decimal(dto.amount).lt(await periodPaid(tx, p.id)))
                throw new ConflictError(
                    'The charge cannot be less than the recorded payments. Reverse the incorrect receipt first',
                );
            const changed = await tx.rentPeriod.update({
                where: { id: p.id },
                data: {
                    amount: dto.amount,
                    dueDate: dbDate(dto.dueDate),
                    adjustmentReason: dto.reason,
                    version: { increment: 1 },
                },
            });
            await audit(tx, workspaceId, userId, id, 'RENT_PERIOD_ADJUSTED', {
                periodId,
                before: p.amount.toString(),
                ...dto,
            });
            await rentalNotify(
                tx,
                tenancy.invitationStatus === 'ACCEPTED' ? tenancy.tenantUserId : null,
                {
                    type: 'HOUSING_UPDATED',
                    entityType: 'HOUSING_TENANCY',
                    entityId: id,
                    title: 'Rent period adjusted',
                    body: `The rent period starting ${isoDate(p.startDate)} was adjusted. Review the updated charge and due date.`,
                    groupKey: `rent-period:${periodId}:${changed.version}`,
                },
            );
            return changed;
        });
    }
    async end(
        id: string,
        workspaceId: string,
        userId: string,
        input: z.infer<typeof endTenancySchema>,
    ) {
        const dto = endTenancySchema.parse(input);
        return withFinancialTransaction(this.prisma, async (tx) => {
            // Same property -> unit -> tenancy order as creation.
            const probe = await this.access(tx, id, userId, workspaceId, true);
            await lockHousingUnit(tx, workspaceId, probe.unitId);
            await tx.$queryRaw`SELECT id FROM housing_tenancies WHERE id = ${id}::uuid FOR UPDATE`;
            const tenancy = await this.access(tx, id, userId, workspaceId, true);
            if (tenancy.status !== 'ACTIVE' || tenancy.version !== dto.expectedVersion)
                throw new ConflictError('The tenancy changed. Refresh first');
            const ws = await tx.workspace.findUniqueOrThrow({ where: { id: workspaceId } });
            if (
                dto.endDate < isoDate(tenancy.startDate) ||
                (dto.endDate !== isoDate(tenancy.startDate) &&
                    dto.endDate > DateTime.now().setZone(ws.timezone).toISODate()!)
            )
                throw new AppError(
                    'Use an actual move-out date between move-in and today',
                    400,
                    'INVALID_MOVE_OUT',
                );
            const finalAmount =
                dto.finalPeriodAmount === undefined
                    ? dto.endDate === (tenancy.endDate && isoDate(tenancy.endDate))
                        ? tenancy.finalPeriodAmount
                        : null
                    : new Decimal(dto.finalPeriodAmount);
            const terms = {
                ...tenancy,
                endDate: dbDate(dto.endDate),
                finalPeriodAmount: finalAmount,
            };
            const schedule = monthlySchedule(terms, dto.endDate);
            // Catch up any past periods before closing; never lose arrears.
            await this.ensurePeriods(
                tx,
                { ...tenancy, endDate: terms.endDate, finalPeriodAmount: terms.finalPeriodAmount },
                dto.endDate,
            );
            const periods = await tx.rentPeriod.findMany({
                where: { tenancyId: id, cancelledAt: null },
            });
            for (const p of periods) {
                const target = schedule.find(
                    (s) => s.startDate.getTime() === p.startDate.getTime(),
                );
                const paid = await periodPaid(tx, p.id);
                if (!target) {
                    if (paid.gt(0))
                        throw new ConflictError(
                            'Future periods have payments. Resolve or reverse those receipts before ending the tenancy',
                        );
                    await tx.rentPeriod.update({
                        where: { id: p.id },
                        data: {
                            cancelledAt: new Date(),
                            adjustmentReason: dto.reason,
                            version: { increment: 1 },
                        },
                    });
                } else if (
                    target.endDate.getTime() !== p.endDate.getTime() ||
                    (dto.finalPeriodAmount !== undefined && isoDate(target.endDate) === dto.endDate)
                ) {
                    const finalCharge =
                        dto.finalPeriodAmount !== undefined &&
                        isoDate(target.endDate) === dto.endDate
                            ? new Decimal(dto.finalPeriodAmount)
                            : target.amount;
                    if (paid.gt(finalCharge))
                        throw new ConflictError(
                            'The final charge is below payments already received. Resolve those receipts first',
                        );
                    await tx.rentPeriod.update({
                        where: { id: p.id },
                        data: {
                            endDate: target.endDate,
                            amount: finalCharge,
                            adjustmentReason: dto.reason,
                            version: { increment: 1 },
                        },
                    });
                }
            }
            const updated = await tx.housingTenancy.update({
                where: { id },
                data: {
                    status: dto.endDate === isoDate(tenancy.startDate) ? 'CANCELLED' : 'ENDED',
                    actualEndDate: dbDate(dto.endDate),
                    version: { increment: 1 },
                },
            });
            await audit(tx, workspaceId, userId, id, 'HOUSING_TENANCY_ENDED', dto);
            await rentalNotify(
                tx,
                tenancy.invitationStatus === 'ACCEPTED' ? tenancy.tenantUserId : null,
                {
                    type: 'HOUSING_UPDATED',
                    entityType: 'HOUSING_TENANCY',
                    entityId: id,
                    title: 'Move-out recorded',
                    body: `Move-out from ${housingLabel(tenancy.unit)} was recorded for ${dto.endDate}. Review the final rent balance.`,
                    groupKey: `tenancy:${id}:end`,
                },
            );
            return updated;
        });
    }
    async payment(id: string, workspaceId: string, userId: string, input: PaymentInput) {
        const dto = paymentSchema.parse(input);
        const requestHash = createHash('sha256')
            .update(
                JSON.stringify({
                    ...dto,
                    allocations: [...dto.allocations].sort((a, b) =>
                        a.periodId.localeCompare(b.periodId),
                    ),
                }),
            )
            .digest('hex');
        return withFinancialTransaction(this.prisma, async (tx) => {
            await tx.$queryRaw`SELECT id FROM housing_tenancies WHERE id = ${id}::uuid FOR UPDATE`;
            const tenancy = await this.access(tx, id, userId, workspaceId, true);
            const existing = await tx.rentPayment.findUnique({
                where: { tenancyId_requestId: { tenancyId: id, requestId: dto.requestId } },
            });
            if (existing) {
                if (existing.requestHash !== requestHash)
                    throw new ConflictError(
                        'This payment reference was used with different details',
                    );
                return { paymentId: existing.id, entryId: existing.entryId, alreadyRecorded: true };
            }
            if (tenancy.status === 'CANCELLED')
                throw new ConflictError('This tenancy was cancelled');
            await rentBook(tx, dto.cashbookId, workspaceId, userId, tenancy.currency);
            const periods = await tx.rentPeriod.findMany({
                where: {
                    tenancyId: id,
                    id: { in: dto.allocations.map((a) => a.periodId) },
                    cancelledAt: null,
                },
            });
            if (periods.length !== dto.allocations.length)
                throw new AppError(
                    'Choose valid rent periods in this tenancy',
                    400,
                    'INVALID_RENT_PERIOD',
                );
            let amount = new Decimal(0);
            for (const a of dto.allocations) {
                const p = periods.find((p) => p.id === a.periodId)!;
                if (new Decimal(a.amount).gt(p.amount.sub(await periodPaid(tx, p.id))))
                    throw new ConflictError(
                        'A payment exceeds the outstanding rent for its period',
                    );
                amount = amount.add(a.amount);
            }
            if (amount.gte('10000000000000000'))
                throw new AppError('Payment exceeds the supported amount', 400, 'AMOUNT_TOO_LARGE');
            if (tenancy.contactId && tenancy.tenantUserId) {
                const current = await entryRecipient(tx, tenancy.contactId, workspaceId);
                if (current && current !== tenancy.tenantUserId)
                    throw new ConflictError(
                        'The contact now identifies someone else. Correct the contact before recording this payment',
                    );
            }
            const activeContact = tenancy.contactId
                ? await tx.contact.findFirst({
                      where: { id: tenancy.contactId, workspaceId, isActive: true },
                      select: { id: true },
                  })
                : null;
            const entry = await this.entries.createEntryWithin(tx, dto.cashbookId, userId, {
                type: 'INCOME',
                amount: amount.toString(),
                accountId: dto.accountId,
                entryDate: dto.entryDate,
                categoryId: dto.categoryId,
                paymentModeId: dto.paymentModeId,
                contactId: activeContact?.id,
                description: `Rent · ${housingLabel(tenancy.unit)} · ${tenancy.tenantName} · ${periods
                    .map((p) => isoDate(p.startDate))
                    .sort()
                    .join(', ')}`,
            });
            const payment = await tx.rentPayment.create({
                data: {
                    tenancyId: id,
                    entryId: entry.id,
                    amount,
                    requestId: dto.requestId,
                    requestHash,
                    allocations: {
                        create: dto.allocations.map((a) => ({
                            periodId: a.periodId,
                            amount: a.amount,
                        })),
                    },
                },
            });
            await syncSharedEntry(tx, entry.id);
            await audit(tx, workspaceId, userId, id, 'RENT_PAYMENT_RECORDED', {
                paymentId: payment.id,
                entryId: entry.id,
                amount: amount.toString(),
                allocations: dto.allocations,
            });
            await rentalNotify(
                tx,
                tenancy.invitationStatus === 'ACCEPTED' ? tenancy.tenantUserId : null,
                {
                    type: 'HOUSING_UPDATED',
                    entityType: 'HOUSING_TENANCY',
                    entityId: id,
                    title: 'Rent payment recorded',
                    body: `${tenancy.currency} ${amount} recorded for ${housingLabel(tenancy.unit)}. Check My tenancies and Shared entries.`,
                    groupKey: `rent-payment:${payment.id}`,
                },
            );
            return { paymentId: payment.id, entryId: entry.id, alreadyRecorded: false };
        });
    }
    async paymentOptions(id: string, workspaceId: string, userId: string) {
        const t = await this.access(this.prisma, id, userId, workspaceId, true);
        const books = await this.prisma.cashbook.findMany({
            where: { workspaceId, currency: t.currency, isActive: true, archivedAt: null },
            orderBy: { name: 'asc' },
        });
        const permitted = [];
        for (const book of books) {
            try {
                await rentBook(this.prisma, book.id, workspaceId, userId, t.currency);
                permitted.push({ id: book.id, name: book.name, allowBackdate: book.allowBackdate });
            } catch (e) {
                if (!(e instanceof AppError) || ![403, 404].includes(e.statusCode)) throw e;
            }
        }
        const accounts = await this.prisma.account.findMany({
            where: { workspaceId, currency: t.currency, archivedAt: null },
            select: { id: true, name: true },
            orderBy: { name: 'asc' },
        });
        return { books: permitted, accounts };
    }
}

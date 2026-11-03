import { inject, injectable } from 'tsyringe';
import { HousingProperty, Prisma, PrismaClient } from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import { createHash, randomUUID } from 'node:crypto';
import { z } from 'zod';
import { AppError, ConflictError, NotFoundError } from '../../core/errors/AppError';
import { withFinancialTransaction } from '../../core/db/transaction';
import { housingWorkspace } from './housing-access';
import {
    AddUnitsInput,
    BatchPreviewInput,
    CreatePropertyInput,
    PropertyPreviewInput,
    addUnitsSchema,
    batchPreviewSchema,
    createPropertySchema,
    propertyPreviewSchema,
    propertyQuerySchema,
    updatePropertySchema,
    UnitInput,
    unitSchema,
} from './housing.dto';

const keyOf = (name: string) => name.trim().toLowerCase();
export const propertySelect = {
    id: true,
    name: true,
    address: true,
    archivedAt: true,
} satisfies Prisma.HousingPropertySelect;
export const housingLabel = (unit: { name: string; property: { name: string } }) =>
    `${unit.property.name} · ${unit.name}`;

export function housingConflict(error: unknown): never {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
        throw new ConflictError(
            'That property name or unit label is already in use, including archived records. Choose a different name.',
        );
    }
    throw error;
}

/** Property precedes unit and tenancy locks. A unit can never move properties. */
export async function lockHousingUnit(
    tx: Prisma.TransactionClient,
    workspaceId: string,
    id: string,
) {
    const probe = await tx.housingUnit.findFirst({
        where: { id, workspaceId },
        select: { propertyId: true },
    });
    if (!probe) throw new NotFoundError('Unit');
    await tx.$queryRaw`SELECT id FROM housing_properties WHERE id = ${probe.propertyId}::uuid AND workspace_id = ${workspaceId}::uuid FOR UPDATE`;
    await tx.$queryRaw`SELECT id FROM housing_units WHERE id = ${id}::uuid AND workspace_id = ${workspaceId}::uuid FOR UPDATE`;
    const unit = await tx.housingUnit.findFirst({
        where: { id, workspaceId },
        include: { property: true },
    });
    if (!unit) throw new NotFoundError('Unit');
    return unit;
}

type ResolvedUnit = {
    name: string;
    kind: HousingProperty['defaultKind'];
    monthlyRent: string;
    description?: string;
};
type Defaults = {
    defaultKind: HousingProperty['defaultKind'];
    defaultMonthlyRent: string | Decimal;
    unitLabelPrefix: string;
    unitNumberStart: number;
};
type ProvisioningResult = { propertyId: string; unitIds: string[] };

function canonical(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === 'object')
        return Object.fromEntries(
            Object.entries(value)
                .filter(([, v]) => v !== undefined)
                .sort(([a], [b]) => a.localeCompare(b))
                .map(([k, v]) => [k, canonical(v)]),
        );
    return value;
}
const digest = (value: unknown) =>
    createHash('sha256')
        .update(JSON.stringify(canonical(value)))
        .digest('hex');

/** Reserve every explicit label first, including labels later in the grid. */
export function generateHousingUnits(
    input: BatchPreviewInput,
    defaults: Defaults,
    existing: string[] = [],
): ResolvedUnit[] {
    const used = new Set(existing.map(keyOf));
    const rows: NonNullable<BatchPreviewInput['units']> =
        input.units ?? Array.from({ length: input.unitCount }, () => ({}));
    for (const [index, row] of rows.entries()) {
        if (!row.name?.trim()) continue;
        const key = keyOf(row.name);
        if (used.has(key))
            throw new AppError(
                `Unit row ${index + 1}: label "${row.name}" is already in use.`,
                409,
                'UNIT_LABEL_CONFLICT',
            );
        used.add(key);
    }
    let number = input.unitNumberStart ?? defaults.unitNumberStart;
    const prefix = input.unitLabelPrefix ?? defaults.unitLabelPrefix;
    return rows.map((row) => {
        let name = row.name?.trim();
        if (!name) {
            do {
                name = `${prefix}${String(number++).padStart(2, '0')}`.trim();
            } while (used.has(keyOf(name)));
            used.add(keyOf(name));
        }
        return {
            name,
            kind: row.kind ?? input.defaultKind ?? defaults.defaultKind,
            monthlyRent: new Decimal(
                row.monthlyRent ?? input.defaultMonthlyRent ?? defaults.defaultMonthlyRent,
            ).toString(),
            ...(row.description === undefined ? {} : { description: row.description }),
        };
    });
}

@injectable()
export class HousingPropertiesService {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) {}

    async property(tx: Prisma.TransactionClient, workspaceId: string, id: string, lock = false) {
        if (lock)
            await tx.$queryRaw`SELECT id FROM housing_properties WHERE id = ${id}::uuid AND workspace_id = ${workspaceId}::uuid FOR UPDATE`;
        const property = await tx.housingProperty.findFirst({ where: { id, workspaceId } });
        if (!property) throw new NotFoundError('Property');
        return property;
    }

    async list(workspaceId: string, userId: string, q: z.infer<typeof propertyQuerySchema>) {
        await housingWorkspace(this.prisma, workspaceId, userId);
        const where: Prisma.HousingPropertyWhereInput = {
            workspaceId,
            archivedAt: q.archived === 'true' ? { not: null } : null,
            ...(q.search
                ? {
                      OR: [
                          { name: { contains: q.search, mode: 'insensitive' } },
                          { address: { contains: q.search, mode: 'insensitive' } },
                      ],
                  }
                : {}),
        };
        const [rows, total] = await Promise.all([
            this.prisma.housingProperty.findMany({
                where,
                skip: (q.page - 1) * q.limit,
                take: q.limit,
                orderBy: [{ name: 'asc' }, { id: 'asc' }],
            }),
            this.prisma.housingProperty.count({ where }),
        ]);
        const counts = await this.counts(rows.map((p) => p.id));
        return {
            data: rows.map((p) => ({ ...p, ...counts.get(p.id) })),
            total,
            page: q.page,
            limit: q.limit,
        };
    }

    private async counts(ids: string[]) {
        const result = new Map<
            string,
            {
                totalUnits: number;
                units: number;
                archivedUnits: number;
                assigned: number;
                unassigned: number;
            }
        >();
        if (!ids.length) return result;
        const rows = await this.prisma.$queryRaw<
            Array<{ property_id: string; total: bigint; active: bigint; assigned: bigint }>
        >(Prisma.sql`
            SELECT u.property_id, count(*) AS total,
                count(*) FILTER (WHERE u.archived_at IS NULL) AS active,
                count(*) FILTER (WHERE u.archived_at IS NULL AND EXISTS (
                    SELECT 1 FROM housing_tenancies t WHERE t.unit_id = u.id AND t.status = 'ACTIVE'
                )) AS assigned
            FROM housing_units u WHERE u.property_id IN (${Prisma.join(ids.map((id) => Prisma.sql`${id}::uuid`))})
            GROUP BY u.property_id`);
        for (const id of ids) {
            const row = rows.find((r) => r.property_id === id);
            const totalUnits = Number(row?.total ?? 0),
                units = Number(row?.active ?? 0),
                assigned = Number(row?.assigned ?? 0);
            result.set(id, {
                totalUnits,
                units,
                archivedUnits: totalUnits - units,
                assigned,
                unassigned: units - assigned,
            });
        }
        return result;
    }

    async detail(workspaceId: string, userId: string, id: string) {
        await housingWorkspace(this.prisma, workspaceId, userId);
        const property = await this.property(this.prisma, workspaceId, id);
        return { ...property, ...(await this.counts([id])).get(id) };
    }

    private propertyPreview(input: z.infer<typeof propertyPreviewSchema>, currency: string) {
        const units = generateHousingUnits(input, input);
        return { units, currency, previewToken: digest({ input, units, currency }) };
    }

    async preview(workspaceId: string, userId: string, input: PropertyPreviewInput) {
        const dto = propertyPreviewSchema.parse(input);
        const workspace = await housingWorkspace(this.prisma, workspaceId, userId, true);
        return this.propertyPreview(dto, workspace.defaultCurrency);
    }

    private async batchPreview(
        tx: Prisma.TransactionClient,
        property: HousingProperty,
        input: BatchPreviewInput,
    ) {
        if (property.archivedAt)
            throw new ConflictError('Restore this property before adding units');
        const existing = await tx.housingUnit.findMany({
            where: { propertyId: property.id },
            select: { name: true },
        });
        const units = generateHousingUnits(
            input,
            property,
            existing.map((u) => u.name),
        );
        return {
            units,
            currency: property.currency,
            expectedVersion: property.version,
            previewToken: digest({
                input,
                units,
                propertyId: property.id,
                version: property.version,
                currency: property.currency,
            }),
        };
    }

    async previewUnits(workspaceId: string, userId: string, id: string, input: BatchPreviewInput) {
        const dto = batchPreviewSchema.parse(input);
        await housingWorkspace(this.prisma, workspaceId, userId, true);
        return this.batchPreview(
            this.prisma,
            await this.property(this.prisma, workspaceId, id),
            dto,
        );
    }

    private async replay(
        tx: Prisma.TransactionClient,
        workspaceId: string,
        userId: string,
        requestId: string,
        hash: string,
    ) {
        const request = await tx.housingProvisioningRequest.findUnique({
            where: { workspaceId_userId_requestId: { workspaceId, userId, requestId } },
        });
        if (!request) return null;
        if (request.requestHash !== hash)
            throw new ConflictError(
                'This request reference was already used with different details',
            );
        return request.result as unknown as ProvisioningResult;
    }

    private async provision(
        workspaceId: string,
        userId: string,
        requestId: string,
        operation: string,
        input: unknown,
        work: (tx: Prisma.TransactionClient) => Promise<ProvisioningResult>,
    ) {
        const hash = digest({ operation, input });
        try {
            return await withFinancialTransaction(this.prisma, async (tx) => {
                await housingWorkspace(tx, workspaceId, userId, true);
                // Serializes identical requests across processes, including property creation.
                await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(${`${workspaceId}:${userId}:${requestId}`}, 0))`;
                const previous = await this.replay(tx, workspaceId, userId, requestId, hash);
                if (previous) return previous;
                const result = await work(tx);
                await tx.housingProvisioningRequest.create({
                    data: {
                        workspaceId,
                        userId,
                        requestId,
                        operation,
                        requestHash: hash,
                        propertyId: result.propertyId,
                        result,
                    },
                });
                await tx.auditLog.create({
                    data: {
                        workspaceId,
                        userId,
                        action:
                            operation === 'CREATE_PROPERTY'
                                ? 'HOUSING_PROPERTY_CREATED'
                                : 'HOUSING_UNITS_ADDED',
                        resource: 'housing',
                        resourceId: result.propertyId,
                        details: { requestId, unitIds: result.unitIds },
                    },
                });
                return result;
            });
        } catch (error) {
            return housingConflict(error);
        }
    }

    private async insertUnits(
        tx: Prisma.TransactionClient,
        property: HousingProperty,
        units: ResolvedUnit[],
    ) {
        const data = units.map((u) => ({
            ...u,
            id: randomUUID(),
            propertyId: property.id,
            workspaceId: property.workspaceId,
            currency: property.currency,
        }));
        await tx.housingUnit.createMany({ data });
        return { propertyId: property.id, unitIds: data.map((u) => u.id) };
    }

    async create(workspaceId: string, userId: string, input: CreatePropertyInput) {
        const { requestId, previewToken, ...dto } = createPropertySchema.parse(input);
        return this.provision(
            workspaceId,
            userId,
            requestId,
            'CREATE_PROPERTY',
            { ...dto, previewToken },
            async (tx) => {
                const ws = await housingWorkspace(tx, workspaceId, userId, true);
                const preview = this.propertyPreview(dto, ws.defaultCurrency);
                if (previewToken !== preview.previewToken)
                    throw new ConflictError(
                        'The property setup changed. Review the units again before saving',
                    );
                const { unitCount, units, ...fields } = dto;
                const property = await tx.housingProperty.create({
                    data: { ...fields, workspaceId, currency: ws.defaultCurrency },
                });
                return this.insertUnits(tx, property, preview.units);
            },
        );
    }

    async addUnits(workspaceId: string, userId: string, id: string, input: AddUnitsInput) {
        const { requestId, previewToken, expectedVersion, ...dto } = addUnitsSchema.parse(input);
        return this.provision(
            workspaceId,
            userId,
            requestId,
            'ADD_UNITS',
            { id, ...dto, previewToken, expectedVersion },
            async (tx) => {
                const property = await this.property(tx, workspaceId, id, true);
                if (property.version !== expectedVersion)
                    throw new ConflictError(
                        'The property changed. Review the units again before saving',
                    );
                const preview = await this.batchPreview(tx, property, dto);
                if (previewToken !== preview.previewToken)
                    throw new ConflictError(
                        'The unit setup changed. Review the units again before saving',
                    );
                const result = await this.insertUnits(tx, property, preview.units);
                await tx.housingProperty.update({
                    where: { id },
                    data: { version: { increment: 1 } },
                });
                return result;
            },
        );
    }

    /** Compatibility endpoint: explicit property, one named unit, durable identity. */
    async createUnit(workspaceId: string, userId: string, input: UnitInput) {
        const { propertyId, requestId, ...dto } = unitSchema.parse(input);
        const result = await this.provision(
            workspaceId,
            userId,
            requestId,
            'ADD_UNITS',
            { propertyId, unit: dto },
            async (tx) => {
                const property = await this.property(tx, workspaceId, propertyId, true);
                const preview = await this.batchPreview(tx, property, {
                    unitCount: 1,
                    units: [dto],
                });
                const created = await this.insertUnits(tx, property, preview.units);
                await tx.housingProperty.update({
                    where: { id: propertyId },
                    data: { version: { increment: 1 } },
                });
                return created;
            },
        );
        return this.prisma.housingUnit.findUniqueOrThrow({ where: { id: result.unitIds[0] } });
    }

    async update(
        workspaceId: string,
        userId: string,
        id: string,
        input: z.infer<typeof updatePropertySchema>,
    ) {
        const { expectedVersion, archived, ...dto } = updatePropertySchema.parse(input);
        try {
            return await withFinancialTransaction(this.prisma, async (tx) => {
                await housingWorkspace(tx, workspaceId, userId, true);
                const property = await this.property(tx, workspaceId, id, true);
                if (property.version !== expectedVersion)
                    throw new ConflictError('The property changed. Refresh and try again');
                if (
                    archived &&
                    (await tx.housingTenancy.count({
                        where: { unit: { propertyId: id }, status: 'ACTIVE' },
                    }))
                )
                    throw new ConflictError(
                        'End all active or scheduled tenancies before archiving this property',
                    );
                const updated = await tx.housingProperty.update({
                    where: { id },
                    data: {
                        ...dto,
                        ...(archived === undefined
                            ? {}
                            : { archivedAt: archived ? new Date() : null }),
                        version: { increment: 1 },
                    },
                });
                await tx.auditLog.create({
                    data: {
                        workspaceId,
                        userId,
                        action: 'HOUSING_PROPERTY_UPDATED',
                        resource: 'housing',
                        resourceId: id,
                        details: {
                            before: {
                                name: property.name,
                                address: property.address,
                                archivedAt: property.archivedAt?.toISOString() ?? null,
                            },
                            changes: { ...dto, archived: archived ?? null },
                        },
                    },
                });
                return updated;
            });
        } catch (error) {
            return housingConflict(error);
        }
    }
}

import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { testPrisma as db, resetDatabase } from '../setup';
import { resolveService } from '../container';
import { createUser, createWorkspace, addWorkspaceMember } from '../factories';
import { HousingPropertiesService } from '../../modules/housing/housing-properties.service';
import { HousingService } from '../../modules/housing/housing.service';
import { propertyPreviewSchema, updateUnitSchema } from '../../modules/housing/housing.dto';

const properties = () => resolveService(HousingPropertiesService);
const housing = () => resolveService(HousingService);
const input = { name: 'Sunrise', address: 'Ntinda', defaultMonthlyRent: '100.125', unitCount: 10 };
let app: import('express').Express;
beforeAll(async () => {
    await import('../../config/container');
    app = (await import('../../app')).default;
});
beforeEach(resetDatabase);
async function fixture() {
    const owner = await createUser();
    const workspace = await createWorkspace(owner.id);
    const preview = await properties().preview(workspace.id, owner.id, input);
    const dto = { ...input, previewToken: preview.previewToken, requestId: randomUUID() };
    const result = (await properties().create(workspace.id, owner.id, dto))!;
    return { owner, workspace, dto, result, unitId: result.unitIds[0] };
}
async function batch(f: Awaited<ReturnType<typeof fixture>>, names?: string[]) {
    const dto = {
        unitCount: names?.length ?? 2,
        ...(names ? { units: names.map((name) => ({ name })) } : {}),
    };
    const preview = await properties().previewUnits(
        f.workspace.id,
        f.owner.id,
        f.result.propertyId,
        dto,
    );
    return {
        ...dto,
        previewToken: preview.previewToken,
        expectedVersion: preview.expectedVersion,
        requestId: randomUUID(),
    };
}

describe('property-first housing', () => {
    it('previews without writing, then creates exactly ten identifiable units and accurate counts', async () => {
        const owner = await createUser(),
            ws = await createWorkspace(owner.id);
        const preview = await properties().preview(ws.id, owner.id, input);
        expect(preview.units.map((u) => u.name)).toEqual(
            Array.from({ length: 10 }, (_, i) => `Unit ${String(i + 1).padStart(2, '0')}`),
        );
        expect(await db.housingProperty.count()).toBe(0);
        const result = (await properties().create(ws.id, owner.id, {
            ...input,
            previewToken: preview.previewToken,
            requestId: randomUUID(),
        }))!;
        expect(await properties().detail(ws.id, owner.id, result.propertyId)).toMatchObject({
            totalUnits: 10,
            assigned: 0,
            unassigned: 10,
        });
        const units = await db.housingUnit.findMany({ orderBy: { name: 'asc' } });
        expect(
            units.map((u) => ({
                name: u.name,
                kind: u.kind,
                monthlyRent: u.monthlyRent.toString(),
            })),
        ).toEqual(preview.units);
        expect(await db.entry.count()).toBe(0);
    });

    it('reserves custom labels before generating blanks and applies rent/type overrides', async () => {
        const owner = await createUser(),
            ws = await createWorkspace(owner.id);
        const preview = await properties().preview(ws.id, owner.id, {
            ...input,
            unitCount: 3,
            units: [{}, { name: 'Unit 01', kind: 'HOUSE', monthlyRent: '250' }, { name: 'A1' }],
        });
        expect(preview.units).toEqual([
            { name: 'Unit 02', kind: 'APARTMENT', monthlyRent: '100.125' },
            { name: 'Unit 01', kind: 'HOUSE', monthlyRent: '250' },
            { name: 'A1', kind: 'APARTMENT', monthlyRent: '100.125' },
        ]);
    });

    it('supports prefixes, starting numbers, one-unit houses and a 500-unit batch', async () => {
        const owner = await createUser(),
            ws = await createWorkspace(owner.id);
        const setup = {
            ...input,
            unitCount: 500,
            defaultKind: 'HOUSE' as const,
            unitLabelPrefix: 'B-',
            unitNumberStart: 98,
        };
        const preview = await properties().preview(ws.id, owner.id, setup);
        expect(preview.units[0].name).toBe('B-98');
        expect(preview.units[499].name).toBe('B-597');
        await properties().create(ws.id, owner.id, {
            ...setup,
            previewToken: preview.previewToken,
            requestId: randomUUID(),
        });
        expect(await db.housingUnit.count()).toBe(500);
    });

    it('rejects invalid counts, mismatched rows and duplicate labels without partial data', async () => {
        const owner = await createUser(),
            ws = await createWorkspace(owner.id);
        for (const unitCount of [0, -1, 1.5, 501])
            expect(propertyPreviewSchema.safeParse({ ...input, unitCount }).success).toBe(false);
        expect(propertyPreviewSchema.safeParse({ ...input, units: [{}] }).success).toBe(false);
        await expect(
            properties().preview(ws.id, owner.id, {
                ...input,
                unitCount: 2,
                units: [{ name: ' a1 ' }, { name: 'A1' }],
            }),
        ).rejects.toMatchObject({ statusCode: 409 });
        await expect(
            properties().create(ws.id, owner.id, {
                ...input,
                previewToken: '0'.repeat(64),
                requestId: randomUUID(),
            }),
        ).rejects.toMatchObject({ statusCode: 409 });
        expect(await db.housingProperty.count()).toBe(0);
        expect(await db.housingUnit.count()).toBe(0);
    });

    it('replays simultaneous property requests and refuses changed reference reuse', async () => {
        const f = await fixture();
        const results = await Promise.all([
            properties().create(f.workspace.id, f.owner.id, f.dto),
            properties().create(f.workspace.id, f.owner.id, f.dto),
        ]);
        expect(results).toEqual([f.result, f.result]);
        expect(await db.housingProperty.count()).toBe(1);
        expect(await db.housingUnit.count()).toBe(10);
        await expect(
            properties().create(f.workspace.id, f.owner.id, { ...f.dto, name: 'Changed' }),
        ).rejects.toMatchObject({ statusCode: 409 });
    });

    it('serializes two new requests for the same property name and preserves labels across properties', async () => {
        const f = await fixture();
        const setup = { ...input, name: 'Sunrise – Bukoto' };
        const preview = await properties().preview(f.workspace.id, f.owner.id, setup);
        const dto = { ...setup, previewToken: preview.previewToken, requestId: randomUUID() };
        const results = await Promise.allSettled([
            properties().create(f.workspace.id, f.owner.id, dto),
            properties().create(f.workspace.id, f.owner.id, { ...dto, requestId: randomUUID() }),
        ]);
        expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
        expect(await db.housingUnit.count({ where: { name: 'Unit 01' } })).toBe(2);
        const collision = { ...input, name: ' sunrise ' };
        const check = await properties().preview(f.workspace.id, f.owner.id, collision);
        await expect(
            properties().create(f.workspace.id, f.owner.id, {
                ...collision,
                previewToken: check.previewToken,
                requestId: randomUUID(),
            }),
        ).rejects.toMatchObject({ statusCode: 409 });
    });

    it('adds units once, reserves archived labels, and retains property currency', async () => {
        const f = await fixture();
        await housing().updateUnit(f.workspace.id, f.owner.id, f.unitId, {
            expectedVersion: 1,
            archived: true,
        });
        await db.workspace.update({
            where: { id: f.workspace.id },
            data: { defaultCurrency: 'USD' },
        });
        const dto = await batch(f);
        const results = await Promise.all([
            properties().addUnits(f.workspace.id, f.owner.id, f.result.propertyId, dto),
            properties().addUnits(f.workspace.id, f.owner.id, f.result.propertyId, dto),
        ]);
        expect(results[0]).toEqual(results[1]);
        const added = await db.housingUnit.findMany({
            where: { id: { in: results[0]!.unitIds } },
            orderBy: { name: 'asc' },
        });
        expect(added.map((u) => u.name)).toEqual(['Unit 11', 'Unit 12']);
        expect(added.every((u) => u.currency === 'UGX')).toBe(true);
        await expect(batch(f, [' unit 01 '])).rejects.toMatchObject({ statusCode: 409 });
    });

    it('rejects stale previews after defaults, labels, or inventory change', async () => {
        const f = await fixture();
        const dto = await batch(f);
        await housing().updateUnit(f.workspace.id, f.owner.id, f.unitId, {
            expectedVersion: 1,
            name: 'Renamed',
        });
        await expect(
            properties().addUnits(f.workspace.id, f.owner.id, f.result.propertyId, dto),
        ).rejects.toMatchObject({ statusCode: 409 });
        expect(await db.housingUnit.count()).toBe(10);
        const fresh = await batch(f);
        const results = await Promise.allSettled([
            properties().addUnits(f.workspace.id, f.owner.id, f.result.propertyId, fresh),
            properties().addUnits(f.workspace.id, f.owner.id, f.result.propertyId, {
                ...fresh,
                requestId: randomUUID(),
            }),
        ]);
        expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    });

    it('preserves room/house types on unrelated patches and leaves existing rents alone', async () => {
        const f = await fixture();
        expect(updateUnitSchema.parse({ expectedVersion: 1, archived: true })).not.toHaveProperty(
            'kind',
        );
        await housing().updateUnit(f.workspace.id, f.owner.id, f.unitId, {
            expectedVersion: 1,
            kind: 'ROOM',
        });
        await housing().updateUnit(f.workspace.id, f.owner.id, f.unitId, {
            expectedVersion: 2,
            archived: true,
        });
        await housing().updateUnit(f.workspace.id, f.owner.id, f.unitId, {
            expectedVersion: 3,
            archived: false,
            monthlyRent: '150',
        });
        const property = await properties().detail(f.workspace.id, f.owner.id, f.result.propertyId);
        await properties().update(f.workspace.id, f.owner.id, property.id, {
            expectedVersion: property.version,
            defaultMonthlyRent: '900',
            defaultKind: 'HOUSE',
        });
        expect(await db.housingUnit.findUnique({ where: { id: f.unitId } })).toMatchObject({
            kind: 'ROOM',
        });
        expect(
            (
                await db.housingUnit.findUniqueOrThrow({ where: { id: f.unitId } })
            ).monthlyRent.toString(),
        ).toBe('150');
        const preview = await properties().previewUnits(f.workspace.id, f.owner.id, property.id, {
            unitCount: 1,
        });
        expect(preview.units[0]).toMatchObject({ monthlyRent: '900', kind: 'HOUSE' });
    });

    it('keeps archived properties out of workspace counts and restores individual archive states', async () => {
        const f = await fixture();
        await housing().updateUnit(f.workspace.id, f.owner.id, f.unitId, {
            expectedVersion: 1,
            archived: true,
        });
        const p = await properties().detail(f.workspace.id, f.owner.id, f.result.propertyId);
        await properties().update(f.workspace.id, f.owner.id, p.id, {
            expectedVersion: p.version,
            archived: true,
        });
        expect(await housing().summary(f.workspace.id, f.owner.id)).toMatchObject({
            properties: 0,
            units: 0,
            unassigned: 0,
        });
        await expect(batch(f)).rejects.toMatchObject({ statusCode: 409 });
        await expect(
            housing().updateUnit(f.workspace.id, f.owner.id, f.unitId, {
                expectedVersion: 2,
                archived: false,
            }),
        ).rejects.toMatchObject({ statusCode: 409 });
        await properties().update(f.workspace.id, f.owner.id, p.id, {
            expectedVersion: p.version + 1,
            archived: false,
        });
        expect(await properties().detail(f.workspace.id, f.owner.id, p.id)).toMatchObject({
            units: 9,
            archivedUnits: 1,
        });
    });

    it('serializes property archival against assignment and preserves unit history on rename', async () => {
        const f = await fixture();
        const results = await Promise.allSettled([
            properties().update(f.workspace.id, f.owner.id, f.result.propertyId, {
                expectedVersion: 1,
                archived: true,
            }),
            housing().createTenancy(f.workspace.id, f.owner.id, {
                unitId: f.unitId,
                tenantName: 'Tenant',
                monthlyRent: '100',
                startDate: '2026-01-01',
                dueDay: 1,
            }),
        ]);
        expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
        const property = await db.housingProperty.findUniqueOrThrow({
            where: { id: f.result.propertyId },
        });
        if (property.archivedAt) expect(await db.housingTenancy.count()).toBe(0);
        else expect(await db.housingTenancy.count()).toBe(1);
    });

    it('blocks archival of scheduled tenancies and filters history by property', async () => {
        const f = await fixture();
        const tenancy = await housing().createTenancy(f.workspace.id, f.owner.id, {
            unitId: f.unitId,
            tenantName: 'Future tenant',
            monthlyRent: '100',
            startDate: '2099-01-01',
            dueDay: 1,
        });
        await expect(
            properties().update(f.workspace.id, f.owner.id, f.result.propertyId, {
                expectedVersion: 1,
                archived: true,
            }),
        ).rejects.toMatchObject({ statusCode: 409 });
        await housing().updateUnit(f.workspace.id, f.owner.id, f.unitId, {
            expectedVersion: 1,
            name: 'A1',
        });
        const view = await housing().detail(tenancy.id, f.owner.id, f.workspace.id);
        expect(view.unit).toMatchObject({
            id: f.unitId,
            name: 'A1',
            propertyId: f.result.propertyId,
            propertyName: 'Sunrise',
        });
        expect(
            (
                await housing().tenancies(f.workspace.id, f.owner.id, {
                    page: 1,
                    limit: 20,
                    propertyId: f.result.propertyId,
                })
            ).total,
        ).toBe(1);
    });

    it('enforces property/workspace/currency relationships at the database boundary', async () => {
        const f = await fixture();
        const other = await createWorkspace(f.owner.id);
        await expect(
            db.housingUnit.create({
                data: {
                    workspaceId: other.id,
                    propertyId: f.result.propertyId,
                    name: 'Foreign',
                    currency: 'UGX',
                    monthlyRent: '100',
                },
            }),
        ).rejects.toThrow();
        await expect(
            db.housingUnit.create({
                data: {
                    workspaceId: f.workspace.id,
                    propertyId: f.result.propertyId,
                    name: 'Wrong currency',
                    currency: 'USD',
                    monthlyRent: '100',
                },
            }),
        ).rejects.toThrow();
        await expect(
            db.housingUnit.create({
                data: {
                    workspaceId: f.workspace.id,
                    propertyId: f.result.propertyId,
                    name: ' unit 01 ',
                    currency: 'UGX',
                    monthlyRent: '100',
                },
            }),
        ).rejects.toThrow();
    });

    it('creates and adds reviewed units through HTTP with durable retry recovery', async () => {
        const owner = await createUser();
        const workspace = await createWorkspace(owner.id);
        const auth = `accessToken=${jwt.sign({ userId: owner.id, email: owner.email }, process.env.JWT_ACCESS_SECRET!)}`;
        const base = `/api/v1/workspaces/${workspace.id}/housing/properties`;
        const preview = await request(app)
            .post(`${base}/preview`)
            .set('Cookie', auth)
            .send(input)
            .expect(200);
        const body = {
            ...input,
            previewToken: preview.body.data.previewToken,
            requestId: randomUUID(),
        };
        const created = await request(app).post(base).set('Cookie', auth).send(body).expect(200);
        const replayed = await request(app).post(base).set('Cookie', auth).send(body).expect(200);
        expect(replayed.body.data).toEqual(created.body.data);
        const id = created.body.data.propertyId;
        const batchInput = {
            unitCount: 2,
            units: [{}, { name: 'Unit 11', kind: 'ROOM', monthlyRent: '200' }],
        };
        const batchPreview = await request(app)
            .post(`${base}/${id}/units/preview`)
            .set('Cookie', auth)
            .send(batchInput)
            .expect(200);
        expect(batchPreview.body.data.units.map((u: { name: string }) => u.name)).toEqual([
            'Unit 12',
            'Unit 11',
        ]);
        const batchBody = {
            ...batchInput,
            previewToken: batchPreview.body.data.previewToken,
            expectedVersion: batchPreview.body.data.expectedVersion,
            requestId: randomUUID(),
        };
        const added = await request(app)
            .post(`${base}/${id}/units`)
            .set('Cookie', auth)
            .send(batchBody)
            .expect(200);
        const repeated = await request(app)
            .post(`${base}/${id}/units`)
            .set('Cookie', auth)
            .send(batchBody)
            .expect(200);
        expect(repeated.body.data).toEqual(added.body.data);
        expect(await db.housingUnit.count({ where: { propertyId: id } })).toBe(12);
        expect(await db.housingProvisioningRequest.count()).toBe(2);
    });

    it('exposes only the accepted tenant’s own property and unit context', async () => {
        const f = await fixture();
        const tenant = await createUser();
        const tenancy = await housing().createTenancy(f.workspace.id, f.owner.id, {
            unitId: f.unitId,
            tenantName: 'Resident',
            startDate: '2026-11-01',
            monthlyRent: '100',
            dueDay: 1,
            notes: 'Private management note',
        });
        await db.housingTenancy.update({
            where: { id: tenancy.id },
            data: { tenantUserId: tenant.id, invitationStatus: 'ACCEPTED' },
        });
        const auth = `accessToken=${jwt.sign({ userId: tenant.id, email: tenant.email }, process.env.JWT_ACCESS_SECRET!)}`;
        const detail = await request(app)
            .get(`/api/v1/housing/tenancies/${tenancy.id}`)
            .set('Cookie', auth)
            .expect(200);
        expect(detail.body.data.unit).toMatchObject({
            id: f.unitId,
            name: 'Unit 01',
            propertyId: f.result.propertyId,
            propertyName: 'Sunrise',
        });
        expect(detail.body.data.unit.property).toEqual({
            id: f.result.propertyId,
            name: 'Sunrise',
            address: 'Ntinda',
        });
        expect(detail.body.data).not.toHaveProperty('notes');
        expect(detail.body.data.unit).not.toHaveProperty('tenancies');
        const base = `/api/v1/workspaces/${f.workspace.id}/housing`;
        await request(app)
            .get(`${base}/properties/${f.result.propertyId}`)
            .set('Cookie', auth)
            .expect(403);
        await request(app).get(`${base}/units`).set('Cookie', auth).expect(403);
        await request(app)
            .post(`${base}/properties/preview`)
            .set('Cookie', auth)
            .send(input)
            .expect(403);
    });

    it('protects HTTP contracts, reports legacy registration clearly and paginates scoped lists', async () => {
        const f = await fixture();
        const member = await createUser();
        await addWorkspaceMember(f.workspace.id, member.id);
        const cookie = (id: string, email: string) =>
            `accessToken=${jwt.sign({ userId: id, email }, process.env.JWT_ACCESS_SECRET!)}`;
        const base = `/api/v1/workspaces/${f.workspace.id}/housing`;
        expect(
            (
                await request(app)
                    .post(`${base}/properties/preview`)
                    .set('Cookie', cookie(member.id, member.email))
                    .send(input)
            ).status,
        ).toBe(403);
        const auth = cookie(f.owner.id, f.owner.email);
        const legacy = await request(app)
            .post(`${base}/units`)
            .set('Cookie', auth)
            .send({ name: 'Legacy unit', monthlyRent: '100' });
        expect(legacy.status).toBe(400);
        expect(JSON.stringify(legacy.body)).toContain('Create or select a property');
        const units = await request(app)
            .get(`${base}/units`)
            .set('Cookie', auth)
            .query({ propertyId: f.result.propertyId, page: 2, limit: 3 });
        expect(units.body.data.total).toBe(10);
        expect(units.body.data.data).toHaveLength(3);
        const other = await createWorkspace(f.owner.id);
        expect(
            (
                await request(app)
                    .get(`/api/v1/workspaces/${other.id}/housing/properties/${f.result.propertyId}`)
                    .set('Cookie', auth)
            ).status,
        ).toBe(404);
        expect(
            (await request(app).get(`${base}/properties/not-a-uuid`).set('Cookie', auth)).status,
        ).toBe(400);
    });
});

import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { Decimal } from '@prisma/client/runtime/library';
import { testPrisma as db, resetDatabase } from '../setup';
import { resolveService } from '../container';
import {
    createUser,
    createWorkspace,
    createCashbook,
    createAccount,
    addWorkspaceMember,
    createInventoryItem,
} from '../factories';
import {
    provisionWorkspaceAccounting,
    ensureCashbookLedgerAccount,
    ensureWalletLedgerAccount,
} from '../../core/ledger/coa.seed';
import { HousingPropertiesService } from '../../modules/housing/housing-properties.service';
import { HousingService } from '../../modules/housing/housing.service';
import { HousingMediaService } from '../../modules/housing/housing-media.service';
import { StorageService } from '../../modules/files/storage.service';
import { RentalIssuesService } from '../../modules/rental-issues/rental-issues.service';
import { EntriesService } from '../../modules/entries/entries.service';
import { SharedEntriesService } from '../../modules/shared-entries/shared-entries.service';
import { monthlySchedule, dbDate } from '../../modules/housing/housing-schedule';
import { scanHousing } from '../../jobs/housingScheduler';
import { purgeWorkspace } from '../../modules/account-deletion/account-deletion.service';
import sharp from 'sharp';

const svc = () => resolveService(HousingService);
const issues = () => resolveService(RentalIssuesService);
let app: import('express').Express;
beforeAll(async () => {
    await import('../../config/container');
    app = (await import('../../app')).default;
});
beforeEach(resetDatabase);
const page = { page: 1, limit: 100 };
async function side(userId: string) {
    const workspace = await createWorkspace(userId);
    const book = await createCashbook(workspace.id, userId);
    const account = await createAccount(workspace.id, { allowNegative: true });
    await db.$transaction(async (tx) => {
        await provisionWorkspaceAccounting(tx, workspace.id, 'UGX');
        await ensureCashbookLedgerAccount(tx, book);
        const wallet = await tx.account.findUniqueOrThrow({
            where: { id: account.id },
            include: { accountType: true },
        });
        await ensureWalletLedgerAccount(tx, wallet, wallet.accountType.classification);
    });
    return { workspace, book, account };
}
async function fixture(linked = true) {
    const owner = await createUser();
    const tenant = await createUser();
    const a = await side(owner.id);
    const b = await side(tenant.id);
    await db.workspace.update({ where: { id: b.workspace.id }, data: { type: 'PERSONAL' } });
    const contact = await db.contact.create({
        data: {
            name: 'Tenant',
            workspaceId: a.workspace.id,
            type: 'CUSTOMER',
            email: tenant.email,
        },
    });
    const properties = resolveService(HousingPropertiesService);
    const setup = {
        name: 'Sunrise Apartments',
        defaultMonthlyRent: '100.125',
        unitCount: 1,
        units: [{ name: 'A1' }],
    };
    const preview = await properties.preview(a.workspace.id, owner.id, setup);
    const created = await properties.create(a.workspace.id, owner.id, {
        ...setup,
        requestId: randomUUID(),
        previewToken: preview.previewToken,
    });
    const unit = await db.housingUnit.findUniqueOrThrow({ where: { id: created!.unitIds[0] } });
    const tenancy = await svc().createTenancy(a.workspace.id, owner.id, {
        unitId: unit.id,
        tenantName: 'Tenant',
        ...(linked ? { contactId: contact.id } : {}),
        monthlyRent: '100.125',
        startDate: '2026-01-31',
        dueDay: 31,
    });
    if (linked) await svc().respond(tenancy.id, tenant.id, true);
    const periods = await db.rentPeriod.findMany({
        where: { tenancyId: tenancy.id },
        orderBy: { startDate: 'asc' },
    });
    const pay = {
        requestId: randomUUID(),
        cashbookId: a.book.id,
        accountId: a.account.id,
        entryDate: '2026-02-01T09:00:00.000Z',
        allocations: [{ periodId: periods[0].id, amount: '40.025' }],
    };
    return { owner, tenant, a, b, contact, unit, tenancy, periods, pay };
}

describe('housing tenancies', () => {
    it('uses anniversary months without drift and requires explicit partial-period charges', () => {
        const terms = {
            startDate: dbDate('2024-01-31'),
            endDate: null,
            monthlyRent: new Decimal(100),
            firstPeriodAmount: null,
            finalPeriodAmount: null,
            dueDay: 31,
        };
        const schedule = monthlySchedule(terms, '2024-03-31');
        expect(schedule.map((p) => p.startDate.toISOString().slice(0, 10))).toEqual([
            '2024-01-31',
            '2024-02-29',
            '2024-03-31',
        ]);
        expect(() =>
            monthlySchedule({ ...terms, endDate: dbDate('2024-03-15') }, '2024-03-31'),
        ).toThrow('agreed amount');
        expect(
            monthlySchedule(
                {
                    ...terms,
                    endDate: dbDate('2024-03-15'),
                    finalPeriodAmount: new Decimal('45.25'),
                },
                '2024-03-31',
            )[1].amount.toString(),
        ).toBe('45.25');
    });
    it('supports offline tenants without creating an account/contact or any financial entry', async () => {
        const f = await fixture(false);
        expect(f.tenancy.tenantUserId).toBeNull();
        expect(await db.entry.count()).toBe(0);
        expect(await db.journalEntry.count({ where: { sourceType: 'CASHBOOK_ENTRY' } })).toBe(0);
        expect((await svc().tenancies(null, f.tenant.id, page)).data).toEqual([]);
        expect(f.periods).toHaveLength(12);
        expect(await db.contact.count()).toBe(1);
    });
    it('serializes assignments and preserves tenant history on move-out', async () => {
        const f = await fixture(false);
        const end = await svc().end(f.tenancy.id, f.a.workspace.id, f.owner.id, {
            endDate: '2026-02-28',
            reason: 'Moved out',
            expectedVersion: 1,
        });
        expect(end.status).toBe('ENDED');
        const input = {
            unitId: f.unit.id,
            tenantName: 'Next tenant',
            monthlyRent: '120',
            startDate: '2026-02-28',
            dueDay: 28,
        };
        const results = await Promise.allSettled([
            svc().createTenancy(f.a.workspace.id, f.owner.id, input),
            svc().createTenancy(f.a.workspace.id, f.owner.id, input),
        ]);
        expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
        expect(await db.housingTenancy.count({ where: { unitId: f.unit.id } })).toBe(2);
        await expect(
            svc().updateUnit(f.a.workspace.id, f.owner.id, f.unit.id, {
                archived: true,
                expectedVersion: 1,
            }),
        ).rejects.toThrow('End the active');
    });
    it('rejects overlapping history and invalid/foreign contacts', async () => {
        const f = await fixture(false);
        await svc().end(f.tenancy.id, f.a.workspace.id, f.owner.id, {
            endDate: '2026-02-28',
            reason: 'Moved out',
            expectedVersion: 1,
        });
        await expect(
            svc().createTenancy(f.a.workspace.id, f.owner.id, {
                unitId: f.unit.id,
                tenantName: 'Earlier',
                monthlyRent: '100',
                startDate: '2026-02-15',
                dueDay: 15,
            }),
        ).rejects.toThrow('overlap');
        const foreign = await db.contact.create({
            data: { workspaceId: f.b.workspace.id, name: 'Foreign', type: 'CUSTOMER' },
        });
        await expect(
            svc().createTenancy(f.a.workspace.id, f.owner.id, {
                unitId: f.unit.id,
                tenantName: 'Next',
                contactId: foreign.id,
                monthlyRent: '100',
                startDate: '2026-03-01',
                dueDay: 1,
            }),
        ).rejects.toThrow('contact');
    });
    it('requires tenant acceptance and isolates private landlord data and other tenants', async () => {
        const f = await fixture(false);
        await svc().invite(f.tenancy.id, f.a.workspace.id, f.owner.id, {
            contactId: f.contact.id,
            expectedVersion: 1,
        });
        const pending = await svc().detail(f.tenancy.id, f.tenant.id, null);
        expect(pending.periods).toEqual([]);
        expect(pending.landlordName).toBe(f.a.workspace.name);
        expect(pending).not.toHaveProperty('notes');
        expect(pending).not.toHaveProperty('contactId');
        await expect(
            issues().create(f.tenant.id, {
                tenancyId: f.tenancy.id,
                title: 'Test issue',
                description: 'My concern',
                kind: 'CONCERN',
                priority: 'NORMAL',
            }),
        ).rejects.toMatchObject({ statusCode: 404 });
        await svc().respond(f.tenancy.id, f.tenant.id, true);
        expect((await svc().detail(f.tenancy.id, f.tenant.id, null)).periods).toHaveLength(12);
        const stranger = await createUser();
        await expect(svc().detail(f.tenancy.id, stranger.id, null)).rejects.toMatchObject({
            statusCode: 404,
        });
        expect(
            await db.workspaceMember.count({
                where: { workspaceId: f.a.workspace.id, userId: f.tenant.id },
            }),
        ).toBe(0);
        const invitation = await db.notification.findFirstOrThrow({
            where: { userId: f.tenant.id, type: 'HOUSING_INVITATION' },
        });
        expect(invitation.workspaceId).toBe(f.b.workspace.id);
    });
    it('does not auto-link unverified users and lets an offline tenant link later', async () => {
        const f = await fixture(false);
        await db.user.update({ where: { id: f.tenant.id }, data: { emailVerified: false } });
        await expect(
            svc().invite(f.tenancy.id, f.a.workspace.id, f.owner.id, {
                contactId: f.contact.id,
                expectedVersion: 1,
            }),
        ).rejects.toThrow('verified');
        await db.user.update({ where: { id: f.tenant.id }, data: { emailVerified: true } });
        await svc().invite(f.tenancy.id, f.a.workspace.id, f.owner.id, {
            contactId: f.contact.id,
            expectedVersion: 1,
        });
        await svc().respond(f.tenancy.id, f.tenant.id, false);
        expect((await svc().detail(f.tenancy.id, f.tenant.id, null)).periods).toEqual([]);
    });
    it('posts partial/advance payments once, creates a shared expense offer, and keeps decimal ledger balances exact', async () => {
        const f = await fixture();
        const input = {
            ...f.pay,
            allocations: [...f.pay.allocations, { periodId: f.periods[1].id, amount: '100.125' }],
        };
        const [one, two] = await Promise.all([
            svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, input),
            svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, input),
        ]);
        expect(one.entryId).toBe(two.entryId);
        expect(await db.rentPayment.count()).toBe(1);
        expect(await db.entry.count()).toBe(1);
        expect(
            (
                await db.account.findUniqueOrThrow({ where: { id: f.a.account.id } })
            ).balance.toString(),
        ).toBe('140.15');
        const share = await db.sharedEntry.findFirstOrThrow();
        expect(share.type).toBe('EXPENSE');
        const accepted = await resolveService(SharedEntriesService).accept(share.id, f.tenant.id, {
            cashbookId: f.b.book.id,
            accountId: f.b.account.id,
            expectedVersion: share.sourceVersion,
        });
        expect(accepted.entryId).toBeTruthy();
        expect(
            (
                await db.account.findUniqueOrThrow({ where: { id: f.b.account.id } })
            ).balance.toString(),
        ).toBe('-140.15');
        const view = await svc().detail(f.tenancy.id, f.tenant.id, null);
        expect(view.periods[0].outstanding).toBe('60.1');
        expect(view.periods[1].state).toBe('PAID');
        expect(view.payments[0]).not.toHaveProperty('entryId');
        const totals = await db.journalLine.aggregate({ _sum: { debit: true, credit: true } });
        expect(totals._sum.debit?.equals(totals._sum.credit!)).toBe(true);
    });
    it('refuses changed retry details and concurrent overpayment without partial postings', async () => {
        const f = await fixture();
        await svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, f.pay);
        await expect(
            svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, {
                ...f.pay,
                allocations: [{ periodId: f.periods[0].id, amount: '30' }],
            }),
        ).rejects.toThrow('different details');
        const input = {
            ...f.pay,
            requestId: randomUUID(),
            allocations: [{ periodId: f.periods[0].id, amount: '60.1' }],
        };
        const results = await Promise.allSettled([
            svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, input),
            svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, {
                ...input,
                requestId: randomUUID(),
            }),
        ]);
        expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
        expect(await db.entry.count()).toBe(2);
    });
    it('enforces book roles, currency, account workspace and period ownership', async () => {
        const f = await fixture();
        await db.cashbookMember.create({
            data: { cashbookId: f.a.book.id, userId: f.owner.id, role: 'VIEWER' },
        });
        await expect(
            svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, f.pay),
        ).rejects.toMatchObject({ statusCode: 403 });
        await db.cashbookMember.deleteMany();
        await expect(
            svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, {
                ...f.pay,
                accountId: f.b.account.id,
            }),
        ).rejects.toThrow('account');
        await expect(
            svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, {
                ...f.pay,
                allocations: [{ periodId: randomUUID(), amount: '1' }],
            }),
        ).rejects.toThrow('period');
        await db.cashbook.update({ where: { id: f.a.book.id }, data: { currency: 'USD' } });
        await expect(
            svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, f.pay),
        ).rejects.toMatchObject({ statusCode: 404 });
        expect(await db.entry.count()).toBe(0);
    });
    it('honors archive, closed fiscal periods and backdate rules', async () => {
        const f = await fixture();
        await db.cashbook.update({ where: { id: f.a.book.id }, data: { archivedAt: new Date() } });
        await expect(
            svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, f.pay),
        ).rejects.toThrow();
        await db.cashbook.update({
            where: { id: f.a.book.id },
            data: { archivedAt: null, allowBackdate: false },
        });
        await expect(
            svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, f.pay),
        ).rejects.toThrow('Backdated');
        await db.cashbook.update({ where: { id: f.a.book.id }, data: { allowBackdate: true } });
        await db.fiscalPeriod.create({
            data: {
                workspaceId: f.a.workspace.id,
                startDate: dbDate('2026-01-01'),
                endDate: dbDate('2026-12-31'),
                status: 'CLOSED',
                note: '2026',
            },
        });
        await expect(
            svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, f.pay),
        ).rejects.toThrow();
        expect(await db.entry.count()).toBe(0);
    });
    it('blocks mutation of allocated receipts and restores dues on normal entry reversal without undoing the tenant copy', async () => {
        const f = await fixture();
        const result = await svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, f.pay);
        const entry = await db.entry.findUniqueOrThrow({ where: { id: result.entryId! } });
        await expect(
            resolveService(EntriesService).updateEntry(entry.id, f.owner.id, {
                amount: '1',
                expectedVersion: entry.version,
            }),
        ).rejects.toThrow('Reverse this rent');
        const share = await db.sharedEntry.findFirstOrThrow();
        const imported = await resolveService(SharedEntriesService).accept(share.id, f.tenant.id, {
            cashbookId: f.b.book.id,
            accountId: f.b.account.id,
            expectedVersion: share.sourceVersion,
        });
        await db.$transaction((tx) =>
            resolveService(EntriesService).reverseEntryWithin(
                tx,
                entry,
                f.owner.id,
                'Wrong payment',
            ),
        );
        expect(
            (await svc().detail(f.tenancy.id, f.owner.id, f.a.workspace.id)).periods[0].outstanding,
        ).toBe('100.125');
        expect(
            (await db.entry.findUniqueOrThrow({ where: { id: imported.entryId! } })).status,
        ).toBe('POSTED');
        expect(
            (await resolveService(SharedEntriesService).list(f.tenant.id, page)).data[0]
                .sourceState,
        ).toBe('REVERSED');
    });
    it('requires explicit move-out charges and refuses to lose advance payments or reduce charges below paid amounts', async () => {
        const f = await fixture(false);
        await svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, {
            ...f.pay,
            allocations: [{ periodId: f.periods[1].id, amount: '100.125' }],
        });
        await expect(
            svc().end(f.tenancy.id, f.a.workspace.id, f.owner.id, {
                endDate: '2026-02-15',
                reason: 'Move out',
                expectedVersion: 1,
            }),
        ).rejects.toThrow('agreed amount');
        await expect(
            svc().end(f.tenancy.id, f.a.workspace.id, f.owner.id, {
                endDate: '2026-02-15',
                finalPeriodAmount: '50',
                reason: 'Move out',
                expectedVersion: 1,
            }),
        ).rejects.toThrow('Future periods');
        await expect(
            svc().updatePeriod(f.tenancy.id, f.periods[1].id, f.a.workspace.id, f.owner.id, {
                amount: '50',
                dueDate: '2026-02-28',
                reason: 'Discount',
                expectedVersion: 1,
            }),
        ).rejects.toThrow('less than');
        expect(
            (await db.housingTenancy.findUniqueOrThrow({ where: { id: f.tenancy.id } })).status,
        ).toBe('ACTIVE');
    });
    it('generates reminders once in the recipient’s own workspace, skips paid periods and inactive tenants', async () => {
        const f = await fixture();
        await createWorkspace(f.tenant.id, { name: 'Tenant business' });
        const time = new Date('2026-01-28T10:00:00Z');
        await scanHousing(db, svc(), time);
        await scanHousing(db, svc(), time);
        const notices = await db.notification.findMany({ where: { type: 'RENT_DUE' } });
        expect(notices).toHaveLength(2);
        expect(notices.find((n) => n.userId === f.tenant.id)?.workspaceId).toBe(f.b.workspace.id);
        await svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, {
            ...f.pay,
            allocations: [{ periodId: f.periods[0].id, amount: '100.125' }],
        });
        await scanHousing(db, svc(), new Date('2026-01-31T10:00:00Z'));
        expect(await db.notification.count({ where: { type: 'RENT_DUE' } })).toBe(2);
    });
    it('allows concerns, owner replies, resolution and tenant reopening without exposing another tenancy', async () => {
        const f = await fixture();
        const issue = await issues().create(f.tenant.id, {
            tenancyId: f.tenancy.id,
            title: 'Leaking tap',
            description: 'Water leaks in the kitchen',
            kind: 'MAINTENANCE',
            priority: 'URGENT',
        });
        await issues().respond(issue.id, f.owner.id, {
            body: 'Repair completed',
            status: 'RESOLVED',
            expectedVersion: 1,
        });
        await issues().respond(issue.id, f.tenant.id, {
            body: 'The leak is still present',
            status: 'OPEN',
            expectedVersion: 2,
        });
        const view = await issues().detail(issue.id, f.tenant.id, page);
        expect(view.status).toBe('OPEN');
        expect(view.messages).toHaveLength(2);
        expect(view).not.toHaveProperty('workspaceId');
        await expect(
            issues().respond(issue.id, f.owner.id, { body: 'Old response', expectedVersion: 1 }),
        ).rejects.toMatchObject({ statusCode: 409 });
        await expect(
            issues().detail(issue.id, (await createUser()).id, page),
        ).rejects.toMatchObject({ statusCode: 404 });
    });
    it('extends issue handling to existing inventory rentals without changing inventory movements', async () => {
        const f = await fixture();
        const item = await createInventoryItem(f.a.workspace.id, { quantityOnHand: 5 });
        const rental = await db.inventoryRental.create({
            data: {
                workspaceId: f.a.workspace.id,
                customerId: f.contact.id,
                status: 'ACTIVE',
                currency: 'UGX',
                startDate: new Date(),
                createdById: f.owner.id,
                lines: {
                    create: {
                        inventoryItemId: item.id,
                        quantity: 1,
                        unitRate: '10',
                        lineTotal: '10',
                        periodUnit: 'DAY',
                    },
                },
            },
        });
        const issue = await issues().create(f.tenant.id, {
            rentalId: rental.id,
            title: 'Rental problem',
            description: 'The item is damaged',
            kind: 'CONCERN',
            priority: 'NORMAL',
        });
        await issues().respond(issue.id, f.owner.id, {
            body: 'Bring it for inspection',
            status: 'IN_PROGRESS',
            expectedVersion: 1,
        });
        expect((await issues().rentals(f.tenant.id)).map((r) => r.id)).toContain(rental.id);
        expect(await db.inventoryTransaction.count()).toBe(0);
    });
    it('secures HTTP endpoints and rejects malformed amounts, dates and resource ids', async () => {
        const f = await fixture();
        const member = await createUser();
        await addWorkspaceMember(f.a.workspace.id, member.id);
        const token = jwt.sign(
            { userId: member.id, email: member.email },
            process.env.JWT_ACCESS_SECRET!,
        );
        const url = `/api/v1/workspaces/${f.a.workspace.id}/housing/units`;
        expect((await request(app).get(url)).status).toBe(401);
        expect((await request(app).get(url).set('Cookie', `accessToken=${token}`)).status).toBe(
            403,
        );
        const ownerToken = jwt.sign(
            { userId: f.owner.id, email: f.owner.email },
            process.env.JWT_ACCESS_SECRET!,
        );
        const malformed = await request(app)
            .post(url)
            .set('Cookie', `accessToken=${ownerToken}`)
            .send({ name: 'Broken', monthlyRent: '-1' });
        expect(malformed.status).toBe(400);
        expect(
            (
                await request(app)
                    .get('/api/v1/housing/tenancies/not-a-uuid')
                    .set('Cookie', `accessToken=${ownerToken}`)
            ).status,
        ).toBe(400);
    });
    it('stores optional private photos under quota, rejects forged images and denies tenant access to another unit', async () => {
        const f = await fixture();
        const upload = vi.spyOn(StorageService.prototype, 'uploadBuffer').mockResolvedValue();
        const remove = vi.spyOn(StorageService.prototype, 'deleteObject').mockResolvedValue();
        const url = vi
            .spyOn(StorageService.prototype, 'generatePresignedUrl')
            .mockResolvedValue('https://private.example/photo');
        try {
            const buffer = await sharp({
                create: { width: 4, height: 4, channels: 3, background: '#ffffff' },
            })
                .png()
                .toBuffer();
            const file = {
                buffer,
                mimetype: 'image/png',
                originalname: 'home.png',
            } as Express.Multer.File;
            const photo = await resolveService(HousingMediaService).upload(
                f.a.workspace.id,
                f.unit.id,
                f.owner.id,
                file,
            );
            expect(
                await resolveService(HousingMediaService).photo(
                    null,
                    f.tenancy.id,
                    photo.id,
                    f.tenant.id,
                ),
            ).toEqual({ url: 'https://private.example/photo' });
            await expect(
                resolveService(HousingMediaService).upload(
                    f.a.workspace.id,
                    f.unit.id,
                    f.owner.id,
                    { ...file, buffer: Buffer.from('not an image') },
                ),
            ).rejects.toThrow('could not');
            await expect(
                resolveService(HousingMediaService).photo(
                    null,
                    f.tenancy.id,
                    photo.id,
                    (await createUser()).id,
                ),
            ).rejects.toMatchObject({ statusCode: 404 });
            expect(upload).toHaveBeenCalledTimes(1);
        } finally {
            upload.mockRestore();
            remove.mockRestore();
            url.mockRestore();
        }
    });

    it('backs allocation totals and immutable receipt amounts with database constraints', async () => {
        const f = await fixture();
        const result = await svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, f.pay);
        const allocation = await db.rentAllocation.findFirstOrThrow();
        await expect(
            db.rentAllocation.update({ where: { id: allocation.id }, data: { amount: '1' } }),
        ).rejects.toThrow();
        await expect(
            db.entry.update({ where: { id: result.entryId! }, data: { amount: '1' } }),
        ).rejects.toThrow();
        expect(
            (
                await db.rentAllocation.findUniqueOrThrow({ where: { id: allocation.id } })
            ).amount.toString(),
        ).toBe('40.025');
    });
    it('keeps real arrears in the overview, paginates receipts and permits collection after contact archival', async () => {
        const f = await fixture();
        await svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, f.pay);
        await db.contact.update({ where: { id: f.contact.id }, data: { isActive: false } });
        await svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, {
            ...f.pay,
            requestId: randomUUID(),
            allocations: [{ periodId: f.periods[0].id, amount: '10' }],
        });
        const detail = await svc().detail(f.tenancy.id, f.owner.id, f.a.workspace.id, {
            page: 2,
            limit: 1,
        });
        expect(detail.paymentsTotal).toBe(2);
        expect(detail.payments).toHaveLength(1);
        const summary = await svc().summary(f.a.workspace.id, f.owner.id);
        expect(summary).toMatchObject({ units: 1, assigned: 1, unassigned: 0 });
        expect(new Decimal(summary.overdue[0].amount).gt(0)).toBe(true);
        expect(await db.sharedEntry.count()).toBe(1);
    });
    it('records holdover move-out, preserves original planned dates and applies an explicitly changed final charge', async () => {
        const f = await fixture(false);
        await svc().end(f.tenancy.id, f.a.workspace.id, f.owner.id, {
            endDate: '2026-02-28',
            reason: 'End original',
            expectedVersion: 1,
        });
        const next = await svc().createTenancy(f.a.workspace.id, f.owner.id, {
            unitId: f.unit.id,
            tenantName: 'Next',
            startDate: '2026-03-01',
            endDate: '2026-04-01',
            monthlyRent: '100',
            dueDay: 1,
        });
        await svc().end(next.id, f.a.workspace.id, f.owner.id, {
            endDate: '2026-05-10',
            finalPeriodAmount: '25',
            reason: 'Stayed longer by agreement',
            expectedVersion: 1,
        });
        const view = await svc().detail(next.id, f.owner.id, f.a.workspace.id);
        expect(view.periods.map((p) => p.amount.toString())).toEqual(['100', '100', '25']);
        expect(view.endDate?.toISOString().slice(0, 10)).toBe('2026-04-01');
        expect(view.actualEndDate?.toISOString().slice(0, 10)).toBe('2026-05-10');
    });
    it('refuses over-quota photos after processing and cleans up the rejected object', async () => {
        const f = await fixture();
        await db.workspace.update({
            where: { id: f.a.workspace.id },
            data: { storageQuotaBytes: 1n },
        });
        const upload = vi.spyOn(StorageService.prototype, 'uploadBuffer').mockResolvedValue();
        const remove = vi.spyOn(StorageService.prototype, 'deleteObject').mockResolvedValue();
        try {
            const buffer = await sharp({
                create: { width: 4, height: 4, channels: 3, background: '#ffffff' },
            })
                .png()
                .toBuffer();
            await expect(
                resolveService(HousingMediaService).upload(
                    f.a.workspace.id,
                    f.unit.id,
                    f.owner.id,
                    {
                        buffer,
                        mimetype: 'image/png',
                        originalname: 'photo.png',
                    } as Express.Multer.File,
                ),
            ).rejects.toMatchObject({ code: 'STORAGE_QUOTA_EXCEEDED' });
            expect(remove).toHaveBeenCalledTimes(1);
            expect(await db.attachment.count()).toBe(0);
        } finally {
            upload.mockRestore();
            remove.mockRestore();
        }
    });
    it('denies deleted tenant sessions and resolves notification links without granting workspace access', async () => {
        const f = await fixture();
        expect(await svc().location(f.tenancy.id, f.tenant.id)).toEqual({ tenant: true });
        expect(await svc().location(f.tenancy.id, f.owner.id)).toEqual({
            tenant: false,
            workspaceId: f.a.workspace.id,
        });
        await db.user.update({
            where: { id: f.tenant.id },
            data: { isActive: false, deletedAt: new Date() },
        });
        await expect(svc().detail(f.tenancy.id, f.tenant.id, null)).rejects.toMatchObject({
            statusCode: 404,
        });
        await expect(svc().tenancies(null, f.tenant.id, page)).rejects.toMatchObject({
            statusCode: 404,
        });
        await scanHousing(db, svc(), new Date('2026-01-28T10:00:00Z'));
        expect(
            await db.notification.count({ where: { userId: f.tenant.id, type: 'RENT_DUE' } }),
        ).toBe(0);
    });

    it('completes the landlord and tenant flow through the public HTTP contracts', async () => {
        const f = await fixture(false);
        const cookie = (id: string, email: string) =>
            `accessToken=${jwt.sign({ userId: id, email }, process.env.JWT_ACCESS_SECRET!)}`;
        const landlord = cookie(f.owner.id, f.owner.email),
            tenant = cookie(f.tenant.id, f.tenant.email);
        const base = `/api/v1/workspaces/${f.a.workspace.id}/housing`;
        const unit = await request(app).post(`${base}/units`).set('Cookie', landlord).send({
            name: 'HTTP apartment',
            monthlyRent: '100',
            propertyId: f.unit.propertyId,
            requestId: randomUUID(),
        });
        expect(unit.status).toBe(200);
        const created = await request(app).post(`${base}/tenancies`).set('Cookie', landlord).send({
            unitId: unit.body.data.id,
            tenantName: 'Tenant',
            contactId: f.contact.id,
            monthlyRent: '100',
            startDate: '2026-01-01',
            dueDay: 1,
        });
        expect(created.status).toBe(200);
        const id = created.body.data.id;
        expect(
            (
                await request(app)
                    .post(`/api/v1/housing/tenancies/${id}/accept`)
                    .set('Cookie', tenant)
            ).status,
        ).toBe(200);
        const options = await request(app)
            .get(`${base}/tenancies/${id}/payment-options`)
            .set('Cookie', landlord);
        expect(options.body.data.books[0].id).toBe(f.a.book.id);
        const detail = await request(app).get(`${base}/tenancies/${id}`).set('Cookie', landlord);
        expect(detail.status).toBe(200);
        const input = {
            requestId: randomUUID(),
            cashbookId: f.a.book.id,
            accountId: f.a.account.id,
            entryDate: '2026-01-02T10:00:00.000Z',
            allocations: [{ periodId: detail.body.data.periods[0].id, amount: '19.125' }],
        };
        const key = randomUUID();
        const paid = await request(app)
            .post(`${base}/tenancies/${id}/payments`)
            .set('Cookie', landlord)
            .set('Idempotency-Key', key)
            .send(input);
        expect(paid.status).toBe(200);
        const retried = await request(app)
            .post(`${base}/tenancies/${id}/payments`)
            .set('Cookie', landlord)
            .set('Idempotency-Key', key)
            .send(input);
        expect(retried.body.data.entryId).toBe(paid.body.data.entryId);
        const view = await request(app)
            .get(`/api/v1/housing/tenancies/${id}`)
            .set('Cookie', tenant);
        expect(view.body.data.periods[0].paid).toBe('19.125');
        expect(view.body.data.payments[0]).not.toHaveProperty('entryId');
        const issue = await request(app).post('/api/v1/rental-issues').set('Cookie', tenant).send({
            tenancyId: id,
            title: 'Payment query',
            description: 'Please confirm the agreed rent',
            kind: 'PAYMENT_DISPUTE',
        });
        expect(issue.status).toBe(200);
        expect(
            (
                await request(app)
                    .post(`/api/v1/rental-issues/${issue.body.data.id}/messages`)
                    .set('Cookie', landlord)
                    .send({
                        body: 'The agreed rent is confirmed',
                        status: 'RESOLVED',
                        expectedVersion: 1,
                    })
            ).status,
        ).toBe(200);
        const thread = await request(app)
            .get(`/api/v1/rental-issues/${issue.body.data.id}`)
            .set('Cookie', tenant);
        expect(thread.body.data.status).toBe('RESOLVED');
        expect(thread.body.data.messages[0].body).toBe('The agreed rent is confirmed');
    });
    it('allows workspace purge without deleting the recipient’s accepted financial record', async () => {
        const f = await fixture();
        await svc().payment(f.tenancy.id, f.a.workspace.id, f.owner.id, f.pay);
        const share = await db.sharedEntry.findFirstOrThrow();
        const accepted = await resolveService(SharedEntriesService).accept(share.id, f.tenant.id, {
            cashbookId: f.b.book.id,
            accountId: f.b.account.id,
            expectedVersion: share.sourceVersion,
        });
        await db.$transaction(
            async (tx) => {
                await tx.$executeRawUnsafe("SET LOCAL app.allow_ledger_maintenance = 'on'");
                await purgeWorkspace(tx, f.a.workspace.id);
            },
            { timeout: 30000 },
        );
        expect(await db.housingTenancy.count()).toBe(0);
        expect(await db.housingProperty.count({ where: { workspaceId: f.a.workspace.id } })).toBe(
            0,
        );
        expect(
            await db.housingProvisioningRequest.count({ where: { workspaceId: f.a.workspace.id } }),
        ).toBe(0);
        expect(
            (await db.entry.findUniqueOrThrow({ where: { id: accepted.entryId! } })).status,
        ).toBe('POSTED');
    });
});

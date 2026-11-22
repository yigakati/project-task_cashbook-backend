/**
 * Receipts.
 *
 * A receipt acknowledges that money was received. It used to require an
 * obligation, which meant the commonest case of all — a walk-in customer paying
 * cash on the spot, creating no receivable — could not be receipted at all.
 *
 * The model is exposed as JSON so the client can render and print an identical
 * copy. Emailing still renders server-side, because the recipient never loads
 * our page; both read this same model, so the printed and emailed copies cannot
 * drift apart.
 */
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'node:crypto';
import { sendEmail, isEmailConfigured } from '../../config/email';
import { generateReceiptPdf } from '../../modules/entries/receipt.generator';
import { Prisma } from '@prisma/client';
import { resetDatabase, testPrisma } from '../setup';
import { resolveService } from '../container';
import { EntriesService } from '../../modules/entries/entries.service';
import { createAccount, createCashbook, createUser, createWorkspace } from '../factories';
import {
    provisionWorkspaceAccounting,
    ensureCashbookLedgerAccount,
    ensureWalletLedgerAccount,
} from '../../core/ledger/coa.seed';

vi.mock('../../config/email', () => ({ sendEmail: vi.fn(), isEmailConfigured: vi.fn() }));
vi.mock('../../modules/entries/receipt.generator', async (original) => ({
    ...(await original<typeof import('../../modules/entries/receipt.generator')>()),
    generateReceiptPdf: vi.fn(),
}));
let app: import('express').Express;
beforeAll(async () => {
    await import('../../config/container');
    app = (await import('../../app')).default;
});

const service = () => resolveService(EntriesService);

async function fixture() {
    const owner = await createUser();
    const workspace = await createWorkspace(owner.id);
    await testPrisma.$transaction(async (tx: Prisma.TransactionClient) => {
        await provisionWorkspaceAccounting(tx, workspace.id, 'UGX');
    });

    const cashbook = await createCashbook(workspace.id, owner.id, { name: 'Shop' });
    await testPrisma.$transaction(async (tx: Prisma.TransactionClient) => {
        await ensureCashbookLedgerAccount(tx, {
            id: cashbook.id,
            workspaceId: workspace.id,
            name: cashbook.name,
            currency: 'UGX',
        });
    });

    // allowNegative so the money-out case can be built at all: the overdraft
    // guard fires before the receipt logic is ever reached otherwise.
    const wallet = await createAccount(workspace.id, {
        name: 'Till',
        balance: '0',
        allowNegative: true,
    });
    await testPrisma.$transaction(async (tx: Prisma.TransactionClient) => {
        const full = await tx.account.findUniqueOrThrow({
            where: { id: wallet.id },
            include: { accountType: true },
        });
        await ensureWalletLedgerAccount(tx, full, full.accountType.classification);
    });

    return { owner, workspace, cashbook, wallet };
}

async function customer(workspaceId: string, overrides: { email?: string | null } = {}) {
    return testPrisma.contact.create({
        data: {
            workspaceId,
            name: 'Jane Customer',
            type: 'CUSTOMER',
            email: overrides.email === undefined ? 'jane@example.com' : overrides.email,
        },
    });
}

async function sale(
    f: Awaited<ReturnType<typeof fixture>>,
    contactId: string | null,
    type: 'INCOME' | 'EXPENSE' = 'INCOME',
) {
    return service().createEntry(f.cashbook.id, f.owner.id, {
        type,
        amount: '25000',
        description: 'Two crates of sodas',
        accountId: f.wallet.id,
        contactId: contactId ?? undefined,
        entryDate: new Date('2026-03-10').toISOString(),
    } as never);
}

beforeEach(async () => {
    await resetDatabase();
    vi.clearAllMocks();
    vi.mocked(sendEmail).mockResolvedValue();
    vi.mocked(isEmailConfigured).mockReturnValue(true);
    vi.mocked(generateReceiptPdf).mockResolvedValue(Buffer.from('PDF'));
});

describe('a cash sale with no receivable', () => {
    it('can be receipted — the case that used to be refused', async () => {
        const f = await fixture();
        const contact = await customer(f.workspace.id);
        const entry = await sale(f, contact.id);

        const receipt = await service().getReceiptModel(entry.id, f.cashbook.id);

        expect(receipt.customer.name).toBe('Jane Customer');
        expect(receipt.amountPaid).toBe('25000');
        expect(receipt.currency).toBe('UGX');
    });

    it('carries no obligation block, rather than a zeroed one', async () => {
        // "Balance remaining: 0" on a walk-in sale invites the question of what
        // balance is meant. Absent is clearer than zero.
        const f = await fixture();
        const contact = await customer(f.workspace.id);
        const entry = await sale(f, contact.id);

        const receipt = await service().getReceiptModel(entry.id, f.cashbook.id);

        expect(receipt.obligation).toBeNull();
        expect(receipt.description).toBe('Two crates of sodas');
    });

    it('says whether it can be emailed', async () => {
        const f = await fixture();
        const contact = await customer(f.workspace.id);
        const entry = await sale(f, contact.id);

        expect((await service().getReceiptModel(entry.id, f.cashbook.id)).canEmail).toBe(true);
    });

    it('is still printable when the customer has no email', async () => {
        // The whole reason the flag exists rather than an error: no address is
        // a reason to print, not a reason to refuse a receipt.
        const f = await fixture();
        const contact = await customer(f.workspace.id, { email: null });
        const entry = await sale(f, contact.id);

        const receipt = await service().getReceiptModel(entry.id, f.cashbook.id);

        expect(receipt.canEmail).toBe(false);
        expect(receipt.customer.name).toBe('Jane Customer');
    });

    it('names the business, so the document is usable as a record', async () => {
        const f = await fixture();
        const contact = await customer(f.workspace.id);
        const entry = await sale(f, contact.id);

        const receipt = await service().getReceiptModel(entry.id, f.cashbook.id);

        expect(receipt.business.name).toBe(f.workspace.name);
        expect(receipt.receiptNumber).toBeTruthy();
    });
});

describe('what cannot be receipted', () => {
    it('refuses an entry with no customer', async () => {
        const f = await fixture();
        const entry = await sale(f, null);

        await expect(service().getReceiptModel(entry.id, f.cashbook.id)).rejects.toThrow(
            /not linked to a customer/i,
        );
    });

    it('refuses money going out', async () => {
        // A receipt acknowledges money RECEIVED. Issuing one for an expense
        // would hand a customer a document saying they were paid.
        const f = await fixture();
        const contact = await customer(f.workspace.id);
        const entry = await sale(f, contact.id, 'EXPENSE');

        await expect(service().getReceiptModel(entry.id, f.cashbook.id)).rejects.toThrow(
            /money received|money out/i,
        );
    });

    it('refuses an entry that does not exist', async () => {
        await expect(
            service().getReceiptModel(
                '00000000-0000-0000-0000-000000000000',
                '00000000-0000-0000-0000-000000000000',
            ),
        ).rejects.toThrow();
    });
});

describe('explicit receipt delivery and business identity', () => {
    it('uses invoice branding and the workspace business profile in both copies', async () => {
        const f = await fixture();
        await testPrisma.workspaceProfile.create({
            data: {
                workspaceId: f.workspace.id,
                displayName: 'Kampala Supplies',
                legalName: 'KS Limited',
                addressLine1: 'Plot 42',
                addressLine2: 'Market Road',
                city: 'Kampala',
                country: 'Uganda',
                phone: '+256700000001',
                email: 'office@example.test',
                billingEmail: 'billing@example.test',
                taxId: 'TIN-123',
                registrationNo: 'REG-123',
                website: 'https://example.test',
            },
        });
        await testPrisma.invoiceSettings.create({
            data: {
                workspaceId: f.workspace.id,
                logoKey: 'logos/business.png',
                defaultFooter: 'Thank you',
                defaultNotes: 'Keep for your records',
                accentColor: '#123456',
            },
        });
        const contact = await customer(f.workspace.id);
        const entry = await sale(f, contact.id);
        const model = await service().getReceiptModel(entry.id, f.cashbook.id);
        expect(model.business).toMatchObject({
            name: 'Kampala Supplies',
            legalName: 'KS Limited',
            address: 'Plot 42, Market Road, Kampala, Uganda',
            email: 'billing@example.test',
            phone: '+256700000001',
            taxId: 'TIN-123',
            registrationNo: 'REG-123',
            footer: 'Thank you',
            notes: 'Keep for your records',
            accentColor: '#123456',
        });
        expect(model.business.logoUrl).toContain('logos/');
        await service().sendReceipt(entry.id, f.owner.id, f.cashbook.id, {
            email: contact.email!,
            expectedVersion: entry.version,
        });
        expect(generateReceiptPdf).toHaveBeenCalledWith(
            model,
            expect.objectContaining({ logoKey: 'logos/business.png' }),
        );
        expect(sendEmail).toHaveBeenCalledWith(
            expect.objectContaining({
                to: contact.email,
                replyTo: 'billing@example.test',
                html: expect.stringContaining('Plot 42, Market Road, Kampala, Uganda'),
                attachments: [expect.objectContaining({ contentType: 'application/pdf' })],
            }),
        );
    });

    it('plain saving never sends a receipt, including a receivable payment', async () => {
        const f = await fixture();
        const contact = await customer(f.workspace.id);
        await sale(f, contact.id);
        const obligation = await testPrisma.cashbookObligation.create({
            data: {
                workspaceId: f.workspace.id,
                cashbookId: f.cashbook.id,
                contactId: contact.id,
                type: 'RECEIVABLE',
                title: 'Goods on credit',
                principalAmount: '100000',
                totalAmount: '100000',
                outstandingAmount: '100000',
            },
        });
        await service().createEntry(f.cashbook.id, f.owner.id, {
            type: 'INCOME',
            amount: '25000',
            description: 'First instalment',
            accountId: f.wallet.id,
            contactId: contact.id,
            obligationId: obligation.id,
            entryDate: new Date().toISOString(),
        });
        expect(sendEmail).not.toHaveBeenCalled();
        expect(generateReceiptPdf).not.toHaveBeenCalled();
        expect(
            (
                await testPrisma.cashbookObligation.findUniqueOrThrow({
                    where: { id: obligation.id },
                })
            ).outstandingAmount.toString(),
        ).toBe('75000');
    });

    it.each([null, '', '   ', 'not-an-email'])(
        'allows printing but rejects sending to %s',
        async (email) => {
            const f = await fixture();
            const contact = await customer(f.workspace.id, { email });
            const entry = await sale(f, contact.id);
            const model = await service().getReceiptModel(entry.id, f.cashbook.id);
            expect(model.canEmail).toBe(false);
            expect(model.business.logoUrl).toContain('logo.png');
            await expect(
                service().sendReceipt(entry.id, f.owner.id, f.cashbook.id),
            ).rejects.toMatchObject({ code: 'NO_EMAIL' });
            expect(sendEmail).not.toHaveBeenCalled();
        },
    );

    it('reports unavailable email without rolling back the saved payment', async () => {
        const f = await fixture();
        const contact = await customer(f.workspace.id);
        const entry = await sale(f, contact.id);
        vi.mocked(isEmailConfigured).mockReturnValue(false);
        await expect(
            service().sendReceipt(entry.id, f.owner.id, f.cashbook.id),
        ).rejects.toMatchObject({ code: 'EMAIL_UNAVAILABLE', statusCode: 503 });
        expect(await testPrisma.entry.count()).toBe(1);
        expect(
            (
                await testPrisma.account.findUniqueOrThrow({ where: { id: f.wallet.id } })
            ).balance.toString(),
        ).toBe('25000');
        expect(sendEmail).not.toHaveBeenCalled();
    });

    it('rejects changed entry versions or recipients before sending', async () => {
        const f = await fixture();
        const contact = await customer(f.workspace.id);
        const entry = await sale(f, contact.id);
        for (const review of [
            { expectedVersion: entry.version + 1 },
            { email: 'changed@example.test' },
        ]) {
            await expect(
                service().sendReceipt(entry.id, f.owner.id, f.cashbook.id, review),
            ).rejects.toMatchObject({ statusCode: 409 });
        }
        expect(sendEmail).not.toHaveBeenCalled();
    });

    it('escapes customer and business text and omits a nonexistent balance', async () => {
        const f = await fixture();
        const contact = await customer(f.workspace.id);
        await testPrisma.contact.update({
            where: { id: contact.id },
            data: { name: '<img src=x onerror=alert(1)>' },
        });
        await testPrisma.workspaceProfile.create({
            data: {
                workspaceId: f.workspace.id,
                displayName: 'Shop & Sons',
                addressLine1: '<script>bad</script>',
            },
        });
        const entry = await sale(f, contact.id);
        await service().sendReceipt(entry.id, f.owner.id, f.cashbook.id);
        const html = vi.mocked(sendEmail).mock.calls[0][0].html;
        expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
        expect(html).toContain('Shop &amp; Sons');
        expect(html).toContain('&lt;script&gt;bad&lt;/script&gt;');
        expect(html).not.toContain('Remaining Balance');
    });

    it('does not turn a successful SMTP send into an error when auditing fails', async () => {
        const f = await fixture();
        const contact = await customer(f.workspace.id);
        const entry = await sale(f, contact.id);
        const audit = vi
            .spyOn(testPrisma.auditLog, 'create')
            .mockRejectedValueOnce(new Error('Audit unavailable'));
        await expect(service().sendReceipt(entry.id, f.owner.id, f.cashbook.id)).resolves.toEqual({
            success: true,
            sentTo: contact.email,
        });
        audit.mockRestore();
        expect(sendEmail).toHaveBeenCalledTimes(1);
    });
});

describe('receipt authorization and request retries', () => {
    it('rejects foreign cashbooks, deleted and reversed entries', async () => {
        const f = await fixture();
        const contact = await customer(f.workspace.id);
        const entry = await sale(f, contact.id);
        const other = await createCashbook(f.workspace.id, f.owner.id);
        await expect(service().getReceiptModel(entry.id, other.id)).rejects.toMatchObject({
            statusCode: 404,
        });
        await expect(service().sendReceipt(entry.id, f.owner.id, other.id)).rejects.toMatchObject({
            statusCode: 404,
        });
        await testPrisma.entry.update({ where: { id: entry.id }, data: { status: 'REVERSED' } });
        await expect(service().getReceiptModel(entry.id, f.cashbook.id)).rejects.toMatchObject({
            statusCode: 409,
        });
        await testPrisma.entry.update({
            where: { id: entry.id },
            data: { status: 'POSTED', isDeleted: true },
        });
        await expect(service().getReceiptModel(entry.id, f.cashbook.id)).rejects.toMatchObject({
            statusCode: 404,
        });
        expect(sendEmail).not.toHaveBeenCalled();
    });

    it('secures HTTP access and binds the entry to the authorized book', async () => {
        const f = await fixture();
        const contact = await customer(f.workspace.id);
        const entry = await sale(f, contact.id);
        const stranger = await fixture();
        const cookie = `accessToken=${jwt.sign({ userId: stranger.owner.id, email: stranger.owner.email }, process.env.JWT_ACCESS_SECRET!)}`;
        const path = `/api/v1/entries/${entry.id}/receipt/cashbook/`;
        expect((await request(app).get(path + f.cashbook.id)).status).toBe(401);
        expect(
            (
                await request(app)
                    .get(path + f.cashbook.id)
                    .set('Cookie', cookie)
            ).status,
        ).toBe(403);
        expect(
            (
                await request(app)
                    .get(path + stranger.cashbook.id)
                    .set('Cookie', cookie)
            ).status,
        ).toBe(404);
        expect(
            (
                await request(app)
                    .get('/api/v1/entries/invalid/receipt/cashbook/' + stranger.cashbook.id)
                    .set('Cookie', cookie)
            ).status,
        ).toBe(400);
        expect(
            (
                await request(app)
                    .post(
                        `/api/v1/entries/${entry.id}/receipt/send/cashbook/${stranger.cashbook.id}`,
                    )
                    .set('Cookie', cookie)
                    .send({})
            ).status,
        ).toBe(404);
        const foreignEntry = `/api/v1/entries/${entry.id}/cashbook/${stranger.cashbook.id}`;
        expect((await request(app).get(foreignEntry).set('Cookie', cookie)).status).toBe(404);
        expect(
            (
                await request(app)
                    .get(`/api/v1/entries/${entry.id}/audit/cashbook/${stranger.cashbook.id}`)
                    .set('Cookie', cookie)
            ).status,
        ).toBe(404);
        expect(
            (
                await request(app)
                    .patch(foreignEntry)
                    .set('Cookie', cookie)
                    .send({ description: 'Unauthorized edit' })
            ).status,
        ).toBe(404);
        expect(
            (
                await request(app)
                    .delete(foreignEntry)
                    .set('Cookie', cookie)
                    .send({ reason: 'Unauthorized reversal' })
            ).status,
        ).toBe(404);
        expect(
            (await testPrisma.entry.findUniqueOrThrow({ where: { id: entry.id } })).description,
        ).toBe('Two crates of sodas');
        expect(sendEmail).not.toHaveBeenCalled();
    });

    it('replays a completed send and refuses concurrent duplicates or changed reuse', async () => {
        const f = await fixture();
        const contact = await customer(f.workspace.id);
        const entry = await sale(f, contact.id);
        const cookie = `accessToken=${jwt.sign({ userId: f.owner.id, email: f.owner.email }, process.env.JWT_ACCESS_SECRET!)}`;
        const url = `/api/v1/entries/${entry.id}/receipt/send/cashbook/${f.cashbook.id}`;
        const key = randomUUID();
        let release!: () => void;
        let entered!: () => void;
        const enteredTransport = new Promise<void>((resolve) => {
            entered = resolve;
        });
        vi.mocked(sendEmail).mockImplementationOnce(async () => {
            entered();
            await new Promise<void>((resolve) => {
                release = resolve;
            });
        });
        const post = (body = { email: contact.email, expectedVersion: entry.version }) =>
            request(app).post(url).set('Cookie', cookie).set('Idempotency-Key', key).send(body);
        const first = post().then((res) => res);
        await enteredTransport;
        const concurrent = await post();
        expect(concurrent.status).toBe(409);
        expect(concurrent.body.code).toBe('IDEMPOTENCY_IN_PROGRESS');
        release();
        expect((await first).status).toBe(200);
        const replay = await post();
        expect(replay.status).toBe(200);
        expect(replay.headers['idempotent-replay']).toBe('true');
        expect(
            (await post({ email: 'different@example.test', expectedVersion: entry.version }))
                .status,
        ).toBe(422);
        expect(sendEmail).toHaveBeenCalledTimes(1);
        expect(await testPrisma.entry.count()).toBe(1);
    });
});

describe('authoritative receipt PDF', () => {
    it('uses the email generator and rejects stale or foreign entry reviews', async () => {
        const f = await fixture();
        const contact = await customer(f.workspace.id);
        const entry = await sale(f, contact.id);
        const cookie = `accessToken=${jwt.sign({ userId: f.owner.id, email: f.owner.email }, (await import('../../config')).config.JWT_ACCESS_SECRET)}`;
        const prefix = (await import('../../config')).config.API_PREFIX;
        const url = `${prefix}/entries/${entry.id}/receipt/pdf/cashbook/${f.cashbook.id}`;
        const result = await request(app)
            .get(url)
            .query({ expectedVersion: entry.version })
            .set('Cookie', cookie);
        expect(result.status).toBe(200);
        expect(result.headers['content-type']).toContain('application/pdf');
        expect(result.headers['cache-control']).toBe('no-store');
        expect(generateReceiptPdf).toHaveBeenCalledWith(
            expect.objectContaining({ entryVersion: entry.version, amountPaid: '25000' }),
            null,
        );
        expect(
            (
                await request(app)
                    .get(url)
                    .query({ expectedVersion: entry.version + 1 })
                    .set('Cookie', cookie)
            ).status,
        ).toBe(409);
        expect(
            (await request(app).get(url).query({ expectedVersion: 'bad' }).set('Cookie', cookie))
                .status,
        ).toBe(400);
        expect((await request(app).get(url)).status).toBe(401);
        const foreign = await fixture();
        await expect(service().receiptPdf(entry.id, foreign.cashbook.id)).rejects.toMatchObject({
            statusCode: 404,
        });
    });
    it('permits a PDF without customer email while preserving email restrictions', async () => {
        const f = await fixture();
        const contact = await customer(f.workspace.id, { email: null });
        const entry = await sale(f, contact.id);
        await expect(service().receiptPdf(entry.id, f.cashbook.id)).resolves.toBeInstanceOf(Buffer);
        await expect(
            service().sendReceipt(entry.id, f.owner.id, f.cashbook.id),
        ).rejects.toMatchObject({ code: 'NO_EMAIL' });
    });
});

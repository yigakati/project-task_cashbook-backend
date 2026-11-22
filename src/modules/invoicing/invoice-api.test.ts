import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { resetDatabase, testPrisma } from '../../test/setup';
import { resolveService } from '../../test/container';
import {
    createCashbook,
    createUser,
    createWorkspace,
    addWorkspaceMember,
} from '../../test/factories';
import { InvoicingService } from './invoicing.service';
import {
    provisionWorkspaceAccounting,
    ensureCashbookLedgerAccount,
} from '../../core/ledger/coa.seed';
import { sendEmail, isEmailConfigured } from '../../config/email';
import { invoiceEmailTemplate } from '../../utils/emailTemplates';

vi.mock('../../config/email', () => ({ sendEmail: vi.fn(), isEmailConfigured: vi.fn() }));
let app: typeof import('../../app').default;
beforeAll(async () => {
    await import('../../config/container');
    app = (await import('../../app')).default;
});
beforeEach(async () => {
    await resetDatabase();
    vi.mocked(sendEmail).mockReset();
    vi.mocked(isEmailConfigured).mockReturnValue(true);
});
afterEach(() => vi.restoreAllMocks());
const service = () => resolveService(InvoicingService);
const cookie = (user: { id: string; email: string }) =>
    `accessToken=${jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_ACCESS_SECRET!)}`;
async function fixture() {
    const owner = await createUser();
    const workspace = await createWorkspace(owner.id);
    const cashbook = await createCashbook(workspace.id, owner.id);
    const customer = await testPrisma.contact.create({
        data: {
            workspaceId: workspace.id,
            type: 'CUSTOMER',
            name: 'Customer',
            email: 'customer@example.test',
        },
    });
    await testPrisma.$transaction(async (tx) => {
        await provisionWorkspaceAccounting(tx, workspace.id, 'UGX');
        await ensureCashbookLedgerAccount(tx, {
            id: cashbook.id,
            workspaceId: workspace.id,
            name: cashbook.name,
            currency: 'UGX',
        });
    });
    const input = {
        customerId: customer.id,
        cashbookId: cashbook.id,
        currency: 'UGX',
        issueDate: '2026-01-01T00:00:00Z',
        dueDate: '2026-01-15T00:00:00Z',
        items: [{ name: 'Service', lineType: 'SALE' as const, quantity: '1', unitPrice: '100' }],
    };
    const invoice = await service().createInvoice(workspace.id, owner.id, input);
    return { owner, workspace, invoice: invoice!, input };
}
describe('invoice HTTP and delivery', () => {
    it('previews draft PDFs privately, validates scope and never writes accounting', async () => {
        const fx = await fixture();
        const other = await fixture();
        const path = `/api/v1/workspaces/${fx.workspace.id}/invoices/preview/draft/pdf`;
        const counts = async () =>
            Promise.all([
                testPrisma.invoice.count(),
                testPrisma.entry.count(),
                testPrisma.cashbookObligation.count(),
                testPrisma.journalEntry.count(),
            ]);
        const before = await counts();
        expect((await request(app).post(path).send(fx.input)).status).toBe(401);
        expect(
            (await request(app).post(path).set('Cookie', cookie(other.owner)).send(fx.input))
                .status,
        ).toBe(403);
        expect(
            (await request(app).post(path).set('Cookie', cookie(fx.owner)).send({})).status,
        ).toBe(400);
        expect(
            (
                await request(app)
                    .post(path)
                    .set('Cookie', cookie(fx.owner))
                    .send({ ...fx.input, customerId: other.input.customerId })
            ).status,
        ).toBe(404);
        expect(
            (
                await request(app)
                    .post(path)
                    .set('Cookie', cookie(fx.owner))
                    .send({ ...fx.input, cashbookId: other.input.cashbookId })
            ).status,
        ).toBe(404);
        const pdf = await request(app).post(path).set('Cookie', cookie(fx.owner)).send(fx.input);
        expect(pdf.status).toBe(200);
        expect(pdf.headers['cache-control']).toBe('no-store');
        expect(pdf.headers['content-type']).toContain('application/pdf');
        expect(pdf.body.subarray(0, 5).toString()).toBe('%PDF-');
        const viewer = await createUser();
        await addWorkspaceMember(fx.workspace.id, viewer.id, 'MEMBER');
        expect(
            (await request(app).post(path).set('Cookie', cookie(viewer)).send(fx.input)).status,
        ).toBe(403);
        expect(await counts()).toEqual(before);
        expect(sendEmail).not.toHaveBeenCalled();
    });
    it('enforces workspace authorization and returns private document/PDF responses', async () => {
        const fx = await fixture();
        const other = await fixture();
        const path = `/api/v1/workspaces/${fx.workspace.id}/invoices`;
        expect((await request(app).get(`${path}/${fx.invoice.id}/document`)).status).toBe(401);
        expect(
            (
                await request(app)
                    .get(`${path}/${fx.invoice.id}/pdf`)
                    .set('Cookie', cookie(other.owner))
            ).status,
        ).toBe(403);
        expect(
            (
                await request(app)
                    .get(
                        `/api/v1/workspaces/${other.workspace.id}/invoices/${fx.invoice.id}/document`,
                    )
                    .set('Cookie', cookie(other.owner))
            ).status,
        ).toBe(404);
        const document = await request(app)
            .get(`${path}/${fx.invoice.id}/document`)
            .set('Cookie', cookie(fx.owner));
        expect(document.status).toBe(200);
        expect(document.headers['cache-control']).toBe('no-store');
        const pdf = await request(app)
            .get(`${path}/${fx.invoice.id}/pdf`)
            .set('Cookie', cookie(fx.owner));
        expect(pdf.status).toBe(200);
        expect(pdf.headers['content-type']).toContain('application/pdf');
        const viewer = await createUser();
        await addWorkspaceMember(fx.workspace.id, viewer.id, 'MEMBER');
        expect(
            (
                await request(app)
                    .patch(`${path}/settings/current`)
                    .set('Cookie', cookie(viewer))
                    .send({ template: 'modern' })
            ).status,
        ).toBe(403);
        expect(
            (
                await request(app)
                    .post(`${path}/preview/draft`)
                    .set('Cookie', cookie(viewer))
                    .send(fx.input)
            ).status,
        ).toBe(403);
    });

    it('reports SMTP failure without undoing the issued invoice', async () => {
        const fx = await fixture();
        vi.mocked(sendEmail).mockRejectedValue(new Error('SMTP unavailable'));
        const result = await service().sendInvoice(fx.invoice.id, fx.workspace.id, fx.owner.id);
        expect(result.emailDelivery).toBe('failed');
        expect(result.status).toBe('SENT');
        expect(
            await testPrisma.cashbookObligation.count({ where: { referenceId: fx.invoice.id } }),
        ).toBe(1);
        expect(
            vi.mocked(sendEmail).mock.calls[0][0].attachments![0].content.subarray(0, 5).toString(),
        ).toBe('%PDF-');
    });

    it('does not claim email delivery when SMTP is unconfigured', async () => {
        const fx = await fixture();
        vi.mocked(isEmailConfigured).mockReturnValue(false);
        expect(
            (await service().sendInvoice(fx.invoice.id, fx.workspace.id, fx.owner.id))
                .emailDelivery,
        ).toBe('not_configured');
        expect(sendEmail).not.toHaveBeenCalled();
    });

    it('escapes user-controlled invoice email fields', () => {
        const html = invoiceEmailTemplate({
            customerName: '<script>alert(1)</script>',
            businessName: '<b>Business</b>',
            invoiceNumber: 'INV-1',
            currency: 'UGX',
            totalAmount: '100.00',
            dueDate: '2026-01-15',
            itemsSummary: [
                { name: '<img src=x onerror=alert(1)>', quantity: '1', total: '100.00' },
            ],
            notes: '<a href="bad">Click</a>',
        });
        expect(html).toContain('&lt;script&gt;');
        expect(html).not.toContain('<script>');
        expect(html).not.toContain('<img src=x');
        expect(html).toContain('&lt;b&gt;Business&lt;/b&gt;');
    });
});

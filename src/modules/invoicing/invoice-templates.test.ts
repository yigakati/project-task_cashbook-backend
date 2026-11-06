import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { resetDatabase, testPrisma } from '../../test/setup';
import { resolveService } from '../../test/container';
import { createCashbook, createUser, createWorkspace } from '../../test/factories';
import { InvoicingService } from './invoicing.service';
import { invoiceDesignAccess, invoiceTemplates } from './invoice-templates';
import { updateInvoiceSettingsSchema } from './invoicing.dto';
import { config } from '../../config';
import {
    provisionWorkspaceAccounting,
    ensureCashbookLedgerAccount,
} from '../../core/ledger/coa.seed';

const service = () => resolveService(InvoicingService);
const environment = config.NODE_ENV;
const subscriptions = config.INVOICE_SUBSCRIPTIONS_ACTIVE;

async function fixture() {
    const user = await createUser();
    const workspace = await createWorkspace(user.id);
    const customer = await testPrisma.contact.create({
        data: { workspaceId: workspace.id, name: 'Customer', type: 'CUSTOMER' },
    });
    const cashbook = await createCashbook(workspace.id, user.id);
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
        issueDate: '2026-01-01T00:00:00Z',
        dueDate: '2026-01-15T00:00:00Z',
        currency: 'UGX',
        items: [
            { name: 'First', quantity: '2', unitPrice: '100.1234', lineType: 'SALE' as const },
            { name: 'Second', quantity: '1', unitPrice: '50', lineType: 'SALE' as const },
        ],
    };
    return { user, workspace, customer, cashbook, input };
}

beforeEach(resetDatabase);
afterEach(() => {
    config.NODE_ENV = environment;
    config.INVOICE_SUBSCRIPTIONS_ACTIVE = subscriptions;
});

describe('invoice design policies', () => {
    it('opens all ten templates now but reserves production customization for subscriptions', () => {
        expect(invoiceTemplates).toHaveLength(10);
        expect(invoiceTemplates.filter((t) => t.tier === 'premium')).toHaveLength(4);
        expect(invoiceDesignAccess('production', false, 'FREE')).toMatchObject({
            premiumTemplatesAllowed: true,
            customizationAllowed: false,
        });
        expect(invoiceDesignAccess('development', false, 'FREE').customizationAllowed).toBe(true);
        expect(invoiceDesignAccess('production', true, 'FREE')).toMatchObject({
            premiumTemplatesAllowed: false,
            customizationAllowed: false,
        });
        expect(invoiceDesignAccess('production', true, 'GROWTH').customizationAllowed).toBe(true);
    });

    it('rejects CSS, unknown layouts, and invalid versions', () => {
        for (const value of [
            { accentColor: 'red;display:none' },
            { template: 'unknown' },
            { customization: { html: '<script>' } },
            { version: 0 },
        ]) {
            expect(updateInvoiceSettingsSchema.safeParse(value).success).toBe(false);
        }
        expect(updateInvoiceSettingsSchema.parse({ defaultNotes: 'Text' })).toEqual({
            defaultNotes: 'Text',
        });
    });

    it('initializes settings atomically and accepts only one concurrent versioned update', async () => {
        const fx = await fixture();
        const responses = await Promise.all([
            service().getSettings(fx.workspace.id),
            service().getSettings(fx.workspace.id),
        ]);
        expect(responses[0].id).toBe(responses[1].id);
        const results = await Promise.allSettled(
            ['modern', 'ledger'].map((template) =>
                service().updateSettings(fx.workspace.id, fx.user.id, {
                    template: template as 'modern',
                    version: 1,
                }),
            ),
        );
        expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
        expect(
            (results.find((r) => r.status === 'rejected') as PromiseRejectedResult).reason,
        ).toMatchObject({ statusCode: 409 });
    });

    it('enforces rollout rules on the server and uses the owner plan', async () => {
        const fx = await fixture();
        const member = await createUser();
        config.NODE_ENV = 'production';
        config.INVOICE_SUBSCRIPTIONS_ACTIVE = false;
        await service().updateSettings(fx.workspace.id, fx.user.id, { template: 'executive' });
        await expect(
            service().updateSettings(fx.workspace.id, fx.user.id, {
                customization: {
                    font: 'serif',
                    density: 'compact',
                    tableStyle: 'ruled',
                    logoPlacement: 'left',
                    paperSize: 'A4',
                },
            }),
        ).rejects.toMatchObject({ statusCode: 403 });
        config.INVOICE_SUBSCRIPTIONS_ACTIVE = true;
        await expect(
            service().updateSettings(fx.workspace.id, fx.user.id, { template: 'studio' }),
        ).rejects.toMatchObject({ statusCode: 403 });
        await testPrisma.userSubscription.create({
            data: { userId: fx.user.id, plan: 'GROWTH', status: 'ACTIVE' },
        });
        expect(
            (await service().updateSettings(fx.workspace.id, member.id, { template: 'studio' }))
                .template,
        ).toBe('studio');
        expect((await service().getSettings(fx.workspace.id)).access.customizationAllowed).toBe(
            true,
        );
    });
});

describe('invoice documents and draft lifecycle', () => {
    it('preserves order, precision, customer snapshot, issuer profile and saved terms', async () => {
        const fx = await fixture();
        await testPrisma.workspaceProfile.create({
            data: {
                workspaceId: fx.workspace.id,
                displayName: 'Example Business',
                addressLine1: 'Kampala Road',
                phone: '+256 700 000 000',
                taxId: 'TIN-1',
            },
        });
        await service().updateSettings(fx.workspace.id, fx.user.id, {
            template: 'signature',
            defaultTerms: 'Net 14',
            defaultNotes: 'Default notes',
        });
        const invoice = await service().createInvoice(fx.workspace.id, fx.user.id, fx.input);
        await testPrisma.invoice.update({
            where: { id: invoice!.id },
            data: {
                billToSnapshot: {
                    name: 'Original customer',
                    billingAddress: { line1: 'Original address' },
                },
            },
        });
        const document = await service().invoiceDocument(invoice!.id, fx.workspace.id);
        expect(document.appearance.template.id).toBe('signature');
        expect(document.business.lines).toContain('Kampala Road');
        expect(document.customer.name).toBe('Original customer');
        expect(document.items.map((i) => i.name)).toEqual(['First', 'Second']);
        expect(document.totals[0].value).toBe('250.2468');
        expect(document.paymentTerms).toBe('Net 14');
        expect(document.status).toBe('DRAFT');
        await service().updateSettings(fx.workspace.id, fx.user.id, { defaultTerms: 'Net 60' });
        expect((await service().invoiceDocument(invoice!.id, fx.workspace.id)).paymentTerms).toBe(
            'Net 14',
        );
        const other = await fixture();
        await expect(
            service().invoiceDocument(invoice!.id, other.workspace.id),
        ).rejects.toMatchObject({ statusCode: 404 });
    });

    it('calculates preview with taxes and discounts without persisting anything', async () => {
        const fx = await fixture();
        const tax = await testPrisma.tax.create({
            data: { workspaceId: fx.workspace.id, name: 'VAT', rate: '18' },
        });
        const input = {
            ...fx.input,
            discountAmount: '10',
            items: [{ ...fx.input.items[0], unitPrice: '100', taxId: tax.id }],
        };
        const document = await service().draftDocument(fx.workspace.id, input);
        expect(document.totals.map((t) => t.value)).toEqual([
            '200.00',
            '10.00',
            '36.00',
            '226.00',
            '0.00',
            '226.00',
        ]);
        expect(await testPrisma.invoice.count()).toBe(0);
        const invoice = await service().createInvoice(fx.workspace.id, fx.user.id, input);
        expect((await service().invoiceDocument(invoice!.id, fx.workspace.id)).totals).toEqual(
            document.totals,
        );
    });

    it('keeps items and totals together, updates discounts alone, and rejects invalid dates', async () => {
        const fx = await fixture();
        const invoice = await service().createInvoice(fx.workspace.id, fx.user.id, fx.input);
        await service().updateInvoice(invoice!.id, fx.workspace.id, fx.user.id, {
            discountAmount: '50',
        });
        expect(
            (await service().getInvoice(invoice!.id, fx.workspace.id)).totalAmount.toString(),
        ).toBe('200.2468');
        await expect(
            service().updateInvoice(invoice!.id, fx.workspace.id, fx.user.id, {
                dueDate: '2025-01-01T00:00:00Z',
                items: [{ ...fx.input.items[0], name: 'Wrong' }],
            }),
        ).rejects.toMatchObject({ statusCode: 400 });
        expect((await service().getInvoice(invoice!.id, fx.workspace.id)).items[0].name).toBe(
            'First',
        );
        await service().updateInvoice(invoice!.id, fx.workspace.id, fx.user.id, {
            items: [{ ...fx.input.items[0], unitPrice: '80' }],
        });
        expect(
            (await service().getInvoice(invoice!.id, fx.workspace.id)).totalAmount.toString(),
        ).toBe('110');
    });

    it('claims invoice issuance once during a simultaneous send', async () => {
        const fx = await fixture();
        const invoice = await service().createInvoice(fx.workspace.id, fx.user.id, fx.input);
        const outcomes = await Promise.allSettled([
            service().sendInvoice(invoice!.id, fx.workspace.id, fx.user.id),
            service().sendInvoice(invoice!.id, fx.workspace.id, fx.user.id),
        ]);
        expect(outcomes.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
        expect(
            await testPrisma.cashbookObligation.count({ where: { referenceId: invoice!.id } }),
        ).toBe(1);
    });
});

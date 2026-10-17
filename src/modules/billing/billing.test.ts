/**
 * Plans: what they cost, what they allow, and that nothing can be charged
 * before payments go live.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { config } from '../../config';
import { resetDatabase, testPrisma } from '../../test/setup';
import { resolveService } from '../../test/container';
import { createUser } from '../../test/factories';
import { PLANS, quote } from '../../core/billing/plans';
import { getStorageLimitBytes } from '../storage/storage-quota.service';
import { WorkspacesService } from '../workspaces/workspaces.service';
import { BillingService, maskPhone, type PaymentProvider } from './billing.service';
import { checkoutSchema, normalizePhone } from './billing.dto';

const GIB = 1024 ** 3;
const billing = () => resolveService(BillingService);
const workspaces = () => resolveService(WorkspacesService);
const setEnforced = (on: boolean) => { (config as { PLAN_LIMITS_ENFORCED: boolean }).PLAN_LIMITS_ENFORCED = on; };

/** A stand-in mobile-money provider: records what it was asked for. */
function fakeProvider(answer: 'PENDING' | 'FAILED' = 'PENDING') {
    const charges: Array<{ amountUgx: number; phone: string; reference: string }> = [];
    const provider: PaymentProvider = {
        name: 'fake',
        enabled: true,
        async charge(input) {
            charges.push(input);
            return answer === 'PENDING'
                ? { status: 'PENDING', providerReference: `fake-${charges.length}` }
                : { status: 'FAILED', reason: 'Insufficient balance' };
        },
    };
    return { provider, charges, service: new BillingService(testPrisma, provider) };
}

describe('plan pricing', () => {
    it('prices each plan, and adds storage per GB within the plan’s ceiling', () => {
        expect(quote(PLANS.FREE).totalUgx).toBe(0);
        expect(quote(PLANS.STARTER).totalUgx).toBe(5000);
        expect(quote(PLANS.GROWTH).totalUgx).toBe(15000);

        // Starter's 2.5 GB taken to 5 GB: 2.5 GB extra at 500/GB.
        const starter = quote(PLANS.STARTER, 2.5);
        expect(starter).toMatchObject({ storageGb: 5, storagePriceUgx: 1250, totalUgx: 6250 });
        // Requests snap to 0.5 GB steps.
        expect(quote(PLANS.STARTER, 1.3)).toMatchObject({ extraStorageGb: 1.5, storageGb: 4 });

        // Capped at the plan's maximum, never priced beyond it.
        expect(quote(PLANS.STARTER, 999)).toMatchObject({ extraStorageGb: 7.5, storageGb: 10, totalUgx: 8750 });
        expect(quote(PLANS.GROWTH, 40)).toMatchObject({ storageGb: 50, totalUgx: 31000 });
        // Free can't buy storage.
        expect(quote(PLANS.FREE, 5)).toMatchObject({ extraStorageGb: 0, totalUgx: 0 });
    });

    it('accepts Ugandan mobile-money numbers in the usual forms', () => {
        for (const phone of ['0771234567', '771234567', '256771234567', '+256 771 234 567', '0701-234-567']) {
            expect(checkoutSchema.safeParse({ plan: 'STARTER', phone }).success).toBe(true);
        }
        expect(checkoutSchema.safeParse({ plan: 'STARTER', phone: '0412345678' }).success).toBe(false);
        expect(checkoutSchema.safeParse({ plan: 'FREE', phone: '0771234567' }).success).toBe(false);
        expect(normalizePhone('0771 234 567')).toBe('+256771234567');
        expect(normalizePhone('+256771234567')).toBe('+256771234567');
        expect(maskPhone('+256771234567')).toBe('+256 77• ••• 567');
    });
});

describe('billing', () => {
    const enforced = config.PLAN_LIMITS_ENFORCED;
    beforeEach(async () => { await resetDatabase(); });
    afterEach(() => setEnforced(enforced));

    it('puts every account on Free until it chooses otherwise', async () => {
        const user = await createUser();
        expect(await billing().account(user.id)).toMatchObject({
            plan: 'FREE', businessWorkspaces: 1, storageGb: 1, priceUgx: 0, paymentsEnabled: false,
        });
    });

    it('refuses checkout as coming soon, and records nothing', async () => {
        const user = await createUser();
        await expect(billing().checkout(user.id, { plan: 'STARTER', extraStorageGb: 2, phone: '0771234567' }))
            .rejects.toMatchObject({ code: 'PAYMENTS_COMING_SOON', statusCode: 503 });
        expect(await testPrisma.userSubscription.count()).toBe(0);
        expect(await testPrisma.subscriptionPayment.count()).toBe(0);
    });

    describe('once a provider is plugged in', () => {
        it('charges the catalogue price, never activating before the provider confirms', async () => {
            const user = await createUser();
            const { service, charges } = fakeProvider();

            const pending = await service.checkout(user.id, { plan: 'STARTER', extraStorageGb: 2.5, phone: '0771 234 567' });
            expect(pending).toMatchObject({ status: 'PENDING', amountUgx: 6250 });
            expect(charges).toEqual([expect.objectContaining({ amountUgx: 6250, phone: '+256771234567', reference: pending.reference })]);

            const payment = await testPrisma.subscriptionPayment.findUniqueOrThrow({ where: { reference: pending.reference } });
            expect(payment).toMatchObject({ status: 'PENDING', amountUgx: 6250, phoneMasked: '+256 77• ••• 567', providerReference: 'fake-1' });
            expect((await service.account(user.id)).plan).toBe('FREE');
        });

        it('sends one prompt for a double tap', async () => {
            const user = await createUser();
            const { service, charges } = fakeProvider();
            const results = await Promise.allSettled([
                service.checkout(user.id, { plan: 'GROWTH', extraStorageGb: 0, phone: '0771234567' }),
                service.checkout(user.id, { plan: 'GROWTH', extraStorageGb: 0, phone: '0771234567' }),
            ]);
            expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
            expect((results.find((r) => r.status === 'rejected') as PromiseRejectedResult).reason)
                .toMatchObject({ code: 'PAYMENT_IN_PROGRESS' });
            expect(charges).toHaveLength(1);
        });

        it('records a declined payment as failed, with nothing activated', async () => {
            const user = await createUser();
            const { service } = fakeProvider('FAILED');
            await expect(service.checkout(user.id, { plan: 'STARTER', extraStorageGb: 0, phone: '0771234567' }))
                .rejects.toMatchObject({ code: 'PAYMENT_FAILED' });
            expect(await testPrisma.subscriptionPayment.findFirst()).toMatchObject({ status: 'FAILED', failureReason: 'Insufficient balance' });
            expect(await testPrisma.userSubscription.count()).toBe(0);
        });

        it('activates a month of the plan once on confirmation, renews after it, and lapses after the grace days', async () => {
            const user = await createUser();
            const { service } = fakeProvider();
            const day = (iso: string) => new Date(`${iso}T09:00:00.000Z`);

            const first = await service.checkout(user.id, { plan: 'STARTER', extraStorageGb: 2.5, phone: '0771234567' }, day('2026-10-01'));
            expect(await service.settlePayment(first.reference, { succeeded: true }, day('2026-10-01'))).toEqual({ settled: true, status: 'SUCCEEDED' });
            // The provider calling back again changes nothing.
            expect(await service.settlePayment(first.reference, { succeeded: true }, day('2026-10-02'))).toEqual({ settled: false, status: 'SUCCEEDED' });

            const active = await service.account(user.id, day('2026-10-15'));
            expect(active).toMatchObject({ plan: 'STARTER', storageGb: 5, currentPeriodEnd: '2026-11-01T09:00:00.000Z' });

            // Renewing the same plan early adds a month after the current one.
            const renewal = await service.checkout(user.id, { plan: 'STARTER', extraStorageGb: 2.5, phone: '0771234567' }, day('2026-10-28'));
            await service.settlePayment(renewal.reference, { succeeded: true }, day('2026-10-28'));
            expect((await service.account(user.id, day('2026-11-15'))).currentPeriodEnd).toBe('2026-12-01T09:00:00.000Z');

            // Three days' grace after the period ends, then Free.
            expect((await service.account(user.id, day('2026-12-03'))).plan).toBe('STARTER');
            expect((await service.account(user.id, day('2026-12-05'))).plan).toBe('FREE');
        });

        it('settles a declined confirmation as failed without touching the plan', async () => {
            const user = await createUser();
            const { service } = fakeProvider();
            const pending = await service.checkout(user.id, { plan: 'GROWTH', extraStorageGb: 0, phone: '0771234567' });
            expect(await service.settlePayment(pending.reference, { succeeded: false, reason: 'Cancelled on phone' }))
                .toEqual({ settled: true, status: 'FAILED' });
            expect(await testPrisma.userSubscription.count()).toBe(0);
        });
    });

    it('raises storage to what the owner’s plan includes, and never lowers a grant', async () => {
        const owner = await createUser();
        const ws = await workspaces().createBusinessWorkspace(owner.id, { name: 'Shop', defaultCurrency: 'UGX' } as never);
        expect(await getStorageLimitBytes(testPrisma, ws.id)).toBe(GIB);

        await testPrisma.userSubscription.create({ data: { userId: owner.id, plan: 'STARTER', extraStorageGb: 2.5 } });
        expect(await getStorageLimitBytes(testPrisma, ws.id)).toBe(5 * GIB);

        // A superadmin grant bigger than the plan stays.
        await testPrisma.workspace.update({ where: { id: ws.id }, data: { storageQuotaBytes: BigInt(20 * GIB) } });
        expect(await getStorageLimitBytes(testPrisma, ws.id)).toBe(20 * GIB);
    });

    it('leaves workspace creation unlimited while limits are off', async () => {
        setEnforced(false);
        const owner = await createUser();
        for (const name of ['A', 'B', 'C']) {
            await workspaces().createBusinessWorkspace(owner.id, { name, defaultCurrency: 'UGX' } as never);
        }
        expect(await testPrisma.workspace.count({ where: { ownerId: owner.id, type: 'BUSINESS' } })).toBe(3);
    });

    it('holds Free to one business workspace when enforced, even when two are created at once', async () => {
        setEnforced(true);
        const owner = await createUser();
        const attempts = await Promise.allSettled([
            workspaces().createBusinessWorkspace(owner.id, { name: 'One', defaultCurrency: 'UGX' } as never),
            workspaces().createBusinessWorkspace(owner.id, { name: 'Two', defaultCurrency: 'UGX' } as never),
        ]);
        expect(attempts.filter((a) => a.status === 'fulfilled')).toHaveLength(1);
        const refused = attempts.find((a) => a.status === 'rejected') as PromiseRejectedResult;
        expect(refused.reason).toMatchObject({ code: 'PLAN_WORKSPACE_LIMIT' });

        // Starter allows five; the personal workspace never counts.
        await testPrisma.userSubscription.create({ data: { userId: owner.id, plan: 'STARTER' } });
        for (const name of ['B', 'C', 'D', 'E']) {
            await workspaces().createBusinessWorkspace(owner.id, { name, defaultCurrency: 'UGX' } as never);
        }
        await expect(workspaces().createBusinessWorkspace(owner.id, { name: 'F', defaultCurrency: 'UGX' } as never))
            .rejects.toMatchObject({ code: 'PLAN_WORKSPACE_LIMIT' });
    });
});

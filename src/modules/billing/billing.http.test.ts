/**
 * /billing over real HTTP: what the pricing page and checkout actually call.
 *
 * The service rules are unit-tested in billing.test.ts; this proves the routes
 * are mounted, that the public ones need no session, that the signed-in ones
 * need one, and that checkout answers PAYMENTS_COMING_SOON — the exact body
 * the frontend keys its "coming soon" dialog on — while no provider is set.
 */
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { resetDatabase, testPrisma } from '../../test/setup';
import { createUser } from '../../test/factories';

// Imported lazily so setup.ts has redirected DATABASE_URL first, and so the
// route files can resolve their controllers from a configured container.
let app: import('express').Express;

beforeAll(async () => {
    await import('../../config/container');
    app = (await import('../../app')).default;
});

async function cookieFor(userId: string, email: string) {
    const { config } = await import('../../config');
    const token = jwt.sign(
        { userId, email, isSuperAdmin: false, jti: `test-${userId}` },
        config.JWT_ACCESS_SECRET,
        { expiresIn: '15m' },
    );
    return `accessToken=${token}`;
}

describe('billing routes', () => {
    beforeEach(async () => {
        await resetDatabase();
    });

    it('serves the catalogue and a quote without a session', async () => {
        const plans = await request(app).get('/api/v1/billing/plans');
        expect(plans.status).toBe(200);
        expect(plans.body.data).toMatchObject({
            currency: 'UGX',
            billingPeriod: 'month',
            paymentsEnabled: false,
        });
        expect(plans.body.data.plans.map((p: { key: string }) => p.key)).toEqual(['FREE', 'STARTER', 'GROWTH']);
        expect(plans.body.data.enterprise.name).toBe('Enterprise');

        // The default when no query is given, and the slider's form.
        const base = await request(app).get('/api/v1/billing/plans/quote?plan=STARTER');
        expect(base.status).toBe(200);
        expect(base.body.data).toMatchObject({ plan: 'STARTER', extraStorageGb: 0, totalUgx: 5000 });

        const sized = await request(app).get('/api/v1/billing/plans/quote?plan=STARTER&extraStorageGb=2.5');
        expect(sized.body.data).toMatchObject({ extraStorageGb: 2.5, storageGb: 5, totalUgx: 6250 });
    });

    it('refuses a quote for a plan that is arranged with us, or a bad storage amount', async () => {
        const enterprise = await request(app).get('/api/v1/billing/plans/quote?plan=ENTERPRISE');
        expect(enterprise.status).toBe(400);
        expect(enterprise.body.code).toBe('PLAN_NOT_QUOTABLE');

        const notAStep = await request(app).get('/api/v1/billing/plans/quote?plan=STARTER&extraStorageGb=1.3');
        expect(notAStep.status).toBe(400);
        expect(notAStep.body.code).toBe('VALIDATION_ERROR');
    });

    it('keeps the account and checkout behind sign-in', async () => {
        expect((await request(app).get('/api/v1/billing/account')).status).toBe(401);
        expect((await request(app).post('/api/v1/billing/checkout').send({ plan: 'STARTER', phone: '0771234567' })).status).toBe(401);
    });

    it('describes a signed-in account on Free, with limits not yet applied', async () => {
        const user = await createUser();
        const res = await request(app)
            .get('/api/v1/billing/account')
            .set('Cookie', await cookieFor(user.id, user.email));

        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({
            plan: 'FREE',
            businessWorkspaces: 1,
            ownedBusinessWorkspaces: 0,
            storageGb: 1,
            priceUgx: 0,
            limitsEnforced: false,
            paymentsEnabled: false,
        });
    });

    it('validates checkout before deciding anything', async () => {
        const user = await createUser();
        const cookie = await cookieFor(user.id, user.email);

        const badPhone = await request(app)
            .post('/api/v1/billing/checkout')
            .set('Cookie', cookie)
            .send({ plan: 'STARTER', phone: '0412345678' });
        expect(badPhone.status).toBe(400);
        expect(badPhone.body.code).toBe('VALIDATION_ERROR');

        // Free needs no payment; Enterprise is arranged with us.
        const free = await request(app)
            .post('/api/v1/billing/checkout')
            .set('Cookie', cookie)
            .send({ plan: 'FREE', phone: '0771234567' });
        expect(free.status).toBe(400);

        expect(await testPrisma.subscriptionPayment.count()).toBe(0);
    });

    it('answers coming soon with the code the app shows its notice for, and records nothing', async () => {
        const user = await createUser();
        const res = await request(app)
            .post('/api/v1/billing/checkout')
            .set('Cookie', await cookieFor(user.id, user.email))
            .send({ plan: 'STARTER', extraStorageGb: 2.5, phone: '0771 234 567' });

        expect(res.status).toBe(503);
        expect(res.body.code).toBe('PAYMENTS_COMING_SOON');
        expect(res.body.message).toContain('not open yet');
        expect(await testPrisma.subscriptionPayment.count()).toBe(0);
        expect(await testPrisma.userSubscription.count()).toBe(0);
    });
});

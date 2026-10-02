/**
 * The public, signed-out surface: deleting an account from the website and
 * the contact form. These are the endpoints app-store reviewers exercise, and
 * the ones most exposed to abuse.
 */
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';

vi.mock('../../config/email', async (original) => ({
    ...(await original<typeof import('../../config/email')>()),
    sendEmail: vi.fn(async () => {}),
}));

import { resetDatabase, testPrisma } from '../../test/setup';
import { createUser } from '../../test/factories';

let app: import('express').Express;

beforeAll(async () => {
    await import('../../config/container');
    app = (await import('../../app')).default;
});

describe('public account deletion and contact endpoints', () => {
    beforeEach(async () => {
        await resetDatabase();
    });

    it('answers identically whether or not the address has an account', async () => {
        const user = await createUser();

        const known = await request(app).post('/api/v1/account-deletion/requests').send({ email: user.email });
        const unknown = await request(app).post('/api/v1/account-deletion/requests').send({ email: 'ghost@nowhere.test' });

        expect(known.status).toBe(202);
        expect(unknown.status).toBe(202);
        expect(known.body.message).toBe(unknown.body.message);
        expect(await testPrisma.accountDeletionRequest.count()).toBe(1);
    });

    it('drops honeypot submissions without saying so', async () => {
        const user = await createUser();
        const res = await request(app)
            .post('/api/v1/account-deletion/requests')
            .send({ email: user.email, website: 'http://spam.example' });

        expect(res.status).toBe(202);
        expect(await testPrisma.accountDeletionRequest.count()).toBe(0);
    });

    it('refuses a made-up confirmation token', async () => {
        const res = await request(app)
            .post('/api/v1/account-deletion/confirm')
            .send({ token: 'x'.repeat(43) });
        expect(res.status).toBe(400);
        expect(res.body.code).toBe('INVALID_TOKEN');
    });

    it('keeps the in-app endpoints behind sign-in', async () => {
        expect((await request(app).get('/api/v1/users/me/deletion')).status).toBe(401);
        expect((await request(app).post('/api/v1/users/me/deletion').send({})).status).toBe(401);
    });

    it('stores contact messages and validates them', async () => {
        const bad = await request(app).post('/api/v1/support/contact').send({ name: 'A', email: 'nope', subject: 'x', message: 'short' });
        expect(bad.status).toBe(400);

        const good = await request(app).post('/api/v1/support/contact').send({
            name: 'Amina', email: 'amina@shop.test', category: 'privacy',
            subject: 'Export my data', message: 'Please send me a copy of everything you hold about me.',
        });
        expect(good.status).toBe(201);
        expect(await testPrisma.contactMessage.findFirst()).toMatchObject({ category: 'privacy', status: 'OPEN' });
    });
});

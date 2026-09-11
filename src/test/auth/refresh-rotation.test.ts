/**
 * Refresh-token rotation, and the expiry hint that lets the client refresh
 * before its access token lapses.
 *
 * Refresh tokens are single-use: each refresh spends the cookie and issues a
 * new one. The failure modes worth pinning down are the concurrent ones — two
 * tabs, or a timer and a 401 in the same tab, presenting the same cookie at
 * once — because that is exactly what bounced requests with a 401 while the
 * server logged a success.
 */
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { resetDatabase, testPrisma } from '../setup';
import { resolveService } from '../container';
import { createUser } from '../factories';
import { AuthService } from '../../modules/auth/auth.service';
import { accessTokenTtlMs } from '../../core/auth/token-lifetimes';

let app: import('express').Express;

beforeAll(async () => {
    await import('../../config/container');
    app = (await import('../../app')).default;
});

async function issueRefreshToken(userId: string): Promise<string> {
    const auth = resolveService(AuthService) as any;
    const { token, hash } = auth.generateRefreshToken();
    await testPrisma.refreshToken.create({
        data: { userId, tokenHash: hash, expiresAt: new Date(Date.now() + 86_400_000) },
    });
    return token;
}

describe('refresh-token rotation', () => {
    beforeEach(resetDatabase);

    it('lets exactly one of two simultaneous refreshes spend the same token', async () => {
        const user = await createUser();
        const token = await issueRefreshToken(user.id);
        const auth = resolveService(AuthService);

        const results = await Promise.allSettled([
            auth.refreshTokens(token),
            auth.refreshTokens(token),
        ]);

        expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
        // One live descendant, not two: the token family did not fork.
        expect(
            await testPrisma.refreshToken.count({ where: { userId: user.id, isRevoked: false } }),
        ).toBe(1);
    });

    it('refuses a token once it has been spent', async () => {
        const user = await createUser();
        const token = await issueRefreshToken(user.id);
        const auth = resolveService(AuthService);

        await auth.refreshTokens(token);
        await expect(auth.refreshTokens(token)).rejects.toMatchObject({ statusCode: 401 });
    });
});

describe('the access-token expiry hint', () => {
    beforeEach(resetDatabase);

    it('is set beside the access cookie, readable by the client, and matches its lifetime', async () => {
        const user = await createUser();
        const token = await issueRefreshToken(user.id);
        const ttl = accessTokenTtlMs();

        const before = Date.now();
        const response = await request(app)
            .post('/api/v1/auth/refresh')
            .set('Cookie', `refreshToken=${token}`);
        const after = Date.now();

        expect(response.status).toBe(200);

        const cookies = ([] as string[]).concat(response.headers['set-cookie'] ?? []);
        const access = cookies.find((c) => c.startsWith('accessToken='));
        const hint = cookies.find((c) => c.startsWith('accessTokenExpiresAt='));

        expect(access).toMatch(/HttpOnly/i);
        expect(hint).toBeDefined();
        // Readable by the client — the whole point of it. It carries a time,
        // not a credential.
        expect(hint).not.toMatch(/HttpOnly/i);

        const expiresAt = Number(hint!.split(';')[0]!.split('=')[1]);
        expect(expiresAt).toBeGreaterThanOrEqual(before + ttl);
        expect(expiresAt).toBeLessThanOrEqual(after + ttl);
    });

    it('marks every authenticated response as private to the browser', async () => {
        const user = await createUser();
        const token = await issueRefreshToken(user.id);

        const response = await request(app)
            .post('/api/v1/auth/refresh')
            .set('Cookie', `refreshToken=${token}`);

        expect(response.headers['cache-control']).toBe('private, no-cache');
    });
});

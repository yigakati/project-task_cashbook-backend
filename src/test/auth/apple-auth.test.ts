import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import express from 'express';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { resetDatabase, testPrisma } from '../setup';
import { resolveService } from '../container';
import { createUser } from '../factories';
import { config } from '../../config';
import { AuthService } from '../../modules/auth/auth.service';
import { AccountDeletionService } from '../../modules/account-deletion/account-deletion.service';
import {
    encryptAppleToken,
    revokeAppleCredential,
    verifyAppleToken,
} from '../../modules/auth/apple.provider';
import deviceRoutes from '../../modules/auth/device-auth.routes';
import { errorHandler } from '../../middlewares/errorHandler';

vi.mock('../../config/email', () => ({ sendEmail: vi.fn(async () => undefined) }));
vi.mock('../../middlewares/rateLimiter', () => ({
    authRateLimiter: (_req: unknown, _res: unknown, next: () => void) => next(),
}));
const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const app = express();
app.use(express.json(), cookieParser());
app.use('/api/v1/auth', deviceRoutes);
app.use(errorHandler);
const original = { ...config };
let fetchMock: ReturnType<typeof vi.fn>;
let tokenClaims: Record<string, unknown>;
let revokeFails = false;

function token(claims: Record<string, unknown> = {}) {
    return jwt.sign(
        {
            sub: 'apple-person',
            email: 'apple@privaterelay.appleid.com',
            email_verified: 'true',
            nonce: 'nonce',
            ...claims,
        },
        rsa.privateKey,
        {
            algorithm: 'RS256',
            keyid: 'test-key',
            issuer: 'https://appleid.apple.com',
            audience: config.APPLE_IOS_CLIENT_ID,
            expiresIn: '5m',
        },
    );
}
const verifier = () => crypto.randomBytes(32).toString('base64url');
const sha = (value: string) => crypto.createHash('sha256').update(value).digest('hex');
const start = async (client = 'ios', kind = 'apple') => {
    const proof = verifier();
    const response = await request(app)
        .post('/api/v1/auth/challenge')
        .send({ kind, client, verifier: proof });
    expect(response.status).toBe(200);
    return { ...response.body.data, verifier: proof };
};

beforeEach(async () => {
    await resetDatabase();
    Object.assign(config, {
        APPLE_TEAM_ID: 'TEAM123456',
        APPLE_KEY_ID: 'KEY1234567',
        APPLE_PRIVATE_KEY: ec.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
        APPLE_TOKEN_ENCRYPTION_KEY: crypto.randomBytes(32).toString('base64'),
        APPLE_WEB_CLIENT_ID: 'com.odixtec.inchange.web',
        APPLE_REDIRECT_URI: 'https://inchange.odixtec.com/auth/apple-return',
        MOBILE_AUTH_ENABLED: true,
    });
    tokenClaims = {};
    revokeFails = false;
    fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
        if (url.endsWith('/keys'))
            return new Response(
                JSON.stringify({
                    keys: [
                        {
                            ...rsa.publicKey.export({ format: 'jwk' }),
                            kid: 'test-key',
                            alg: 'RS256',
                        },
                    ],
                }),
            );
        if (url.endsWith('/revoke')) return new Response('', { status: revokeFails ? 503 : 200 });
        const body = new URLSearchParams(String(init?.body));
        const claims = { ...tokenClaims };
        const clientId = body.get('client_id')!;
        const idToken = jwt.sign(
            {
                sub: 'apple-person',
                email: 'apple@privaterelay.appleid.com',
                email_verified: 'true',
                nonce: 'nonce',
                ...claims,
            },
            rsa.privateKey,
            {
                algorithm: 'RS256',
                keyid: 'test-key',
                issuer: 'https://appleid.apple.com',
                audience: clientId,
                expiresIn: '5m',
            },
        );
        return new Response(
            JSON.stringify({ id_token: idToken, refresh_token: 'secret-refresh-token' }),
        );
    });
    vi.stubGlobal('fetch', fetchMock);
});
afterEach(() => {
    Object.assign(config, original);
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
});

describe('Apple token verification', () => {
    it('verifies a signed token against Apple keys', async () => {
        expect((await verifyAppleToken(token(), config.APPLE_IOS_CLIENT_ID, 'nonce')).sub).toBe(
            'apple-person',
        );
    });
    it.each([
        ['nonce', { nonce: 'wrong' }],
        ['issuer', { iss: 'https://evil.example' }],
        ['audience', { aud: 'different-app' }],
        ['expiry', { exp: 1 }],
        ['subject', { sub: '' }],
    ])('rejects the wrong %s', async (_name, claims) => {
        const signed = jwt.sign(
            {
                sub: 'person',
                nonce: 'nonce',
                iss: 'https://appleid.apple.com',
                aud: config.APPLE_IOS_CLIENT_ID,
                exp: Math.floor(Date.now() / 1000) + 60,
                ...claims,
            },
            rsa.privateKey,
            { algorithm: 'RS256', keyid: 'test-key' },
        );
        await expect(
            verifyAppleToken(signed, config.APPLE_IOS_CLIENT_ID, 'nonce'),
        ).rejects.toMatchObject({ statusCode: 401 });
    });
    it('rejects a forged signature and an HMAC token', async () => {
        const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        const forged = jwt.sign({ sub: 'person', nonce: 'nonce' }, other.privateKey, {
            algorithm: 'RS256',
            keyid: 'test-key',
        });
        await expect(
            verifyAppleToken(forged, config.APPLE_IOS_CLIENT_ID, 'nonce'),
        ).rejects.toMatchObject({ statusCode: 401 });
        await expect(
            verifyAppleToken(jwt.sign({}, 'secret'), config.APPLE_IOS_CLIENT_ID, 'nonce'),
        ).rejects.toMatchObject({ statusCode: 401 });
    });
});

describe('Apple identity and challenge lifecycle', () => {
    it('creates one identity, workspace, encrypted credential, and cookie session', async () => {
        const challenge = await start();
        tokenClaims = { nonce: challenge.nonce };
        const response = await request(app)
            .post('/api/v1/auth/apple')
            .send({ ...challenge, code: 'one-time', firstName: 'Ada' });
        expect(response.status).toBe(200);
        expect(response.body.data.user.firstName).toBe('Ada');
        expect(JSON.stringify(response.body)).not.toContain('secret-refresh-token');
        const credentials = await testPrisma.appleCredential.findMany();
        expect(credentials).toHaveLength(1);
        expect(credentials[0].encryptedRefreshToken).not.toContain('secret-refresh-token');
        expect(await testPrisma.workspace.count()).toBe(1);
        expect([].concat(response.headers['set-cookie'] as never).join(';')).toContain('HttpOnly');
        expect(
            (
                await request(app)
                    .post('/api/v1/auth/apple')
                    .send({ ...challenge, code: 'one-time' })
            ).status,
        ).toBe(401);
        expect(await testPrisma.user.count()).toBe(1);
    });
    it('rejects missing proof, wrong proof, and expired challenges before exchanging codes', async () => {
        expect((await request(app).post('/api/v1/auth/apple').send({ code: 'code' })).status).toBe(
            400,
        );
        const challenge = await start();
        expect(
            (
                await request(app)
                    .post('/api/v1/auth/apple')
                    .send({ ...challenge, verifier: verifier(), code: 'code' })
            ).status,
        ).toBe(401);
        await testPrisma.authChallenge.update({
            where: { id: challenge.challengeId },
            data: { expiresAt: new Date(0) },
        });
        expect(
            (
                await request(app)
                    .post('/api/v1/auth/apple')
                    .send({ ...challenge, code: 'code' })
            ).status,
        ).toBe(401);
        expect(fetchMock).not.toHaveBeenCalled();
    });
    it('requires explicit linking when an email already belongs to a user', async () => {
        const user = await createUser({ email: 'apple@privaterelay.appleid.com' });
        await expect(
            resolveService(AuthService).appleLogin({ code: 'code', client: 'ios', nonce: 'nonce' }),
        ).rejects.toMatchObject({ statusCode: 409 });
        expect(await testPrisma.linkedIdentity.count()).toBe(0);
        await resolveService(AuthService).appleLogin(
            { code: 'code', client: 'ios', nonce: 'nonce' },
            undefined,
            undefined,
            user.id,
        );
        expect(await testPrisma.linkedIdentity.count()).toBe(1);
        const other = await createUser();
        await expect(
            resolveService(AuthService).appleLogin(
                { code: 'code', client: 'ios', nonce: 'nonce' },
                undefined,
                undefined,
                other.id,
            ),
        ).rejects.toMatchObject({ statusCode: 409 });
    });
    it('supports repeat consent without name/email and retains both client revocation tokens', async () => {
        const auth = resolveService(AuthService);
        const first = await auth.appleLogin({
            code: 'code',
            client: 'ios',
            nonce: 'nonce',
            firstName: 'Ada',
        });
        tokenClaims = { email: undefined, email_verified: undefined };
        const second = await auth.appleLogin({ code: 'code2', client: 'web', nonce: 'nonce' });
        expect(second.user.id).toBe(first.user.id);
        expect(second.user.firstName).toBe('Ada');
        expect(await testPrisma.appleCredential.count()).toBe(2);
    });
    it('serializes simultaneous first consent without duplicate accounts or workspaces', async () => {
        const auth = resolveService(AuthService);
        const results = await Promise.all([
            auth.appleLogin({ code: 'a', client: 'ios', nonce: 'nonce' }),
            auth.appleLogin({ code: 'b', client: 'ios', nonce: 'nonce' }),
        ]);
        expect(results[0].user.id).toBe(results[1].user.id);
        expect(await testPrisma.workspace.count()).toBe(1);
    });
    it('rejects unverified email and rolls back identity creation', async () => {
        tokenClaims = { email_verified: false };
        await expect(
            resolveService(AuthService).appleLogin({ code: 'code', client: 'ios', nonce: 'nonce' }),
        ).rejects.toMatchObject({ statusCode: 401 });
        expect(await testPrisma.user.count()).toBe(0);
    });
    it('binds encrypted credentials to identity and client', async () => {
        const encrypted = encryptAppleToken('secret-token', 'identity', 'client');
        await expect(
            revokeAppleCredential({
                identityId: 'another-identity',
                clientId: 'client',
                encryptedRefreshToken: encrypted,
            }),
        ).rejects.toMatchObject({ code: 'APPLE_REVOCATION_FAILED' });
        expect(fetchMock).not.toHaveBeenCalled();
    });
    it('keeps credentials and account on revocation failure, then purges on explicit retry', async () => {
        const { user } = await resolveService(AuthService).appleLogin({
            code: 'code',
            client: 'ios',
            nonce: 'nonce',
        });
        const deletion = await testPrisma.accountDeletionRequest.create({
            data: {
                userId: user.id,
                status: 'SCHEDULED',
                source: 'IN_APP',
                scheduledFor: new Date(0),
            },
        });
        revokeFails = true;
        await expect(
            resolveService(AccountDeletionService).execute(deletion.id),
        ).rejects.toMatchObject({ code: 'APPLE_REVOCATION_FAILED' });
        expect(await testPrisma.appleCredential.count()).toBe(1);
        expect((await testPrisma.user.findUniqueOrThrow({ where: { id: user.id } })).isActive).toBe(
            true,
        );
        revokeFails = false;
        await resolveService(AccountDeletionService).execute(deletion.id, { actorId: user.id });
        expect(await testPrisma.appleCredential.count()).toBe(0);
        expect(
            (await testPrisma.user.findUniqueOrThrow({ where: { id: user.id } })).deletedAt,
        ).not.toBeNull();
    });
});

describe('native browser handoff', () => {
    it('requires both secrets and redeems only once under concurrency', async () => {
        const user = await createUser();
        const challenge = await start('ios', 'google');
        const browser = await request(app)
            .post('/api/v1/auth/mobile/browser')
            .send({
                challengeId: challenge.challengeId,
                browserProof: new URLSearchParams(new URL(challenge.url).hash.slice(1)).get(
                    'proof',
                ),
            });
        expect(browser.status).toBe(200);
        expect(
            (
                await request(app)
                    .post('/api/v1/auth/mobile/browser')
                    .send({
                        challengeId: challenge.challengeId,
                        browserProof: new URLSearchParams(new URL(challenge.url).hash.slice(1)).get(
                            'proof',
                        ),
                    })
            ).status,
        ).toBe(401);
        vi.spyOn(AuthService.prototype, 'googleLogin').mockResolvedValue({
            user,
            accessToken: '',
            refreshToken: '',
        });
        const complete = await request(app).post('/api/v1/auth/mobile/complete').send({
            challengeId: challenge.challengeId,
            browserSecret: browser.body.data.browserSecret,
            idToken: 'google-id',
        });
        expect(complete.status).toBe(200);
        const code = new URL(complete.body.data.returnUrl).searchParams.get('code');
        expect(
            (
                await request(app)
                    .post('/api/v1/auth/mobile/redeem')
                    .send({ challengeId: challenge.challengeId, verifier: verifier(), code })
            ).status,
        ).toBe(401);
        const results = await Promise.all(
            [1, 2].map(() =>
                request(app).post('/api/v1/auth/mobile/redeem').send({
                    challengeId: challenge.challengeId,
                    verifier: challenge.verifier,
                    code,
                }),
            ),
        );
        expect(results.map((r) => r.status).sort()).toEqual([200, 401]);
        expect(await testPrisma.refreshToken.count()).toBe(1);
    });
    it('requires authentication to start an account connection', async () => {
        expect(
            (
                await request(app)
                    .post('/api/v1/auth/connect/challenge')
                    .send({ kind: 'apple', client: 'ios', verifier: verifier() })
            ).status,
        ).toBe(401);
    });
});

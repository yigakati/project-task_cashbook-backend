import { Router, Request, Response, NextFunction } from 'express';
import { container } from 'tsyringe';
import { PrismaClient, Prisma } from '@prisma/client';
import crypto from 'node:crypto';
import { z } from 'zod';
import { config } from '../../config';
import { AuthService } from './auth.service';
import { setAuthCookies } from './auth.controller';
import { appleAvailable, appleConfiguration } from './apple.provider';
import { authenticate } from '../../middlewares/authenticate';
import { authRateLimiter } from '../../middlewares/rateLimiter';
import { AuthenticatedRequest } from '../../core/types';
import {
    AppError,
    AuthenticationError,
    ConflictError,
    ValidationError,
} from '../../core/errors/AppError';

const router = Router();
const db = () => container.resolve<PrismaClient>('PrismaClient');
const auth = () => container.resolve(AuthService);
const hash = (value: string) => crypto.createHash('sha256').update(value).digest('hex');
const secret = z.string().regex(/^[A-Za-z0-9_-]{43,128}$/);
const proof = z.object({ challengeId: z.string().uuid(), verifier: secret });
const referral = {
    referralCode: z.string().trim().max(32).optional(),
    referralSource: z.enum(['LINK', 'CODE']).optional(),
};
const route =
    (handler: (req: Request, res: Response) => Promise<unknown>) =>
    (req: Request, res: Response, next: NextFunction) => {
        void handler(req, res).catch((error) => {
            if (error instanceof z.ZodError)
                return next(new ValidationError('Check the sign-in request and try again.'));
            if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002')
                return next(
                    new ConflictError(
                        'This identity was connected in another request. Sign in again.',
                    ),
                );
            next(error);
        });
    };

router.use((_req, res, next) => {
    if (
        [
            '/providers',
            '/challenge',
            '/connect/challenge',
            '/apple',
            '/mobile/browser',
            '/mobile/complete',
            '/mobile/redeem',
        ].includes(_req.path)
    ) {
        res.set('Cache-Control', 'no-store');
    }
    next();
});
router.get('/providers', (_req, res) =>
    res.json({
        success: true,
        data: {
            apple: { web: appleAvailable('web'), ios: appleAvailable('ios') },
            mobile: config.MOBILE_AUTH_ENABLED,
        },
    }),
);

const start = route(async (req, res) => {
    const data = z
        .object({
            kind: z.enum(['apple', 'google', 'oc']),
            client: z.enum(['web', 'ios']),
            verifier: secret,
            ...referral,
        })
        .parse(req.body);
    if (data.kind !== 'apple' && (data.client !== 'ios' || !config.MOBILE_AUTH_ENABLED))
        throw new AppError('Mobile sign-in is not enabled', 503, 'MOBILE_NOT_CONFIGURED');
    const apple = data.kind === 'apple' ? appleConfiguration(data.client) : undefined;
    const browserProof = crypto.randomBytes(32).toString('base64url');
    await db().authChallenge.deleteMany({ where: { expiresAt: { lt: new Date() } } });
    const challenge = await db().authChallenge.create({
        data: {
            kind: data.kind,
            client: data.client,
            resultCodeHash: data.kind !== 'apple' ? hash(browserProof) : null,
            referralCode: data.referralCode,
            referralSource: data.referralSource,
            verifierHash: hash(data.verifier),
            nonce: crypto.randomBytes(32).toString('hex'),
            userId: (req as AuthenticatedRequest).user?.userId,
            expiresAt: new Date(Date.now() + 10 * 60_000),
        },
    });
    res.json({
        success: true,
        data: {
            challengeId: challenge.id,
            nonce: challenge.nonce,
            ...apple,
            ...(data.kind !== 'apple'
                ? {
                      url: `${config.APP_URL}/auth/mobile?challenge=${challenge.id}#proof=${browserProof}`,
                  }
                : {}),
        },
    });
});
router.post('/challenge', authRateLimiter, start);
router.post('/connect/challenge', authRateLimiter, authenticate as any, start);

router.post(
    '/apple',
    authRateLimiter,
    route(async (req, res) => {
        const data = proof
            .extend({
                code: z.string().min(1).max(4096),
                firstName: z.string().trim().max(100).optional(),
                lastName: z.string().trim().max(100).optional(),
                ...referral,
            })
            .parse(req.body);
        const challenge = await db().authChallenge.findUnique({ where: { id: data.challengeId } });
        if (
            !challenge ||
            challenge.kind !== 'apple' ||
            challenge.verifierHash !== hash(data.verifier) ||
            challenge.consumedAt ||
            challenge.expiresAt <= new Date()
        )
            throw new AuthenticationError('This sign-in attempt expired. Please start again.');
        const claimed = await db().authChallenge.updateMany({
            where: { id: challenge.id, consumedAt: null },
            data: { consumedAt: new Date() },
        });
        if (!claimed.count) throw new AuthenticationError('This sign-in attempt was already used');
        const result = await auth().appleLogin(
            { ...data, client: challenge.client as 'web' | 'ios', nonce: challenge.nonce },
            req.ip,
            req.get('user-agent'),
            challenge.userId ?? undefined,
        );
        setAuthCookies(res, result.accessToken, result.refreshToken);
        res.json({ success: true, data: { user: result.user } });
    }),
);

// The system browser receives no native-session credentials. A second secret,
// generated here, binds completion to this browser; redemption also needs the
// verifier retained by the native app (never placed in a URL).
router.post(
    '/mobile/browser',
    authRateLimiter,
    route(async (req, res) => {
        if (!config.MOBILE_AUTH_ENABLED) throw new AppError('Mobile sign-in is not enabled', 503);
        const { challengeId, browserProof } = z
            .object({ challengeId: z.string().uuid(), browserProof: secret })
            .parse(req.body);
        const challenge = await db().authChallenge.findUnique({ where: { id: challengeId } });
        if (
            !challenge ||
            !['google', 'oc'].includes(challenge.kind) ||
            challenge.expiresAt <= new Date() ||
            challenge.consumedAt
        )
            throw new AuthenticationError('Sign-in expired');
        const browserSecret = crypto.randomBytes(32).toString('base64url');
        const claimed = await db().authChallenge.updateMany({
            where: { id: challengeId, resultCodeHash: hash(browserProof) },
            data: { resultCodeHash: hash(browserSecret) },
        });
        if (!claimed.count)
            throw new AuthenticationError(
                'This sign-in window was already opened. Start again in the app.',
            );
        res.json({ success: true, data: { provider: challenge.kind, browserSecret } });
    }),
);

router.post(
    '/mobile/complete',
    authRateLimiter,
    route(async (req, res) => {
        const data = z
            .object({
                challengeId: z.string().uuid(),
                browserSecret: secret,
                idToken: z.string().max(10000).optional(),
                code: z.string().max(4096).optional(),
                ...referral,
            })
            .parse(req.body);
        const challenge = await db().authChallenge.findUnique({ where: { id: data.challengeId } });
        if (
            !config.MOBILE_AUTH_ENABLED ||
            !challenge ||
            challenge.resultCodeHash !== hash(data.browserSecret) ||
            challenge.expiresAt <= new Date() ||
            challenge.consumedAt
        )
            throw new AuthenticationError('Sign-in expired');
        const claimed = await db().authChallenge.updateMany({
            where: { id: challenge.id, consumedAt: null },
            data: { consumedAt: new Date() },
        });
        if (!claimed.count) throw new AuthenticationError('Sign-in already completed');
        let userId: string;
        if (challenge.kind === 'google' && data.idToken) {
            const dto = {
                idToken: data.idToken,
                referralCode: challenge.referralCode ?? undefined,
                referralSource: challenge.referralSource as 'LINK' | 'CODE' | undefined,
            };
            if (challenge.userId)
                userId = (
                    await auth().connectGoogle(challenge.userId, dto, req.ip, req.get('user-agent'))
                ).id;
            else
                userId = (await auth().googleLogin(dto, req.ip, req.get('user-agent'), false)).user
                    .id;
        } else if (challenge.kind === 'oc' && data.code) {
            const dto = {
                code: data.code,
                referralCode: challenge.referralCode ?? undefined,
                referralSource: challenge.referralSource as 'LINK' | 'CODE' | undefined,
            };
            if (challenge.userId)
                userId = (
                    await auth().connectOc(challenge.userId, dto, req.ip, req.get('user-agent'))
                ).id;
            else userId = (await auth().ocLogin(dto, req.ip, req.get('user-agent'), false)).user.id;
        } else throw new AuthenticationError('Missing provider authorization');
        const code = crypto.randomBytes(32).toString('base64url');
        await db().authChallenge.update({
            where: { id: challenge.id },
            data: {
                resultUserId: userId,
                resultCodeHash: hash(code),
                expiresAt: new Date(Date.now() + 60_000),
            },
        });
        res.json({
            success: true,
            data: {
                returnUrl: `com.odixtec.inchange://auth?challenge=${challenge.id}&code=${code}`,
            },
        });
    }),
);

router.post(
    '/mobile/redeem',
    authRateLimiter,
    route(async (req, res) => {
        const data = proof.extend({ code: secret }).parse(req.body);
        const userId = await db().$transaction(async (tx) => {
            const challenge = await tx.authChallenge.findUnique({
                where: { id: data.challengeId },
            });
            if (
                !config.MOBILE_AUTH_ENABLED ||
                !challenge?.resultUserId ||
                challenge.verifierHash !== hash(data.verifier) ||
                challenge.resultCodeHash !== hash(data.code) ||
                challenge.expiresAt <= new Date()
            )
                throw new AuthenticationError('Sign-in expired. Start again in the app.');
            const claimed = await tx.authChallenge.deleteMany({
                where: { id: challenge.id, resultCodeHash: challenge.resultCodeHash },
            });
            if (!claimed.count) throw new AuthenticationError('Sign-in already redeemed');
            return challenge.resultUserId;
        });
        const result = await auth().createOAuthSession(userId, req.ip, req.get('user-agent'));
        setAuthCookies(res, result.accessToken, result.refreshToken);
        res.json({ success: true, data: { user: result.user } });
    }),
);
export default router;

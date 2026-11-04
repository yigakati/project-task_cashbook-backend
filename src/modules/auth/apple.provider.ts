import crypto from 'node:crypto';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { z } from 'zod';
import { config } from '../../config';
import { AppError, AuthenticationError } from '../../core/errors/AppError';

const ISSUER = 'https://appleid.apple.com';
const TIMEOUT_MS = 10_000;
let cachedKeys:
    { keys: crypto.webcrypto.JsonWebKey[]; expiresAt: number; fetchedAt: number } | undefined;

export function appleConfiguration(client: 'web' | 'ios') {
    const clientId = client === 'ios' ? config.APPLE_IOS_CLIENT_ID : config.APPLE_WEB_CLIENT_ID;
    if (
        !clientId ||
        !config.APPLE_TEAM_ID ||
        !config.APPLE_KEY_ID ||
        !config.APPLE_PRIVATE_KEY ||
        Buffer.from(config.APPLE_TOKEN_ENCRYPTION_KEY, 'base64').length !== 32 ||
        (client === 'web' && !config.APPLE_REDIRECT_URI.startsWith('https://'))
    ) {
        throw new AppError(
            'Apple sign-in is not configured. Please use another sign-in method.',
            503,
            'APPLE_NOT_CONFIGURED',
        );
    }
    try {
        const key = crypto.createPrivateKey(config.APPLE_PRIVATE_KEY.replace(/\\n/g, '\n'));
        if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1')
            throw new Error('Wrong key');
        if (
            !/^[A-Z0-9]{10}$/.test(config.APPLE_TEAM_ID) ||
            !/^[A-Z0-9]{10}$/.test(config.APPLE_KEY_ID)
        )
            throw new Error('Invalid identifiers');
        if (
            client === 'web' &&
            new URL(config.APPLE_REDIRECT_URI).origin !== new URL(config.APP_URL).origin
        )
            throw new Error('Wrong callback origin');
    } catch {
        throw new AppError(
            'Apple sign-in configuration is invalid. Please use another sign-in method.',
            503,
            'APPLE_NOT_CONFIGURED',
        );
    }
    return { clientId, redirectUri: client === 'web' ? config.APPLE_REDIRECT_URI : undefined };
}

export function appleAvailable(client: 'web' | 'ios'): boolean {
    try {
        appleConfiguration(client);
        return true;
    } catch {
        return false;
    }
}

function clientSecret(clientId: string): string {
    return jwt.sign({}, config.APPLE_PRIVATE_KEY.replace(/\\n/g, '\n'), {
        algorithm: 'ES256',
        keyid: config.APPLE_KEY_ID,
        issuer: config.APPLE_TEAM_ID,
        subject: clientId,
        audience: ISSUER,
        expiresIn: '5m',
    });
}

async function applePost(path: 'token' | 'revoke', body: Record<string, string>) {
    let response: Response;
    try {
        response = await fetch(`${ISSUER}/auth/${path}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ ...body, client_secret: clientSecret(body.client_id) }),
            signal: AbortSignal.timeout(TIMEOUT_MS),
        });
    } catch {
        throw new AppError('Apple is unavailable. Please try again.', 503, 'APPLE_UNAVAILABLE');
    }
    if (!response.ok) {
        if (response.status >= 500 || response.status === 429) {
            throw new AppError('Apple is unavailable. Please try again.', 503, 'APPLE_UNAVAILABLE');
        }
        // Never log Apple's response: it may contain tokens or personal data.
        throw new AuthenticationError(
            'Apple authorization expired or was rejected. Please sign in again.',
        );
    }
    return response;
}

export async function verifyAppleToken(
    token: string,
    clientId: string,
    nonce: string,
): Promise<JwtPayload> {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || decoded.header.alg !== 'RS256' || !decoded.header.kid) {
        throw new AuthenticationError('Invalid Apple identity token');
    }
    const now = Date.now();
    const missing = !cachedKeys?.keys.some(
        (key) => (key as crypto.webcrypto.JsonWebKey & { kid?: string }).kid === decoded.header.kid,
    );
    if (
        !cachedKeys ||
        cachedKeys.expiresAt <= now ||
        (missing && now - cachedKeys.fetchedAt > 60_000)
    ) {
        try {
            const response = await fetch(`${ISSUER}/auth/keys`, {
                signal: AbortSignal.timeout(TIMEOUT_MS),
            });
            if (!response.ok) throw new Error('Keys unavailable');
            const data = (await response.json()) as { keys: crypto.webcrypto.JsonWebKey[] };
            if (!Array.isArray(data.keys)) throw new Error('Invalid keys');
            cachedKeys = { keys: data.keys, fetchedAt: now, expiresAt: now + 3_600_000 };
        } catch {
            throw new AppError(
                'Apple verification is unavailable. Please try again.',
                503,
                'APPLE_UNAVAILABLE',
            );
        }
    }
    const key = cachedKeys.keys.find(
        (key) => (key as crypto.webcrypto.JsonWebKey & { kid?: string }).kid === decoded.header.kid,
    );
    if (!key || key.kty !== 'RSA') throw new AuthenticationError('Unknown Apple signing key');
    try {
        const payload = jwt.verify(
            token,
            crypto.createPublicKey({ key: key as crypto.webcrypto.JsonWebKey, format: 'jwk' }),
            {
                algorithms: ['RS256'],
                issuer: ISSUER,
                audience: clientId,
                clockTolerance: 5,
            },
        ) as JwtPayload;
        if (
            payload.aud !== clientId ||
            !payload.sub ||
            !payload.exp ||
            !payload.iat ||
            payload.iat > Math.floor(now / 1000) + 5 ||
            payload.nonce !== nonce
        ) {
            throw new Error('Invalid claims');
        }
        return payload;
    } catch {
        throw new AuthenticationError('Invalid Apple identity token');
    }
}

export async function exchangeAppleCode(code: string, client: 'web' | 'ios', nonce: string) {
    const { clientId, redirectUri } = appleConfiguration(client);
    const response = await applePost('token', {
        grant_type: 'authorization_code',
        code,
        client_id: clientId,
        ...(redirectUri ? { redirect_uri: redirectUri } : {}),
    });
    const data = z
        .object({ id_token: z.string().min(1), refresh_token: z.string().min(1) })
        .parse(await response.json());
    const claims = await verifyAppleToken(data.id_token, clientId, nonce);
    const email = typeof claims.email === 'string' ? claims.email.trim().toLowerCase() : undefined;
    if (
        email &&
        (!(claims.email_verified === true || claims.email_verified === 'true') ||
            !z.string().email().safeParse(email).success)
    ) {
        throw new AuthenticationError('Apple did not verify this email address');
    }
    return { subject: claims.sub!, email, refreshToken: data.refresh_token, clientId };
}

export function encryptAppleToken(token: string, identityId: string, clientId: string): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(
        'aes-256-gcm',
        Buffer.from(config.APPLE_TOKEN_ENCRYPTION_KEY, 'base64'),
        iv,
    );
    cipher.setAAD(Buffer.from(`${identityId}:${clientId}`));
    const encrypted = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
    return [iv, cipher.getAuthTag(), encrypted].map((part) => part.toString('base64')).join('.');
}

export async function revokeAppleCredential(credential: {
    identityId: string;
    clientId: string;
    encryptedRefreshToken: string;
}) {
    try {
        const [iv, tag, data] = credential.encryptedRefreshToken
            .split('.')
            .map((part) => Buffer.from(part, 'base64'));
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            Buffer.from(config.APPLE_TOKEN_ENCRYPTION_KEY, 'base64'),
            iv,
        );
        decipher.setAAD(Buffer.from(`${credential.identityId}:${credential.clientId}`));
        decipher.setAuthTag(tag);
        const token = Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
        await applePost('revoke', {
            client_id: credential.clientId,
            token,
            token_type_hint: 'refresh_token',
        });
    } catch {
        throw new AppError(
            'Apple authorization could not be revoked. Retry account deletion after checking Apple connectivity and key configuration.',
            503,
            'APPLE_REVOCATION_FAILED',
        );
    }
}

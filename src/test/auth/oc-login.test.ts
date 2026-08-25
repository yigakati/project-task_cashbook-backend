/**
 * OC (OpenChat) sign-in — the parts that are genuinely new risk surface
 * compared to `googleLogin`, which this mirrors for everything else.
 *
 * Google hands the frontend a signed ID token; verifying it is a local
 * signature check, no outbound call of ours needed. OC hands back only a
 * one-time code, so this server makes two outbound calls to a third party to
 * turn it into a session. What these tests pin down:
 *
 *   - the redirect_uri sent to OC is always the server's own fixed,
 *     registered value — never anything a caller of this endpoint supplies,
 *     since OC's app registration only ever recognises the one URI it was
 *     created with;
 *   - a hung or unreachable OC does not hang the request indefinitely;
 *   - the service refuses to run at all when it has no credentials to use.
 *
 * The full happy path (real OC token/userinfo exchange, account linking,
 * session issuance) is not mocked here, matching this codebase's existing
 * coverage of `googleLogin` — neither has a mocked-network integration test;
 * both are exercised manually against the real provider.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resetDatabase } from '../setup';
import { resolveService } from '../container';
import { AuthService } from '../../modules/auth/auth.service';
import { config } from '../../config';

const authService = () => resolveService(AuthService);

describe('ocLogin — the redirect_uri sent to OC is always our own fixed value', () => {
    beforeEach(resetDatabase);

    let fetchSpy: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        fetchSpy = vi.fn().mockRejectedValue(new Error('network mocked off'));
        vi.stubGlobal('fetch', fetchSpy);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('is never accepted as input, and the token exchange always carries the configured one', async () => {
        // No redirectUri field exists on the DTO at all — this is really a
        // compile-time guarantee (ocLoginSchema has no such key), exercised
        // here by confirming what actually goes out on the wire.
        await expect(authService().ocLogin({ code: 'irrelevant' } as any))
            .rejects.toMatchObject({ code: 'AUTHENTICATION_ERROR' });

        expect(fetchSpy).toHaveBeenCalledTimes(1);
        const [url, init] = fetchSpy.mock.calls[0]!;
        expect(url).toBe(`${config.OC_BASE_URL}/api/oauth/token`);

        const body = JSON.parse(init!.body as string);
        expect(body.redirect_uri).toBe(config.OC_REDIRECT_URI);
        expect(body.client_id).toBe(config.Client_ID);
    });

    it('is ignored even if a caller sends one anyway', async () => {
        // Extra fields on the request body are simply not part of the typed
        // DTO and never reach this method — but assert it directly, since
        // "the field is unused" is exactly the kind of thing a later edit
        // could quietly break by re-reading req.body instead of the DTO.
        await expect(authService().ocLogin(
            { code: 'irrelevant', redirectUri: 'https://attacker.example.com/steal' } as any,
        )).rejects.toMatchObject({ code: 'AUTHENTICATION_ERROR' });

        const [, init] = fetchSpy.mock.calls[0]!;
        const body = JSON.parse(init!.body as string);
        expect(body.redirect_uri).toBe(config.OC_REDIRECT_URI);
        expect(body.redirect_uri).not.toContain('attacker.example.com');
    });
});

describe('ocLogin — a hung OC does not hang this request', () => {
    beforeEach(resetDatabase);

    it('aborts the token exchange rather than waiting forever', async () => {
        const fetchSpy = vi.fn((_url: string, init?: RequestInit) => {
            // Never resolves on its own — only the AbortSignal ends it.
            return new Promise((_resolve, reject) => {
                init?.signal?.addEventListener('abort', () => reject(new Error('aborted')));
            });
        });
        vi.stubGlobal('fetch', fetchSpy);

        try {
            await expect(authService().ocLogin({ code: 'irrelevant' } as any))
                .rejects.toMatchObject({ code: 'AUTHENTICATION_ERROR' });
            expect(fetchSpy.mock.calls[0]![1]).toHaveProperty('signal');
        } finally {
            vi.unstubAllGlobals();
        }
    }, 15_000);
});

describe('ocLogin — refuses to run unconfigured', () => {
    beforeEach(resetDatabase);

    it('reports a clear, operational error when the client credentials are unset', async () => {
        const originalId = config.Client_ID;
        const originalSecret = config.Client_Secret;
        // The parsed config object carries no runtime immutability of its own
        // (TypeScript's readonly is erased); saved and restored so this does
        // not leak into any other test in the process.
        (config as { Client_ID: string }).Client_ID = '';
        (config as { Client_Secret: string }).Client_Secret = '';

        try {
            await expect(authService().ocLogin({ code: 'irrelevant' } as any))
                .rejects.toMatchObject({ code: 'OC_AUTH_NOT_CONFIGURED' });
        } finally {
            (config as { Client_ID: string }).Client_ID = originalId;
            (config as { Client_Secret: string }).Client_Secret = originalSecret;
        }
    });
});

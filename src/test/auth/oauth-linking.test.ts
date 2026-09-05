/**
 * `AuthService#resolveOAuthUser` — shared account-resolution logic behind
 * both `googleLogin` and `ocLogin`.
 *
 * Pins down the bug this replaced: `User.provider`/`providerId` used to be a
 * single mutable slot, so linking a second OAuth provider to an existing
 * account overwrote the first — a user who linked Google, then OC, could no
 * longer sign in with Google, because the lookup by `(GOOGLE, googleSub)` no
 * longer matched anything. `LinkedIdentity` gives every provider its own row,
 * so both stay usable simultaneously.
 *
 * Called directly rather than through `ocLogin`/`googleLogin`, since those
 * also do real network/SDK calls this suite has no reason to mock twice —
 * the account-resolution logic is identical either way (see auth.service.ts).
 */
import { randomUUID } from 'node:crypto';
import type { Prisma } from '@prisma/client';
import { beforeEach, describe, expect, it } from 'vitest';
import { resetDatabase, testPrisma } from '../setup';
import { resolveService } from '../container';
import { createUser } from '../factories';
import { AuthService } from '../../modules/auth/auth.service';
import { AuditAction } from '../../core/types';

const authService = () => resolveService(AuthService) as any;

/** Typed pass-through so `testPrisma.$transaction` can still infer `tx`. */
function resolveOAuthUser(
    tx: Prisma.TransactionClient,
    args: unknown,
): Promise<{ user: { id: string; email: string }; isNewUser: boolean }> {
    return authService().resolveOAuthUser(tx, args);
}

function linkArgs(provider: 'GOOGLE' | 'OC', providerId: string, email: string) {
    return {
        provider,
        providerId,
        email,
        firstName: 'Test',
        lastName: 'User',
        linkedAction: provider === 'GOOGLE' ? AuditAction.GOOGLE_ACCOUNT_LINKED : AuditAction.OC_ACCOUNT_LINKED,
        createdAction: provider === 'GOOGLE' ? AuditAction.GOOGLE_ACCOUNT_CREATED : AuditAction.OC_ACCOUNT_CREATED,
    };
}

describe('resolveOAuthUser — linking multiple providers to one account', () => {
    beforeEach(resetDatabase);

    it('links a second provider without disturbing the first, or the original local account', async () => {
        const localUser = await createUser({ email: `multi-${randomUUID()}@test.local` });

        const { user: afterGoogle, isNewUser: googleIsNew } = await testPrisma.$transaction((tx: Prisma.TransactionClient) =>
            resolveOAuthUser(tx, linkArgs('GOOGLE', `google-${randomUUID()}`, localUser.email)),
        );
        expect(afterGoogle.id).toBe(localUser.id);
        expect(googleIsNew).toBe(false);

        const ocProviderId = `oc-${randomUUID()}`;
        const { user: afterOc, isNewUser: ocIsNew } = await testPrisma.$transaction((tx: Prisma.TransactionClient) =>
            resolveOAuthUser(tx, linkArgs('OC', ocProviderId, localUser.email)),
        );
        expect(afterOc.id).toBe(localUser.id);
        expect(ocIsNew).toBe(false);

        // The original account's own provider/providerId (LOCAL) must be untouched.
        const reloaded = await testPrisma.user.findUniqueOrThrow({ where: { id: localUser.id } });
        expect(reloaded.provider).toBe('LOCAL');
        expect(reloaded.passwordHash).toBe(localUser.passwordHash);

        const identities: { provider: string; providerId: string }[] =
            await testPrisma.linkedIdentity.findMany({ where: { userId: localUser.id } });
        expect(identities.map((i) => i.provider).sort()).toEqual(['GOOGLE', 'OC']);

        // The scenario the old single-slot design broke: linking OC after
        // Google must not make a later Google sign-in fail or create a
        // duplicate identity row.
        const { user: googleAgain, isNewUser: googleAgainIsNew } = await testPrisma.$transaction((tx: Prisma.TransactionClient) =>
            resolveOAuthUser(tx, linkArgs('GOOGLE', identities.find((i) => i.provider === 'GOOGLE')!.providerId, localUser.email)),
        );
        expect(googleAgain.id).toBe(localUser.id);
        expect(googleAgainIsNew).toBe(false);

        const googleIdentityCount = await testPrisma.linkedIdentity.count({
            where: { userId: localUser.id, provider: 'GOOGLE' },
        });
        expect(googleIdentityCount).toBe(1);
    });

    it('creates a new user, workspace, and identity row when no account matches', async () => {
        const email = `brand-new-${randomUUID()}@test.local`;

        const { user, isNewUser } = await testPrisma.$transaction((tx: Prisma.TransactionClient) =>
            resolveOAuthUser(tx, linkArgs('OC', `oc-${randomUUID()}`, email)),
        );
        expect(isNewUser).toBe(true);
        expect(user.email).toBe(email);

        const workspace = await testPrisma.workspace.findFirst({ where: { ownerId: user.id } });
        expect(workspace).toBeTruthy();
        expect(workspace?.type).toBe('PERSONAL');

        const identity = await testPrisma.linkedIdentity.findFirst({ where: { userId: user.id } });
        expect(identity?.provider).toBe('OC');
    });

    it('rejects linking to an existing but unverified account', async () => {
        const unverified = await testPrisma.user.create({
            data: {
                email: `unverified-${randomUUID()}@test.local`,
                passwordHash: 'hashed-not-used-in-tests',
                firstName: 'Test',
                lastName: 'User',
                emailVerified: false,
            },
        });

        await expect(
            testPrisma.$transaction((tx: Prisma.TransactionClient) => resolveOAuthUser(tx, linkArgs('OC', `oc-${randomUUID()}`, unverified.email))),
        ).rejects.toMatchObject({ code: 'EMAIL_NOT_VERIFIED' });
    });
});

describe('setupPassword — accounts that reached the app via OAuth only', () => {
    beforeEach(resetDatabase);

    it('sets a password for an account that has none yet', async () => {
        const oauthOnlyUser = await testPrisma.user.create({
            data: {
                email: `oauth-only-${randomUUID()}@test.local`,
                firstName: 'O',
                lastName: 'C',
                emailVerified: true,
                provider: 'OC',
                providerId: `oc-${randomUUID()}`,
            },
        });

        await authService().setupPassword(oauthOnlyUser.id, { newPassword: 'Str0ng!Passw0rd' });

        const reloaded = await testPrisma.user.findUniqueOrThrow({ where: { id: oauthOnlyUser.id } });
        expect(reloaded.passwordHash).toBeTruthy();
    });

    it('refuses to overwrite a password that already exists', async () => {
        const localUser = await createUser();

        await expect(authService().setupPassword(localUser.id, { newPassword: 'Str0ng!Passw0rd' }))
            .rejects.toMatchObject({ code: 'PASSWORD_ALREADY_SET' });

        const reloaded = await testPrisma.user.findUniqueOrThrow({ where: { id: localUser.id } });
        expect(reloaded.passwordHash).toBe(localUser.passwordHash);
    });
});

/**
 * The app-store review account: created once, left alone when healthy,
 * repaired when it drifts, and never duplicated by replicas booting together.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { WorkspaceType } from '@prisma/client';
import { config } from '../../config';
import { resetDatabase, testPrisma } from '../../test/setup';
import { resolveService } from '../../test/container';
import { AuthService } from '../auth/auth.service';
import { ReviewAccountService } from './review-account.service';

const creds = { email: 'user@playstore.com', password: 'secret2026' };
const review = () => resolveService(ReviewAccountService);
const signIn = () => resolveService(AuthService).login({ email: creds.email, password: creds.password } as never);

const accounts = () => testPrisma.user.findMany({ where: { email: creds.email } });
const personalWorkspaces = (ownerId: string) =>
    testPrisma.workspace.findMany({ where: { ownerId, type: WorkspaceType.PERSONAL, isActive: true } });

describe('review account', () => {
    const superAdmins = config.SUPER_ADMIN_EMAILS;
    beforeEach(async () => { await resetDatabase(); });
    afterEach(() => { (config as { SUPER_ADMIN_EMAILS: string }).SUPER_ADMIN_EMAILS = superAdmins; });

    it('creates a verified, ordinary account with a ready personal workspace, which can sign in', async () => {
        expect(await review().ensure(creds)).toMatchObject({ status: 'created', email: creds.email });

        const [user] = await accounts();
        expect(user).toMatchObject({ emailVerified: true, isActive: true, isSuperAdmin: false, provider: 'LOCAL' });
        const [workspace] = await personalWorkspaces(user.id);
        expect(workspace.defaultCurrency).toBe('UGX');
        expect(await testPrisma.cashbook.count({ where: { workspaceId: workspace.id } })).toBeGreaterThan(0);

        const session = await signIn();
        expect(session.accessToken).toBeTruthy();
    });

    it('leaves a healthy account alone on the next boot', async () => {
        await review().ensure(creds);
        const before = (await accounts())[0];
        const audits = await testPrisma.auditLog.count();

        expect(await review().ensure(creds)).toMatchObject({ status: 'unchanged' });
        const after = (await accounts())[0];
        expect(after.updatedAt).toEqual(before.updatedAt);
        expect(await testPrisma.auditLog.count()).toBe(audits);
    });

    it('creates exactly one account when several replicas boot at once', async () => {
        const results = await Promise.all(Array.from({ length: 5 }, () => review().ensure(creds)));

        expect(results.filter((r) => r.status === 'created')).toHaveLength(1);
        expect(results.filter((r) => r.status === 'unchanged')).toHaveLength(4);
        const users = await accounts();
        expect(users).toHaveLength(1);
        expect(await personalWorkspaces(users[0].id)).toHaveLength(1);
    });

    it('repairs a changed password, lost verification and deactivation, and ends old sessions', async () => {
        await review().ensure(creds);
        await signIn();
        const [user] = await accounts();
        await testPrisma.user.update({
            where: { id: user.id },
            data: { passwordHash: 'not-a-real-hash', emailVerified: false, isActive: false },
        });

        const result = await review().ensure(creds);
        expect(result.status).toBe('repaired');
        expect(result.repaired).toEqual(expect.arrayContaining(['password', 'unverified', 'inactive']));
        expect(await testPrisma.refreshToken.count({ where: { userId: user.id, isRevoked: false } })).toBe(0);
        expect((await signIn()).accessToken).toBeTruthy();
        expect(await accounts()).toHaveLength(1);
    });

    it('gives it a personal workspace again if it lost its own', async () => {
        await review().ensure(creds);
        const [user] = await accounts();
        await testPrisma.workspace.updateMany({ where: { ownerId: user.id }, data: { isActive: false } });

        expect(await review().ensure(creds)).toMatchObject({ status: 'repaired', repaired: ['workspace'] });
        expect(await personalWorkspaces(user.id)).toHaveLength(1);
    });

    it('starts afresh after the account was deleted', async () => {
        await review().ensure(creds);
        const [old] = await accounts();
        // What account deletion leaves: an anonymised tombstone with no email.
        await testPrisma.user.update({
            where: { id: old.id },
            data: { email: `deleted-${old.id}@deleted.invalid`, deletedAt: new Date(), isActive: false },
        });

        expect(await review().ensure(creds)).toMatchObject({ status: 'created' });
        const [fresh] = await accounts();
        expect(fresh.id).not.toBe(old.id);
    });

    it('is off when no email is configured, and refuses to seed a superadmin', async () => {
        expect(await review().ensure({ email: '', password: 'x' })).toEqual({ status: 'disabled' });

        (config as { SUPER_ADMIN_EMAILS: string }).SUPER_ADMIN_EMAILS = creds.email;
        expect(await review().ensure(creds)).toMatchObject({ status: 'refused' });
        expect(await accounts()).toHaveLength(0);
    });
});

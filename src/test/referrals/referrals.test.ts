/**
 * Referrals: appointing agents, crediting signups, and who may see the numbers.
 *
 * The rules worth pinning down are the ones that decide whether an agent gets
 * paid for work they did not do, or goes unpaid for work they did:
 *
 *   - attribution is first-touch and written once;
 *   - a bad code never costs someone their signup;
 *   - only a brand-new account can be referred;
 *   - the figures are visible in the agent's own personal workspace and
 *     nowhere else.
 */
import { randomUUID } from 'node:crypto';
import type { Prisma } from '@prisma/client';
import { beforeEach, describe, expect, it } from 'vitest';
import { resetDatabase, testPrisma } from '../setup';
import { resolveService } from '../container';
import { createUser, createWorkspace } from '../factories';
import { PlatformService } from '../../modules/platform/platform.service';
import { ReferralsService } from '../../modules/referrals/referrals.service';
import { attributeReferral, markReferralVerified } from '../../modules/referrals/referrals.helpers';
import { AuthService } from '../../modules/auth/auth.service';
import { AuditAction } from '../../core/types';

const platform = () => resolveService(PlatformService);
const referrals = () => resolveService(ReferralsService);

async function appointAgent(adminId: string) {
    const agentUser = await createUser({ email: `agent-${randomUUID()}@test.local` });
    const agent = await platform().setReferralAgent({
        targetUserId: agentUser.id,
        actorId: adminId,
        isActive: true,
    });
    return { agentUser, agent };
}

/** A personal workspace, which is the only place an agent sees their figures. */
async function personalWorkspace(ownerId: string) {
    const ws = await createWorkspace(ownerId, { name: 'Personal' });
    await testPrisma.workspace.update({
        where: { id: ws.id },
        data: { type: 'PERSONAL' },
    });
    return ws;
}

describe('appointing referral agents', () => {
    beforeEach(resetDatabase);

    it('mints a readable code and keeps it across a revoke and reappointment', async () => {
        const admin = await createUser({ email: `admin-${randomUUID()}@test.local` });
        const { agentUser, agent } = await appointAgent(admin.id);

        // No characters that get misread when written down or read aloud.
        expect(agent.code).toMatch(/^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{8}$/);
        expect(agent.isActive).toBe(true);

        const revoked = await platform().setReferralAgent({
            targetUserId: agentUser.id, actorId: admin.id, isActive: false,
        });
        expect(revoked.isActive).toBe(false);
        expect(revoked.revokedAt).not.toBeNull();

        const reappointed = await platform().setReferralAgent({
            targetUserId: agentUser.id, actorId: admin.id, isActive: true,
        });
        // The same code: posters and links already carrying it must keep working.
        expect(reappointed.code).toBe(agent.code);
        expect(reappointed.revokedAt).toBeNull();
    });

    it('refuses to appoint a deactivated account', async () => {
        const admin = await createUser({ email: `admin2-${randomUUID()}@test.local` });
        const target = await createUser({ email: `off-${randomUUID()}@test.local` });
        await testPrisma.user.update({ where: { id: target.id }, data: { isActive: false } });

        await expect(
            platform().setReferralAgent({ targetUserId: target.id, actorId: admin.id, isActive: true }),
        ).rejects.toMatchObject({ code: 'USER_INACTIVE' });
    });
});

describe('crediting a signup', () => {
    beforeEach(resetDatabase);

    it('credits the agent, and records how the code arrived', async () => {
        const admin = await createUser({ email: `a1-${randomUUID()}@test.local` });
        const { agent } = await appointAgent(admin.id);
        const newcomer = await createUser({ email: `new-${randomUUID()}@test.local` });

        await testPrisma.$transaction((tx) =>
            attributeReferral(tx, {
                rawCode: agent.code,
                userId: newcomer.id,
                signupMethod: 'GOOGLE',
                source: 'LINK',
                emailVerified: false,
            }),
        );

        const row = await testPrisma.referral.findUniqueOrThrow({
            where: { referredUserId: newcomer.id },
        });
        expect(row.agentId).toBe(agent.id);
        expect(row.source).toBe('LINK');
        expect(row.signupMethod).toBe('GOOGLE');
        expect(row.status).toBe('SIGNED_UP');
    });

    it('accepts the code however it was typed', async () => {
        const admin = await createUser({ email: `a2-${randomUUID()}@test.local` });
        const { agent } = await appointAgent(admin.id);
        const newcomer = await createUser({ email: `new2-${randomUUID()}@test.local` });

        await testPrisma.$transaction((tx) =>
            attributeReferral(tx, {
                rawCode: `  ${agent.code.toLowerCase()} `,
                userId: newcomer.id,
                signupMethod: 'LOCAL',
                source: 'CODE',
                emailVerified: false,
            }),
        );

        expect(
            await testPrisma.referral.count({ where: { referredUserId: newcomer.id } }),
        ).toBe(1);
    });

    it('never fails a signup over a bad, revoked or self-referring code', async () => {
        const admin = await createUser({ email: `a3-${randomUUID()}@test.local` });
        const { agentUser, agent } = await appointAgent(admin.id);
        const newcomer = await createUser({ email: `new3-${randomUUID()}@test.local` });

        // Unknown code.
        await expect(testPrisma.$transaction((tx) =>
            attributeReferral(tx, {
                rawCode: 'NOSUCH99', userId: newcomer.id, signupMethod: 'LOCAL', source: 'CODE', emailVerified: false,
            }),
        )).resolves.toBeUndefined();

        // Their own code.
        await expect(testPrisma.$transaction((tx) =>
            attributeReferral(tx, {
                rawCode: agent.code, userId: agentUser.id, signupMethod: 'LOCAL', source: 'CODE', emailVerified: false,
            }),
        )).resolves.toBeUndefined();

        // Revoked agent.
        await platform().setReferralAgent({
            targetUserId: agentUser.id, actorId: admin.id, isActive: false,
        });
        await expect(testPrisma.$transaction((tx) =>
            attributeReferral(tx, {
                rawCode: agent.code, userId: newcomer.id, signupMethod: 'LOCAL', source: 'CODE', emailVerified: false,
            }),
        )).resolves.toBeUndefined();

        // None of the three wrote anything.
        expect(await testPrisma.referral.count()).toBe(0);
    });

    it('keeps the first attribution when a second one is attempted', async () => {
        const admin = await createUser({ email: `a4-${randomUUID()}@test.local` });
        const first = await appointAgent(admin.id);
        const second = await appointAgent(admin.id);
        const newcomer = await createUser({ email: `new4-${randomUUID()}@test.local` });

        await testPrisma.$transaction((tx) =>
            attributeReferral(tx, {
                rawCode: first.agent.code, userId: newcomer.id, signupMethod: 'LOCAL', source: 'CODE', emailVerified: false,
            }),
        );
        await testPrisma.$transaction((tx) =>
            attributeReferral(tx, {
                rawCode: second.agent.code, userId: newcomer.id, signupMethod: 'LOCAL', source: 'CODE', emailVerified: false,
            }),
        );

        const rows = await testPrisma.referral.findMany({ where: { referredUserId: newcomer.id } });
        expect(rows).toHaveLength(1);
        expect(rows[0]!.agentId).toBe(first.agent.id);
    });

    it('promotes to VERIFIED once the address is confirmed', async () => {
        const admin = await createUser({ email: `a5-${randomUUID()}@test.local` });
        const { agent } = await appointAgent(admin.id);
        const newcomer = await createUser({ email: `new5-${randomUUID()}@test.local` });

        await testPrisma.$transaction((tx) =>
            attributeReferral(tx, {
                rawCode: agent.code, userId: newcomer.id, signupMethod: 'LOCAL', source: 'CODE', emailVerified: false,
            }),
        );
        await markReferralVerified(testPrisma, newcomer.id);

        const row = await testPrisma.referral.findUniqueOrThrow({
            where: { referredUserId: newcomer.id },
        });
        expect(row.status).toBe('VERIFIED');
        expect(row.verifiedAt).not.toBeNull();
    });
});

describe('who can see the figures', () => {
    beforeEach(resetDatabase);

    it('shows an agent their own totals in their personal workspace', async () => {
        const admin = await createUser({ email: `s1-${randomUUID()}@test.local` });
        const { agentUser, agent } = await appointAgent(admin.id);
        const ws = await personalWorkspace(agentUser.id);

        const newcomer = await createUser({ email: `s2-${randomUUID()}@test.local` });
        await testPrisma.$transaction((tx) =>
            attributeReferral(tx, {
                rawCode: agent.code, userId: newcomer.id, signupMethod: 'LOCAL', source: 'LINK',
                emailVerified: false,
            }),
        );

        const overview = await referrals().getAgentOverview(ws.id, agentUser.id);
        expect(overview.code).toBe(agent.code);
        expect(overview.shareLink).toContain(`ref=${agent.code}`);
        expect(overview.totals.all).toBe(1);
        expect(overview.totals.verified).toBe(0);
        // A first name is enough to recognise a referral; an email would make
        // this a contactable list of other people's accounts.
        expect(overview.referrals[0]!.referredUser).not.toHaveProperty('email');
    });

    it('hides it from a business workspace, from non-agents, and from other people', async () => {
        const admin = await createUser({ email: `s3-${randomUUID()}@test.local` });
        const { agentUser } = await appointAgent(admin.id);
        const outsider = await createUser({ email: `s4-${randomUUID()}@test.local` });

        // Their own BUSINESS workspace: right person, wrong place.
        const business = await createWorkspace(agentUser.id, { name: 'Their Co' });
        await expect(
            referrals().getAgentOverview(business.id, agentUser.id),
        ).rejects.toMatchObject({ statusCode: 404 });

        // Someone else's personal workspace.
        const theirs = await personalWorkspace(agentUser.id);
        await expect(
            referrals().getAgentOverview(theirs.id, outsider.id),
        ).rejects.toMatchObject({ statusCode: 404 });

        // A personal workspace whose owner is not an agent at all.
        const plainUser = await createUser({ email: `s5-${randomUUID()}@test.local` });
        const plainWs = await personalWorkspace(plainUser.id);
        await expect(
            referrals().getAgentOverview(plainWs.id, plainUser.id),
        ).rejects.toMatchObject({ statusCode: 404 });
    });

    it('closes the section as soon as the agent is revoked', async () => {
        const admin = await createUser({ email: `s6-${randomUUID()}@test.local` });
        const { agentUser } = await appointAgent(admin.id);
        const ws = await personalWorkspace(agentUser.id);

        await expect(referrals().getAgentOverview(ws.id, agentUser.id)).resolves.toBeTruthy();

        await platform().setReferralAgent({
            targetUserId: agentUser.id, actorId: admin.id, isActive: false,
        });

        await expect(
            referrals().getAgentOverview(ws.id, agentUser.id),
        ).rejects.toMatchObject({ statusCode: 404 });
    });
});

describe('who may be an agent', () => {
    beforeEach(resetDatabase);

    it('refuses to appoint a superadmin', async () => {
        const admin = await createUser({ email: `sa1-${randomUUID()}@test.local` });
        const other = await createUser({ email: `sa2-${randomUUID()}@test.local` });
        await testPrisma.user.update({ where: { id: other.id }, data: { isSuperAdmin: true } });

        await expect(
            platform().setReferralAgent({ targetUserId: other.id, actorId: admin.id, isActive: true }),
        ).rejects.toMatchObject({ code: 'SUPERADMIN_INELIGIBLE' });

        expect(await testPrisma.referralAgent.count()).toBe(0);
    });

    it('still allows revoking someone promoted to superadmin after appointment', async () => {
        const admin = await createUser({ email: `sa3-${randomUUID()}@test.local` });
        const { agentUser } = await appointAgent(admin.id);

        // Promoted afterwards — the ineligibility rule must not trap them.
        await testPrisma.user.update({
            where: { id: agentUser.id },
            data: { isSuperAdmin: true },
        });

        const revoked = await platform().setReferralAgent({
            targetUserId: agentUser.id, actorId: admin.id, isActive: false,
        });
        expect(revoked.isActive).toBe(false);
    });
});

describe('referrals credit first-time accounts only', () => {
    beforeEach(resetDatabase);

    it('ignores a code carried by someone who already had an account', async () => {
        const admin = await createUser({ email: `ex1-${randomUUID()}@test.local` });
        const { agent } = await appointAgent(admin.id);

        // Already a user before the code ever appeared.
        const existing = await createUser({ email: `ex2-${randomUUID()}@test.local` });
        await testPrisma.linkedIdentity.create({
            data: {
                userId: existing.id,
                provider: 'GOOGLE',
                providerId: `g-${randomUUID()}`,
                email: existing.email,
            },
        });

        const auth = resolveService(AuthService) as any;

        // Signing in again — Case A, an identity that already exists. The
        // resolver is the only place attribution happens, and it must not fire
        // for anything but a brand-new account.
        const identity = await testPrisma.linkedIdentity.findFirstOrThrow({
            where: { userId: existing.id },
        });
        const { isNewUser } = await (testPrisma.$transaction((tx: Prisma.TransactionClient) =>
            auth.resolveOAuthUser(tx, {
                provider: 'GOOGLE',
                providerId: identity.providerId,
                email: existing.email,
                firstName: 'Test',
                lastName: 'User',
                linkedAction: AuditAction.GOOGLE_ACCOUNT_LINKED,
                createdAction: AuditAction.GOOGLE_ACCOUNT_CREATED,
                referralCode: agent.code,
                referralSource: 'LINK',
            }),
        ) as Promise<{ isNewUser: boolean }>);

        expect(isNewUser).toBe(false);
        expect(await testPrisma.referral.count()).toBe(0);
    });

    it('credits a brand-new account arriving through the same code', async () => {
        const admin = await createUser({ email: `ex3-${randomUUID()}@test.local` });
        const { agent } = await appointAgent(admin.id);
        const auth = resolveService(AuthService) as any;

        const email = `fresh-${randomUUID()}@test.local`;
        const { user, isNewUser } = await (testPrisma.$transaction((tx: Prisma.TransactionClient) =>
            auth.resolveOAuthUser(tx, {
                provider: 'GOOGLE',
                providerId: `g-${randomUUID()}`,
                email,
                firstName: 'Fresh',
                lastName: 'Arrival',
                linkedAction: AuditAction.GOOGLE_ACCOUNT_LINKED,
                createdAction: AuditAction.GOOGLE_ACCOUNT_CREATED,
                referralCode: agent.code,
                referralSource: 'LINK',
            }),
        ) as Promise<{ user: { id: string }; isNewUser: boolean }>);

        expect(isNewUser).toBe(true);
        const row = await testPrisma.referral.findUniqueOrThrow({
            where: { referredUserId: user.id },
        });
        expect(row.agentId).toBe(agent.id);
    });
});

describe('verification keeps step with how the account was created', () => {
    beforeEach(resetDatabase);

    /*
     * The bug this pins down: a social signup creates the account already
     * verified and never passes through the OTP step, so a referral recorded
     * as SIGNED_UP had nothing anywhere that could ever promote it. It showed
     * as "pending" forever, with no approval mechanism — because none was ever
     * meant to exist.
     */
    it('records an OC signup as verified straight away', async () => {
        const admin = await createUser({ email: `v1-${randomUUID()}@test.local` });
        const { agent } = await appointAgent(admin.id);
        const auth = resolveService(AuthService) as any;

        const { user } = await (testPrisma.$transaction((tx: Prisma.TransactionClient) =>
            auth.resolveOAuthUser(tx, {
                provider: 'OC',
                providerId: `oc-${randomUUID()}`,
                email: `oc-signup-${randomUUID()}@test.local`,
                firstName: 'Oc',
                lastName: 'Newcomer',
                linkedAction: AuditAction.OC_ACCOUNT_LINKED,
                createdAction: AuditAction.OC_ACCOUNT_CREATED,
                referralCode: agent.code,
                referralSource: 'LINK',
            }),
        ) as Promise<{ user: { id: string; emailVerified: boolean } }>);

        // The account itself is verified — the provider proved the address.
        expect(user.emailVerified).toBe(true);

        const row = await testPrisma.referral.findUniqueOrThrow({
            where: { referredUserId: user.id },
        });
        expect(row.signupMethod).toBe('OC');
        expect(row.status).toBe('VERIFIED');
        expect(row.verifiedAt).not.toBeNull();
    });

    it('does the same for Google', async () => {
        const admin = await createUser({ email: `v2-${randomUUID()}@test.local` });
        const { agent } = await appointAgent(admin.id);
        const auth = resolveService(AuthService) as any;

        const { user } = await (testPrisma.$transaction((tx: Prisma.TransactionClient) =>
            auth.resolveOAuthUser(tx, {
                provider: 'GOOGLE',
                providerId: `g-${randomUUID()}`,
                email: `g-signup-${randomUUID()}@test.local`,
                firstName: 'Google',
                lastName: 'Newcomer',
                linkedAction: AuditAction.GOOGLE_ACCOUNT_LINKED,
                createdAction: AuditAction.GOOGLE_ACCOUNT_CREATED,
                referralCode: agent.code,
                referralSource: 'LINK',
            }),
        ) as Promise<{ user: { id: string } }>);

        const row = await testPrisma.referral.findUniqueOrThrow({
            where: { referredUserId: user.id },
        });
        expect(row.status).toBe('VERIFIED');
    });

    it('leaves an email signup unverified until the OTP is answered', async () => {
        const admin = await createUser({ email: `v3-${randomUUID()}@test.local` });
        const { agent } = await appointAgent(admin.id);
        const newcomer = await createUser({ email: `v4-${randomUUID()}@test.local` });

        await testPrisma.$transaction((tx) =>
            attributeReferral(tx, {
                rawCode: agent.code,
                userId: newcomer.id,
                signupMethod: 'LOCAL',
                source: 'CODE',
                emailVerified: false,
            }),
        );

        const before = await testPrisma.referral.findUniqueOrThrow({
            where: { referredUserId: newcomer.id },
        });
        expect(before.status).toBe('SIGNED_UP');
        expect(before.verifiedAt).toBeNull();

        // Answering the OTP is what promotes it — the path that always worked.
        await markReferralVerified(testPrisma, newcomer.id);

        const after = await testPrisma.referral.findUniqueOrThrow({
            where: { referredUserId: newcomer.id },
        });
        expect(after.status).toBe('VERIFIED');
    });

    it('counts an OC referral in the agent\'s verified total, not the waiting one', async () => {
        const admin = await createUser({ email: `v5-${randomUUID()}@test.local` });
        const { agentUser, agent } = await appointAgent(admin.id);
        const ws = await personalWorkspace(agentUser.id);
        const auth = resolveService(AuthService) as any;

        await testPrisma.$transaction((tx: Prisma.TransactionClient) =>
            auth.resolveOAuthUser(tx, {
                provider: 'OC',
                providerId: `oc-${randomUUID()}`,
                email: `oc-total-${randomUUID()}@test.local`,
                firstName: 'Counted',
                lastName: 'Once',
                linkedAction: AuditAction.OC_ACCOUNT_LINKED,
                createdAction: AuditAction.OC_ACCOUNT_CREATED,
                referralCode: agent.code,
                referralSource: 'LINK',
            }),
        );

        const overview = await referrals().getAgentOverview(ws.id, agentUser.id);
        expect(overview.totals.all).toBe(1);
        expect(overview.totals.verified).toBe(1);
        expect(overview.totals.signedUp).toBe(0);
    });
});

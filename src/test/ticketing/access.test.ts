/**
 * Who can reach the ticket desk at all.
 *
 * Two gates, and they answer different questions. The FEATURE gate asks whether
 * this organisation has ticketing at all — a superadmin decision, and one that
 * answers 404 rather than 403 so an org that was never granted it cannot
 * discover that other orgs have it. The CAPABILITY gate asks whether this person
 * may do the thing, and is the only place in the system where a staff tag grants
 * authority rather than merely describing a job.
 *
 * The escalation this is really guarding is HR: HR holds MANAGE_MEMBERS and no
 * financial permission whatsoever. If tagging somebody TICKETING rode on plain
 * member management, HR could hand out the ability to post money to the books by
 * relabelling an employee.
 */
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { resetDatabase, testPrisma } from '../setup';
import { resolveService } from '../container';
import { createUser, createWorkspace, addWorkspaceMember } from '../factories';
import { MembersService } from '../../modules/members/members.service';
import { WorkspaceRole, StaffTag, FeatureKey } from '../../core/types';
import { WorkspacePermission as P } from '../../core/types/workspace-permissions';
import {
    ticketDeskCapabilities,
    isTicketingEnabled,
} from '../../core/authz/ticketing-access';

// Imported lazily so setup.ts has redirected DATABASE_URL, and so the route
// files can resolve their controllers from a configured container.
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

describe('ticketDeskCapabilities', () => {
    it('gives a plain member nothing', () => {
        expect(ticketDeskCapabilities(WorkspaceRole.MEMBER, null).size).toBe(0);
    });

    it('gives a TICKETING-tagged member the desk, and only the desk', () => {
        const caps = ticketDeskCapabilities(WorkspaceRole.MEMBER, StaffTag.TICKETING);

        expect(caps.has(P.VIEW_TICKETING)).toBe(true);
        expect(caps.has(P.SELL_TICKETS)).toBe(true);
        expect(caps.has(P.VOID_TICKET_SALE)).toBe(true);

        // An attendant must not be able to change the prices they sell at, or
        // reconcile their own drawer, or read the takings analytics.
        expect(caps.has(P.MANAGE_TICKETING)).toBe(false);
        expect(caps.has(P.RECONCILE_TICKET_SHIFT)).toBe(false);
        expect(caps.has(P.MANAGE_MEMBERSHIPS)).toBe(false);
        expect(caps.has(P.VIEW_TICKET_ANALYTICS)).toBe(false);
    });

    it('gives every other tag nothing — they are labels, not grants', () => {
        for (const tag of [StaffTag.BAR, StaffTag.MAINTENANCE, StaffTag.SOCIAL_MEDIA,
            StaffTag.SUPERVISOR, StaffTag.SECURITY, StaffTag.KITCHEN, StaffTag.RESTAURANT]) {
            expect(ticketDeskCapabilities(WorkspaceRole.MEMBER, tag).size).toBe(0);
        }
    });

    it('gives an owner, admin and general manager the whole surface', () => {
        for (const role of [WorkspaceRole.OWNER, WorkspaceRole.ADMIN, WorkspaceRole.GENERAL_MANAGER]) {
            const caps = ticketDeskCapabilities(role, null);
            expect(caps.has(P.MANAGE_TICKETING)).toBe(true);
            expect(caps.has(P.SELL_TICKETS)).toBe(true);
            expect(caps.has(P.RECONCILE_TICKET_SHIFT)).toBe(true);
            expect(caps.has(P.MANAGE_MEMBERSHIPS)).toBe(true);
            expect(caps.has(P.VIEW_TICKET_ANALYTICS)).toBe(true);
        }
    });

    it('gives an accountant the reports and no way to sell', () => {
        const caps = ticketDeskCapabilities(WorkspaceRole.ACCOUNTANT, null);
        expect(caps.has(P.VIEW_TICKETING)).toBe(true);
        expect(caps.has(P.VIEW_TICKET_ANALYTICS)).toBe(true);
        expect(caps.has(P.SELL_TICKETS)).toBe(false);
        expect(caps.has(P.MANAGE_TICKETING)).toBe(false);
    });

    it('gives HR and project managers nothing, tagged or not', () => {
        for (const role of [WorkspaceRole.HR, WorkspaceRole.PROJECT_MANAGER]) {
            expect(ticketDeskCapabilities(role, null).size).toBe(0);
            // Tagging them is still the only way in, and that requires
            // MANAGE_TICKETING to do — see the members tests below.
            expect(ticketDeskCapabilities(role, StaffTag.TICKETING).has(P.MANAGE_TICKETING))
                .toBe(false);
        }
    });
});

describe('the feature gate', () => {
    beforeEach(resetDatabase);

    it('answers 404 for an organisation that was never granted ticketing', async () => {
        const owner = await createUser();
        const workspace = await createWorkspace(owner.id);

        expect(await isTicketingEnabled(testPrisma, workspace.id)).toBe(false);

        const response = await request(app)
            .get(`/api/v1/workspaces/${workspace.id}/ticketing/today`)
            .set('Cookie', await cookieFor(owner.id, owner.email));

        // 404 rather than 403: an org without the module should not be able to
        // tell that the module exists.
        expect(response.status).toBe(404);
    });

    it('lets the owner in once a superadmin unlocks it', async () => {
        const owner = await createUser();
        const workspace = await createWorkspace(owner.id);
        await testPrisma.workspaceFeature.create({
            data: { workspaceId: workspace.id, feature: FeatureKey.TICKETING, enabledById: owner.id },
        });

        const response = await request(app)
            .get(`/api/v1/workspaces/${workspace.id}/ticketing/access`)
            .set('Cookie', await cookieFor(owner.id, owner.email));

        expect(response.status).toBe(200);
        expect(response.body.data.capabilities).toContain(P.MANAGE_TICKETING);
    });

    it('keeps an untagged member out even when the org has ticketing', async () => {
        const owner = await createUser();
        const member = await createUser();
        const workspace = await createWorkspace(owner.id);
        await addWorkspaceMember(workspace.id, member.id, WorkspaceRole.MEMBER);
        await testPrisma.workspaceFeature.create({
            data: { workspaceId: workspace.id, feature: FeatureKey.TICKETING, enabledById: owner.id },
        });

        const response = await request(app)
            .get(`/api/v1/workspaces/${workspace.id}/ticketing/today`)
            .set('Cookie', await cookieFor(member.id, member.email));

        expect(response.status).toBe(403);
    });

    it('lets a tagged member work the desk but not change its settings', async () => {
        const owner = await createUser();
        const attendant = await createUser();
        const workspace = await createWorkspace(owner.id);
        await addWorkspaceMember(workspace.id, attendant.id, WorkspaceRole.MEMBER);
        await testPrisma.workspaceMember.updateMany({
            where: { workspaceId: workspace.id, userId: attendant.id },
            data: { staffTag: StaffTag.TICKETING },
        });
        await testPrisma.workspaceFeature.create({
            data: { workspaceId: workspace.id, feature: FeatureKey.TICKETING, enabledById: owner.id },
        });

        const cookie = await cookieFor(attendant.id, attendant.email);

        const desk = await request(app)
            .get(`/api/v1/workspaces/${workspace.id}/ticketing/today`)
            .set('Cookie', cookie);
        expect(desk.status).toBe(200);

        const settings = await request(app)
            .get(`/api/v1/workspaces/${workspace.id}/ticketing/settings`)
            .set('Cookie', cookie);
        expect(settings.status).toBe(403);

        const analytics = await request(app)
            .get(`/api/v1/workspaces/${workspace.id}/ticketing/analytics/summary`)
            .set('Cookie', cookie);
        expect(analytics.status).toBe(403);
    });

    it('records the refusal, so a pattern of them is visible', async () => {
        const owner = await createUser();
        const member = await createUser();
        const workspace = await createWorkspace(owner.id);
        await addWorkspaceMember(workspace.id, member.id, WorkspaceRole.MEMBER);
        await testPrisma.workspaceFeature.create({
            data: { workspaceId: workspace.id, feature: FeatureKey.TICKETING, enabledById: owner.id },
        });

        await request(app)
            .get(`/api/v1/workspaces/${workspace.id}/ticketing/today`)
            .set('Cookie', await cookieFor(member.id, member.email));

        const denied = await testPrisma.auditLog.findFirst({
            where: { userId: member.id, action: 'PERMISSION_DENIED' },
        });
        expect(denied).not.toBeNull();
        expect((denied!.details as any).attemptedAction).toBe(P.VIEW_TICKETING);
    });
});

describe('who may put somebody on the ticket desk', () => {
    beforeEach(resetDatabase);

    const members = () => resolveService(MembersService);

    it('lets an owner tag a member as an attendant', async () => {
        const owner = await createUser();
        const staff = await createUser();
        const workspace = await createWorkspace(owner.id);
        await addWorkspaceMember(workspace.id, staff.id, WorkspaceRole.MEMBER);

        await members().updateMemberRole(workspace.id, staff.id, owner.id, {
            staffTag: 'TICKETING',
        } as any);

        const row = await testPrisma.workspaceMember.findFirstOrThrow({
            where: { workspaceId: workspace.id, userId: staff.id },
        });
        expect(row.staffTag).toBe('TICKETING');
    });

    /*
     * The escalation this whole design exists to prevent.
     *
     * HR can manage members and holds no financial permission at all. Confirming
     * a ticket sale posts a cashbook entry and moves a wallet. If the TICKETING
     * tag rode on MANAGE_MEMBERS like every other tag, HR could grant the
     * ability to post money by relabelling somebody — a sideways route to
     * exactly what assignableRoles() blocks on the role axis.
     */
    it('refuses to let HR hand out the ticket desk', async () => {
        const owner = await createUser();
        const hr = await createUser();
        const staff = await createUser();
        const workspace = await createWorkspace(owner.id);
        await addWorkspaceMember(workspace.id, hr.id, WorkspaceRole.HR);
        await addWorkspaceMember(workspace.id, staff.id, WorkspaceRole.MEMBER);

        await expect(members().updateMemberRole(workspace.id, staff.id, hr.id, {
            staffTag: 'TICKETING',
        } as any)).rejects.toThrow(/manage ticketing/i);

        const row = await testPrisma.workspaceMember.findFirstOrThrow({
            where: { workspaceId: workspace.id, userId: staff.id },
        });
        expect(row.staffTag).toBeNull();
    });

    it('lets HR apply an ordinary label, which grants nothing', async () => {
        const owner = await createUser();
        const hr = await createUser();
        const staff = await createUser();
        const workspace = await createWorkspace(owner.id);
        await addWorkspaceMember(workspace.id, hr.id, WorkspaceRole.HR);
        await addWorkspaceMember(workspace.id, staff.id, WorkspaceRole.MEMBER);

        await members().updateMemberRole(workspace.id, staff.id, hr.id, {
            staffTag: 'BAR',
        } as any);

        const row = await testPrisma.workspaceMember.findFirstOrThrow({
            where: { workspaceId: workspace.id, userId: staff.id },
        });
        expect(row.staffTag).toBe('BAR');
    });

    it('refuses to let HR take somebody OFF the desk either', async () => {
        // Removing the tag is as much a ticketing decision as adding it: HR
        // should not be able to shut the gate mid-shift.
        const owner = await createUser();
        const hr = await createUser();
        const attendant = await createUser();
        const workspace = await createWorkspace(owner.id);
        await addWorkspaceMember(workspace.id, hr.id, WorkspaceRole.HR);
        await addWorkspaceMember(workspace.id, attendant.id, WorkspaceRole.MEMBER);
        await testPrisma.workspaceMember.updateMany({
            where: { workspaceId: workspace.id, userId: attendant.id },
            data: { staffTag: StaffTag.TICKETING },
        });

        await expect(members().updateMemberRole(workspace.id, attendant.id, hr.id, {
            staffTag: null,
        } as any)).rejects.toThrow(/manage ticketing/i);
    });

    it('lets a general manager run the desk’s staffing', async () => {
        const owner = await createUser();
        const gm = await createUser();
        const staff = await createUser();
        const workspace = await createWorkspace(owner.id);
        await addWorkspaceMember(workspace.id, gm.id, WorkspaceRole.GENERAL_MANAGER);
        await addWorkspaceMember(workspace.id, staff.id, WorkspaceRole.MEMBER);

        await members().updateMemberRole(workspace.id, staff.id, gm.id, {
            staffTag: 'TICKETING',
        } as any);

        const row = await testPrisma.workspaceMember.findFirstOrThrow({
            where: { workspaceId: workspace.id, userId: staff.id },
        });
        expect(row.staffTag).toBe('TICKETING');
    });

    it('records a tag change, so who put whom on the desk is answerable', async () => {
        const owner = await createUser();
        const staff = await createUser();
        const workspace = await createWorkspace(owner.id);
        await addWorkspaceMember(workspace.id, staff.id, WorkspaceRole.MEMBER);

        await members().updateMemberRole(workspace.id, staff.id, owner.id, {
            staffTag: 'TICKETING',
        } as any);

        const audit = await testPrisma.auditLog.findFirstOrThrow({
            where: { action: 'MEMBER_STAFF_TAG_CHANGED' },
        });
        expect((audit.details as any).newStaffTag).toBe('TICKETING');
        expect((audit.details as any).targetUserId).toBe(staff.id);
    });

    it('leaves the role alone when only the tag changes', async () => {
        const owner = await createUser();
        const accountant = await createUser();
        const workspace = await createWorkspace(owner.id);
        await addWorkspaceMember(workspace.id, accountant.id, WorkspaceRole.ACCOUNTANT);

        await members().updateMemberRole(workspace.id, accountant.id, owner.id, {
            staffTag: 'SUPERVISOR',
        } as any);

        const row = await testPrisma.workspaceMember.findFirstOrThrow({
            where: { workspaceId: workspace.id, userId: accountant.id },
        });
        expect(row.role).toBe('ACCOUNTANT');
        expect(row.staffTag).toBe('SUPERVISOR');
    });
});

describe('the access endpoint answers rather than hides', () => {
    beforeEach(resetDatabase);

    it('reports a workspace without the module as disabled, with a 200', async () => {
        const owner = await createUser();
        const workspace = await createWorkspace(owner.id);

        const response = await request(app)
            .get(`/api/v1/workspaces/${workspace.id}/ticketing/access`)
            .set('Cookie', await cookieFor(owner.id, owner.email));

        // "No" is the answer this endpoint exists to give. As a 404 it was
        // logged as a failed request in every member's browser, on every page,
        // for the ordinary case of an organisation without ticketing.
        expect(response.status).toBe(200);
        expect(response.body.data).toMatchObject({ enabled: false, capabilities: [] });
    });

    it('still refuses someone outside the workspace', async () => {
        const owner = await createUser();
        const outsider = await createUser();
        const workspace = await createWorkspace(owner.id);

        const response = await request(app)
            .get(`/api/v1/workspaces/${workspace.id}/ticketing/access`)
            .set('Cookie', await cookieFor(outsider.id, outsider.email));

        // Answering "disabled" must not become a way to probe workspaces the
        // caller has nothing to do with.
        expect(response.status).toBe(403);
    });
});

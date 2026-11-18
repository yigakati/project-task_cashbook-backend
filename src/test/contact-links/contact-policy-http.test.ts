import { beforeEach, describe, expect, it, vi } from 'vitest';
import express from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import request from 'supertest';
import { WorkspaceRole } from '@prisma/client';
import { resetDatabase, testPrisma } from '../setup';
import '../container';
import {
    addWorkspaceMember,
    createUser,
    createWorkspace,
    enableManualContacts,
} from '../factories';
import { config } from '../../config';
import contactsRouter from '../../modules/contacts/contacts.routes';
import {
    contactLinksWorkspaceRouter,
    contactLinksRouter,
} from '../../modules/contact-links/contact-links.routes';
import { errorHandler } from '../../middlewares/errorHandler';

vi.mock('../../config/email', () => ({ sendEmail: vi.fn(async () => undefined) }));
const app = express();
app.use(express.json(), cookieParser());
app.use('/contacts', contactsRouter);
app.use('/workspaces/:workspaceId/contact-links', contactLinksWorkspaceRouter);
app.use('/contact-links', contactLinksRouter);
app.use(errorHandler);
function cookie(user: { id: string; email: string }) {
    return `accessToken=${jwt.sign({ userId: user.id, email: user.email }, config.JWT_ACCESS_SECRET, { expiresIn: '5m' })}`;
}
async function fixture() {
    const owner = await createUser();
    const workspace = await createWorkspace(owner.id);
    const contact = await testPrisma.contact.create({
        data: { workspaceId: workspace.id, name: 'Existing customer', type: 'CUSTOMER' },
    });
    const profile = await testPrisma.customerProfile.create({
        data: { contactId: contact.id, taxId: 'original' },
    });
    return {
        owner,
        workspace,
        contact,
        profile,
        auth: cookie(owner),
        path: `/contacts/${workspace.id}`,
    };
}
beforeEach(resetDatabase);

describe('contact policy at every HTTP boundary', () => {
    it('rejects direct manual writes while keeping existing contacts and billing readable', async () => {
        const { path, auth, contact } = await fixture();
        const mutations = [
            request(app).post(path).send({ name: 'Bypass', type: 'CUSTOMER' }),
            request(app).patch(`${path}/${contact.id}`).send({ name: 'Bypass' }),
            request(app).patch(`${path}/${contact.id}`).send({ type: 'VENDOR' }),
            request(app).delete(`${path}/${contact.id}`),
            request(app).post(`${path}/${contact.id}/profile`).send({ taxId: 'changed' }),
            request(app).patch(`${path}/${contact.id}/profile`).send({ taxId: 'changed' }),
        ];
        for (const mutation of mutations) {
            const result = await mutation.set('Cookie', auth);
            expect(result.status).toBe(403);
            expect(result.body.code).toBe('MANUAL_CONTACTS_DISABLED');
        }
        expect((await request(app).get(path).set('Cookie', auth)).body.data).toHaveLength(1);
        const profile = await request(app).get(`${path}/${contact.id}/profile`).set('Cookie', auth);
        expect(profile.status).toBe(200);
        expect(profile.body.data.taxId).toBe('original');
        expect(await testPrisma.contact.count()).toBe(1);
    });

    it('honors switching on and back off without restarting, and normalizes manual identity', async () => {
        const { path, auth } = await fixture();
        await enableManualContacts();
        const added = await request(app)
            .post(path)
            .set('Cookie', auth)
            .send({ name: '  New customer  ', email: ' PERSON@EXAMPLE.TEST ', type: 'CUSTOMER' });
        expect(added.status).toBe(201);
        expect(added.body.data).toMatchObject({
            name: 'New customer',
            email: 'person@example.test',
        });
        const url = `${path}/${added.body.data.id}`;
        expect(
            (await request(app).post(`${url}/profile`).set('Cookie', auth).send({ taxId: 'valid' }))
                .status,
        ).toBe(201);
        expect(
            (
                await request(app)
                    .patch(`${url}/profile`)
                    .set('Cookie', auth)
                    .send({ notes: 'saved' })
            ).status,
        ).toBe(200);
        await testPrisma.platformSetting.update({
            where: { key: 'manual_contacts_enabled' },
            data: { value: false },
        });
        const rejected = await request(app)
            .patch(url)
            .set('Cookie', auth)
            .send({ name: 'Blocked' });
        expect(rejected.body.code).toBe('MANUAL_CONTACTS_DISABLED');
        expect(
            (await request(app).post(path).set('Cookie', auth).send({ name: 'Blocked' })).status,
        ).toBe(403);
    });

    it('rejects blank names, malformed email and unsupported staff classification', async () => {
        const { path, auth } = await fixture();
        await enableManualContacts();
        for (const payload of [
            { name: '   ' },
            { name: 'Valid', email: 'bad' },
            { name: 'Valid', type: 'STAFF' },
        ]) {
            expect((await request(app).post(path).set('Cookie', auth).send(payload)).status).toBe(
                400,
            );
        }
    });

    it('invites while manual entry is off and creates selectable contacts only after acceptance', async () => {
        const { owner, workspace, auth } = await fixture();
        const recipient = await createUser();
        const recipientWorkspace = await createWorkspace(recipient.id);
        for (const [ws, email] of [
            [workspace, owner.email],
            [recipientWorkspace, recipient.email],
        ] as const) {
            await testPrisma.workspaceProfile.create({
                data: { workspaceId: ws.id, displayName: ws.name, email },
            });
        }
        const path = `/workspaces/${workspace.id}/contact-links`;
        const lookup = await request(app)
            .get(`${path}/lookup`)
            .query({ email: recipient.email })
            .set('Cookie', auth);
        expect(lookup.status).toBe(200);
        expect(lookup.body.data.found).toBe(true);
        const invite = await request(app)
            .post(`${path}/requests`)
            .set('Cookie', auth)
            .send({ email: recipient.email, requestedType: 'VENDOR' });
        expect(invite.status).toBe(201);
        expect(await testPrisma.contact.count()).toBe(1);
        const duplicate = await request(app)
            .post(`${path}/requests`)
            .set('Cookie', auth)
            .send({ email: recipient.email, requestedType: 'VENDOR' });
        expect(duplicate.status).toBe(409);
        const accepted = await request(app)
            .post(`/contact-links/requests/${invite.body.data.id}/accept`)
            .set('Cookie', cookie(recipient))
            .send({ workspaceId: recipientWorkspace.id });
        expect(accepted.status).toBe(200);
        const linked = await testPrisma.contact.findFirstOrThrow({
            where: { workspaceId: workspace.id, contactLinkId: { not: null } },
        });
        const url = `/contacts/${workspace.id}/${linked.id}`;
        expect(
            (await request(app).patch(url).set('Cookie', auth).send({ type: 'CUSTOMER' })).status,
        ).toBe(200);
        expect(
            (await request(app).patch(url).set('Cookie', auth).send({ name: 'Spoofed' })).body.code,
        ).toBe('LINKED_CONTACT_READONLY');
        expect(
            (
                await request(app)
                    .patch(`${url}/profile`)
                    .set('Cookie', auth)
                    .send({ taxId: 'Spoofed' })
            ).body.code,
        ).toBe('LINKED_CONTACT_READONLY');
    });

    it('allows inviting an email with no platform account and deduplicates concurrent requests', async () => {
        const { workspace, auth } = await fixture();
        const path = `/workspaces/${workspace.id}/contact-links/requests`;
        const send = () =>
            request(app)
                .post(path)
                .set('Cookie', auth)
                .send({ email: 'future@example.test', requestedType: 'CUSTOMER' });
        const results = await Promise.all([send(), send()]);
        expect(results.map((result) => result.status).sort()).toEqual([201, 409]);
        expect(await testPrisma.contactLinkRequest.count()).toBe(1);
        expect(await testPrisma.contact.count()).toBe(1);
    });

    it('denies unauthorized management and foreign workspace/contact access', async () => {
        const { workspace, contact, path, auth } = await fixture();
        const member = await createUser();
        await addWorkspaceMember(workspace.id, member.id, WorkspaceRole.MEMBER);
        await enableManualContacts();
        expect((await request(app).get(path).set('Cookie', cookie(member))).status).toBe(200);
        expect(
            (await request(app).post(path).set('Cookie', cookie(member)).send({ name: 'Bypass' }))
                .status,
        ).toBe(403);
        expect(
            (
                await request(app)
                    .post(`/workspaces/${workspace.id}/contact-links/requests`)
                    .set('Cookie', cookie(member))
                    .send({ email: 'someone@example.test' })
            ).status,
        ).toBe(403);
        const foreign = await createWorkspace(member.id);
        expect((await request(app).get(`/contacts/${foreign.id}`).set('Cookie', auth)).status).toBe(
            403,
        );
        const mismatched = `/contacts/${foreign.id}/${contact.id}`;
        expect(
            (
                await request(app)
                    .patch(mismatched)
                    .set('Cookie', cookie(member))
                    .send({ name: 'Bypass' })
            ).status,
        ).toBe(404);
        expect(
            (
                await request(app)
                    .post(`${mismatched}/profile`)
                    .set('Cookie', cookie(member))
                    .send({})
            ).status,
        ).toBe(404);
        expect((await request(app).post(path).send({ name: 'Anonymous' })).status).toBe(401);
    });
});

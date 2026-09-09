/**
 * Manual contact entry as a platform-wide switch, and connected contacts as
 * read-only.
 *
 * Two rules meet here and are easy to confuse:
 *
 *   - The platform-wide manual-contacts switch decides whether contact data
 *     may be kept by hand at all. Off unless a superadmin turns it on, and it
 *     is on for every workspace or for none.
 *   - A connected contact's details belong to the business they describe,
 *     whatever this workspace has been granted — except its type, which is
 *     this workspace's own classification of the relationship.
 */
import { randomUUID } from 'node:crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import { resetDatabase, testPrisma } from '../setup';
import { resolveService } from '../container';
import { createUser, createWorkspace } from '../factories';
import { ContactsService } from '../../modules/contacts/contacts.service';
import { ContactLinksService } from '../../modules/contact-links/contact-links.service';

const contacts = () => resolveService(ContactsService);
const contactLinks = () => resolveService(ContactLinksService);

async function enableManualContacts() {
    await testPrisma.platformSetting.upsert({
        where: { key: 'manual_contacts_enabled' },
        update: { value: true },
        create: { key: 'manual_contacts_enabled', value: true },
    });
}

async function workspaceWithProfile(ownerId: string, displayName: string, email: string) {
    const ws = await createWorkspace(ownerId, { name: displayName });
    await testPrisma.workspaceProfile.create({
        data: { workspaceId: ws.id, displayName, email },
    });
    return ws;
}

describe('manual contacts — off unless switched on platform-wide', () => {
    beforeEach(resetDatabase);

    it('refuses to create, update or delete by hand while switched off', async () => {
        const user = await createUser({ email: `m1-${randomUUID()}@test.local` });
        const ws = await createWorkspace(user.id);

        await expect(
            contacts().createContact(ws.id, user.id, { name: 'Walk-in', type: 'CUSTOMER' } as any),
        ).rejects.toMatchObject({ code: 'MANUAL_CONTACTS_DISABLED' });

        // A row that predates the switch being turned off is still protected.
        const existing = await testPrisma.contact.create({
            data: { workspaceId: ws.id, name: 'Typed before', type: 'CUSTOMER' },
        });

        await expect(
            contacts().updateContact(existing.id, ws.id, user.id, { name: 'Renamed' } as any),
        ).rejects.toMatchObject({ code: 'MANUAL_CONTACTS_DISABLED' });

        await expect(
            contacts().deleteContact(existing.id, ws.id, user.id),
        ).rejects.toMatchObject({ code: 'MANUAL_CONTACTS_DISABLED' });
    });

    it('allows all three once a superadmin switches it on', async () => {
        const user = await createUser({ email: `m2-${randomUUID()}@test.local` });
        const ws = await createWorkspace(user.id);
        await enableManualContacts();

        const created = await contacts().createContact(
            ws.id, user.id, { name: 'Walk-in', type: 'CUSTOMER' } as any,
        );
        expect(created.name).toBe('Walk-in');

        const updated = await contacts().updateContact(
            created.id, ws.id, user.id, { name: 'Walk-in Ltd' } as any,
        );
        expect(updated.name).toBe('Walk-in Ltd');

        await expect(contacts().deleteContact(created.id, ws.id, user.id)).resolves.toBeUndefined();
    });

    it('refuses billing details by hand while switched off', async () => {
        const user = await createUser({ email: `m3-${randomUUID()}@test.local` });
        const ws = await createWorkspace(user.id);
        const contact = await testPrisma.contact.create({
            data: { workspaceId: ws.id, name: 'Someone', type: 'CUSTOMER' },
        });

        await expect(
            contacts().createCustomerProfile(contact.id, ws.id, user.id, { taxId: 'X' } as any),
        ).rejects.toMatchObject({ code: 'MANUAL_CONTACTS_DISABLED' });
    });
});

describe('connected contacts — theirs to maintain, yours to classify', () => {
    beforeEach(resetDatabase);

    async function connectedPair() {
        const me = await createUser({ email: `c1-${randomUUID()}@test.local` });
        const them = await createUser({ email: `c2-${randomUUID()}@test.local` });
        const myWs = await workspaceWithProfile(me.id, 'Mine Ltd', 'mine@test.local');
        const theirWs = await workspaceWithProfile(them.id, 'Theirs Ltd', them.email);

        // The switch is deliberately on, to prove the read-only rule is about
        // the connection and not about manual entry being off.
        await enableManualContacts();

        const request = await contactLinks().createRequest(myWs.id, me.id, {
            email: them.email,
            requestedType: 'VENDOR',
        });
        const { requesterContact } = await contactLinks().acceptRequest(request.id, them.id, {
            workspaceId: theirWs.id,
        });
        return { me, them, myWs, theirWs, contact: requesterContact };
    }

    it('refuses edits to details the other business owns', async () => {
        const { me, myWs, contact } = await connectedPair();

        await expect(
            contacts().updateContact(contact.id, myWs.id, me.id, { name: 'My own name for them' } as any),
        ).rejects.toMatchObject({ code: 'LINKED_CONTACT_READONLY' });

        await expect(
            contacts().updateContact(contact.id, myWs.id, me.id, { email: 'spoofed@test.local' } as any),
        ).rejects.toMatchObject({ code: 'LINKED_CONTACT_READONLY' });
    });

    it('still allows changing whether they are a customer or a vendor', async () => {
        const { me, myWs, contact } = await connectedPair();
        expect(contact.type).toBe('VENDOR');

        const updated = await contacts().updateContact(
            contact.id, myWs.id, me.id, { type: 'CUSTOMER' } as any,
        );
        expect(updated.type).toBe('CUSTOMER');
        // Their details are untouched by the reclassification.
        expect(updated.name).toBe('Theirs Ltd');
    });

    it('refuses billing edits and deletion, pointing at disconnect instead', async () => {
        const { me, myWs, contact } = await connectedPair();

        await expect(
            contacts().createCustomerProfile(contact.id, myWs.id, me.id, { taxId: 'MINE' } as any),
        ).rejects.toMatchObject({ code: 'LINKED_CONTACT_READONLY' });

        await expect(
            contacts().deleteContact(contact.id, myWs.id, me.id),
        ).rejects.toMatchObject({ code: 'LINKED_CONTACT_READONLY' });
    });
});

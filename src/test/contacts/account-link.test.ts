/**
 * The contact ↔ platform-account link, as the rental contract flow sees it.
 *
 * A customer created normally carries no userId — only auto-created contacts
 * (peer links, staff claims) do. But the rental contract toggle keys on
 * "does this customer have an account", and a workspace that recorded the
 * same email a user signed up with has said everything needed. These tests
 * pin the read-time resolution the list performs.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { resetDatabase, testPrisma } from '../setup';
import { createWorkspace, createUser } from '../factories';
import { resolveService } from '../container';
import { ContactsService } from '../../modules/contacts/contacts.service';

const contacts = () => resolveService(ContactsService);

describe('contact → account resolution (list)', () => {
    beforeEach(resetDatabase);

    it('a normally-created customer with a matching email resolves to the account', async () => {
        const owner = await createUser();
        const workspace = await createWorkspace(owner.id);

        // The same person, both sides of the platform.
        const user = await createUser({ email: `customer-${Date.now()}@test.local` });
        const service = contacts();

        // Created through the ORDINARY path — no userId, just an email.
        await service.createContact(workspace.id, owner.id, {
            name: 'Sarah the Customer',
            email: user.email,
            type: 'CUSTOMER',
        } as any);

        const list = await service.getContacts(workspace.id);
        expect(list).toHaveLength(1);
        // The read resolves the link: the rental contract toggle can appear.
        expect(list[0].userId).toBe(user.id);
    });

    it('contacts without a matching account stay unlinked', async () => {
        const owner = await createUser();
        const workspace = await createWorkspace(owner.id);
        const service = contacts();

        await service.createContact(workspace.id, owner.id, {
            name: 'Walk In',
            email: `nowhere-${Date.now()}@test.local`,
            type: 'CUSTOMER',
        } as any);
        await service.createContact(workspace.id, owner.id, {
            name: 'No Email At All',
            type: 'CUSTOMER',
        } as any);

        const list = await service.getContacts(workspace.id);
        expect(list).toHaveLength(2);
        for (const c of list) {
            expect(c.userId).toBeNull();
        }
    });

    it('inactive accounts do not count as linkable', async () => {
        const owner = await createUser();
        const workspace = await createWorkspace(owner.id);

        const deactivated = await createUser({ email: `gone-${Date.now()}@test.local` });
        await testPrisma.user.update({
            where: { id: deactivated.id },
            data: { isActive: false },
        });

        const service = contacts();
        await service.createContact(workspace.id, owner.id, {
            name: 'Deactivated Customer',
            email: deactivated.email,
            type: 'CUSTOMER',
        } as any);

        const list = await service.getContacts(workspace.id);
        expect(list[0].userId).toBeNull();
    });

    it('an explicit userId link is preserved untouched', async () => {
        const owner = await createUser();
        const workspace = await createWorkspace(owner.id);
        const linkedUser = await createUser({ email: `linked-${Date.now()}@test.local` });

        // Auto-created (the peer-links shape): userId set at creation.
        await testPrisma.contact.create({
            data: {
                workspaceId: workspace.id,
                userId: linkedUser.id,
                type: 'STAFF',
                name: 'Already Linked',
                email: `different-${Date.now()}@test.local`,
            },
        });

        const service = contacts();
        const list = await service.getContacts(workspace.id);
        expect(list[0].userId).toBe(linkedUser.id);
    });
});

/**
 * Connecting a contact to another workspace on the platform.
 *
 * The behaviours worth pinning down are the ones that are expensive to get
 * wrong and invisible when they are: which workspace ends up owning a request
 * when the same person could answer from several, whether accepting twice can
 * mint two connections, whether linking into a contact someone already typed
 * preserves what they typed, and whether a workspace with nothing to say about
 * itself is stopped before it shares nothing.
 */
import { randomUUID } from 'node:crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import { resetDatabase, testPrisma } from '../setup';
import { resolveService } from '../container';
import { createUser, createWorkspace } from '../factories';
import { ContactLinksService, inverseContactType } from '../../modules/contact-links/contact-links.service';
import { WorkspaceProfileService } from '../../modules/workspace-profile/workspace-profile.service';

const contactLinks = () => resolveService(ContactLinksService);
const profiles = () => resolveService(WorkspaceProfileService);

async function workspaceWithProfile(
    ownerId: string,
    profile: { displayName: string; email?: string; phone?: string; taxId?: string; city?: string },
) {
    const ws = await createWorkspace(ownerId, { name: profile.displayName });
    await testPrisma.workspaceProfile.create({
        data: {
            workspaceId: ws.id,
            displayName: profile.displayName,
            email: profile.email ?? null,
            phone: profile.phone ?? null,
            taxId: profile.taxId ?? null,
            city: profile.city ?? null,
        },
    });
    return ws;
}

/** A workspace that exists but has said nothing about itself yet. */
async function bareWorkspace(ownerId: string) {
    return createWorkspace(ownerId, { name: `Bare ${randomUUID().slice(0, 6)}` });
}

describe('contact connections — requesting and accepting', () => {
    beforeEach(resetDatabase);

    it('links both sides, inverts the role, and fills the requester\'s books', async () => {
        const buyerUser = await createUser({ email: `buyer-${randomUUID()}@test.local` });
        const sellerUser = await createUser({ email: `seller-${randomUUID()}@test.local` });

        const buyerWs = await workspaceWithProfile(buyerUser.id, {
            displayName: 'Buyer Ltd',
            email: 'ap@buyer.test',
        });
        const sellerWs = await workspaceWithProfile(sellerUser.id, {
            displayName: 'Seller Co',
            email: 'sales@seller.test',
            taxId: 'TIN-99',
            city: 'Kampala',
        });

        // The buyer records the seller as somebody they buy FROM.
        const request = await contactLinks().createRequest(buyerWs.id, buyerUser.id, {
            email: sellerUser.email,
            requestedType: 'VENDOR',
        });

        const { requesterContact, recipientContact } = await contactLinks().acceptRequest(
            request.id,
            sellerUser.id,
            { workspaceId: sellerWs.id },
        );

        // Buyer's side carries the seller's own details.
        expect(requesterContact.name).toBe('Seller Co');
        expect(requesterContact.email).toBe('sales@seller.test');
        expect(requesterContact.type).toBe('VENDOR');
        expect(requesterContact.linkedWorkspaceId).toBe(sellerWs.id);

        // Seller's side is the mirror: the buyer is their CUSTOMER, not
        // another vendor.
        expect(recipientContact.type).toBe('CUSTOMER');
        expect(recipientContact.name).toBe('Buyer Ltd');
        expect(recipientContact.linkedWorkspaceId).toBe(buyerWs.id);

        // Billing rides along on the CustomerProfile invoices already read.
        const billing = await testPrisma.customerProfile.findUnique({
            where: { contactId: requesterContact.id },
        });
        expect(billing?.taxId).toBe('TIN-99');
        expect((billing?.billingAddress as any)?.city).toBe('Kampala');
    });

    it('inverts only the roles that have an inverse', () => {
        expect(inverseContactType('CUSTOMER' as any)).toBe('VENDOR');
        expect(inverseContactType('VENDOR' as any)).toBe('CUSTOMER');
        expect(inverseContactType('PERSONAL' as any)).toBe('PERSONAL');
        expect(inverseContactType('STAFF' as any)).toBe('PERSONAL');
    });

    it('lets the accepter override the inferred role', async () => {
        const a = await createUser({ email: `a-${randomUUID()}@test.local` });
        const b = await createUser({ email: `b-${randomUUID()}@test.local` });
        const wsA = await workspaceWithProfile(a.id, { displayName: 'A Ltd', email: 'a@test.local' });
        const wsB = await workspaceWithProfile(b.id, { displayName: 'B Ltd', email: 'b@test.local' });

        const request = await contactLinks().createRequest(wsA.id, a.id, {
            email: b.email,
            requestedType: 'CUSTOMER',
        });

        const { recipientContact } = await contactLinks().acceptRequest(request.id, b.id, {
            workspaceId: wsB.id,
            type: 'PERSONAL',
        });

        expect(recipientContact.type).toBe('PERSONAL');
    });
});

describe('contact connections — the first workspace to accept owns it', () => {
    beforeEach(resetDatabase);

    it('refuses a second acceptance, even from another workspace of the same person', async () => {
        const requesterUser = await createUser({ email: `req-${randomUUID()}@test.local` });
        const accepterUser = await createUser({ email: `acc-${randomUUID()}@test.local` });

        const requesterWs = await workspaceWithProfile(requesterUser.id, {
            displayName: 'Requester Ltd', email: 'r@test.local',
        });
        // The accepter belongs to two orgs and could answer from either.
        const firstWs = await workspaceWithProfile(accepterUser.id, {
            displayName: 'Their Business', email: 'biz@test.local',
        });
        const secondWs = await workspaceWithProfile(accepterUser.id, {
            displayName: 'Their Side Project', email: 'side@test.local',
        });

        const request = await contactLinks().createRequest(requesterWs.id, requesterUser.id, {
            email: accepterUser.email,
            requestedType: 'CUSTOMER',
        });

        await contactLinks().acceptRequest(request.id, accepterUser.id, { workspaceId: firstWs.id });

        // The second workspace answering the same request — a stale tab, a
        // second device — must not mint a second connection.
        await expect(
            contactLinks().acceptRequest(request.id, accepterUser.id, { workspaceId: secondWs.id }),
        ).rejects.toMatchObject({ code: 'INVALID_STATUS' });

        const links = await testPrisma.contactLink.findMany();
        expect(links).toHaveLength(1);

        const contacts = await testPrisma.contact.findMany({
            where: { workspaceId: requesterWs.id },
        });
        expect(contacts).toHaveLength(1);
        expect(contacts[0]!.linkedWorkspaceId).toBe(firstWs.id);
    });

    it('holds under genuinely concurrent acceptances', async () => {
        const requesterUser = await createUser({ email: `req2-${randomUUID()}@test.local` });
        const accepterUser = await createUser({ email: `acc2-${randomUUID()}@test.local` });

        const requesterWs = await workspaceWithProfile(requesterUser.id, {
            displayName: 'Requester Two', email: 'r2@test.local',
        });
        const wsOne = await workspaceWithProfile(accepterUser.id, {
            displayName: 'Org One', email: 'one@test.local',
        });
        const wsTwo = await workspaceWithProfile(accepterUser.id, {
            displayName: 'Org Two', email: 'two@test.local',
        });

        const request = await contactLinks().createRequest(requesterWs.id, requesterUser.id, {
            email: accepterUser.email,
            requestedType: 'CUSTOMER',
        });

        const results = await Promise.allSettled([
            contactLinks().acceptRequest(request.id, accepterUser.id, { workspaceId: wsOne.id }),
            contactLinks().acceptRequest(request.id, accepterUser.id, { workspaceId: wsTwo.id }),
        ]);

        const fulfilled = results.filter((r) => r.status === 'fulfilled');
        expect(fulfilled).toHaveLength(1);
        expect(await testPrisma.contactLink.count()).toBe(1);
    });

    it('refuses a second pending request to the same person', async () => {
        const requesterUser = await createUser({ email: `req3-${randomUUID()}@test.local` });
        const target = await createUser({ email: `tgt-${randomUUID()}@test.local` });
        const ws = await workspaceWithProfile(requesterUser.id, {
            displayName: 'Sender', email: 's@test.local',
        });

        await contactLinks().createRequest(ws.id, requesterUser.id, { email: target.email, requestedType: 'CUSTOMER' });

        await expect(
            contactLinks().createRequest(ws.id, requesterUser.id, { email: target.email, requestedType: 'CUSTOMER' }),
        ).rejects.toMatchObject({ statusCode: 409 });
    });
});

describe('contact connections — a workspace shares what is already known about it', () => {
    beforeEach(resetDatabase);

    it('accepts straight away using the workspace name and the owner\'s account email', async () => {
        const requesterUser = await createUser({ email: `rq-${randomUUID()}@test.local` });
        const accepterUser = await createUser({ email: `ac-${randomUUID()}@test.local` });

        const requesterWs = await workspaceWithProfile(requesterUser.id, {
            displayName: 'Asking Ltd', email: 'ask@test.local',
        });
        // No profile row at all — the state every workspace predating this was
        // in, and the state a workspace created by a path that does not seed
        // one lands in.
        const unfilledWs = await bareWorkspace(accepterUser.id);

        const request = await contactLinks().createRequest(requesterWs.id, requesterUser.id, {
            email: accepterUser.email,
            requestedType: 'CUSTOMER',
        });

        // No form, no gate: the app already knew both things it needed.
        const { requesterContact } = await contactLinks().acceptRequest(
            request.id,
            accepterUser.id,
            { workspaceId: unfilledWs.id },
        );

        expect(requesterContact.name).toBe(unfilledWs.name);
        expect(requesterContact.email).toBe(accepterUser.email);

        // And the workspace now owns that address as its own, ready to be
        // changed to a real billing one whenever they have it.
        const seeded = await testPrisma.workspaceProfile.findUniqueOrThrow({
            where: { workspaceId: unfilledWs.id },
        });
        expect(seeded.email).toBe(accepterUser.email);
        expect(seeded.displayName).toBe(unfilledWs.name);
    });

    it('does not follow the owner\'s account email once seeded', async () => {
        const owner = await createUser({ email: `own-${randomUUID()}@test.local` });
        const ws = await bareWorkspace(owner.id);

        // First read seeds it from the account email.
        const seeded = await profiles().getProfile(ws.id);
        expect(seeded.email).toBe(owner.email);

        // The org then moves it to a real billing address.
        await profiles().updateProfile(ws.id, owner.id, { email: 'billing@theorg.test' });

        // Changing the account email afterwards leaves the workspace's alone.
        await testPrisma.user.update({
            where: { id: owner.id },
            data: { email: `changed-${randomUUID()}@test.local` },
        });

        const after = await profiles().getProfile(ws.id);
        expect(after.email).toBe('billing@theorg.test');
    });

    it('still refuses when even the defaults leave nothing to share', async () => {
        const requesterUser = await createUser({ email: `rq2-${randomUUID()}@test.local` });
        const accepterUser = await createUser({ email: `ac2-${randomUUID()}@test.local` });

        const requesterWs = await workspaceWithProfile(requesterUser.id, {
            displayName: 'Asking Two', email: 'ask2@test.local',
        });
        const clearedWs = await workspaceWithProfile(accepterUser.id, {
            displayName: 'Cleared Ltd',
        });
        // Someone deliberately emptied the contact fields — the backstop the
        // gate exists for, now that the common case is filled in by default.
        await testPrisma.workspaceProfile.update({
            where: { workspaceId: clearedWs.id },
            data: { email: null, phone: null },
        });

        const request = await contactLinks().createRequest(requesterWs.id, requesterUser.id, {
            email: accepterUser.email,
            requestedType: 'CUSTOMER',
        });

        await expect(
            contactLinks().acceptRequest(request.id, accepterUser.id, { workspaceId: clearedWs.id }),
        ).rejects.toMatchObject({
            code: 'WORKSPACE_PROFILE_INCOMPLETE',
            missing: ['emailOrPhone'],
        });

        // Nothing was half-created by the refused attempt.
        expect(await testPrisma.contactLink.count()).toBe(0);
        const stillPending = await testPrisma.contactLinkRequest.findUniqueOrThrow({
            where: { id: request.id },
        });
        expect(stillPending.status).toBe('PENDING');

        // Filling it in lets the same acceptance through.
        await profiles().updateProfile(clearedWs.id, accepterUser.id, {
            email: 'hello@cleared.test',
        });

        const { requesterContact } = await contactLinks().acceptRequest(
            request.id,
            accepterUser.id,
            { workspaceId: clearedWs.id },
        );
        expect(requesterContact.email).toBe('hello@cleared.test');
    });
});

describe('contact connections — existing hand-typed contacts', () => {
    beforeEach(resetDatabase);

    it('links into the existing row, keeps what was typed, and fills only the blanks', async () => {
        const meUser = await createUser({ email: `me-${randomUUID()}@test.local` });
        const themUser = await createUser({ email: `them-${randomUUID()}@test.local` });

        const myWs = await workspaceWithProfile(meUser.id, { displayName: 'Mine', email: 'me@test.local' });
        const theirWs = await workspaceWithProfile(themUser.id, {
            displayName: 'Their Official Name',
            email: themUser.email,
            phone: '+256700000000',
            taxId: 'TIN-7',
        });

        // Recorded by hand months ago, with a nickname and some history.
        const typed = await testPrisma.contact.create({
            data: {
                workspaceId: myWs.id,
                name: 'Joe from the market',
                email: themUser.email,
                type: 'VENDOR',
            },
        });

        const request = await contactLinks().createRequest(myWs.id, meUser.id, {
            email: themUser.email,
            requestedType: 'VENDOR',
        });
        expect(request.requesterContactId).toBe(typed.id);

        const { requesterContact } = await contactLinks().acceptRequest(request.id, themUser.id, {
            workspaceId: theirWs.id,
        });

        // Same row — no duplicate beside it.
        expect(requesterContact.id).toBe(typed.id);
        expect(await testPrisma.contact.count({ where: { workspaceId: myWs.id } })).toBe(1);

        // The name they chose survives; the blank phone gets filled.
        expect(requesterContact.name).toBe('Joe from the market');
        expect(requesterContact.phone).toBe('+256700000000');
    });

    it('keeps a locally corrected field corrected when the counterparty updates', async () => {
        const meUser = await createUser({ email: `me2-${randomUUID()}@test.local` });
        const themUser = await createUser({ email: `them2-${randomUUID()}@test.local` });

        const myWs = await workspaceWithProfile(meUser.id, { displayName: 'Mine 2', email: 'me2@test.local' });
        const theirWs = await workspaceWithProfile(themUser.id, {
            displayName: 'Original Name',
            email: themUser.email,
            phone: '+256700000001',
        });

        const request = await contactLinks().createRequest(myWs.id, meUser.id, {
            email: themUser.email, requestedType: 'CUSTOMER',
        });
        const { requesterContact } = await contactLinks().acceptRequest(request.id, themUser.id, {
            workspaceId: theirWs.id,
        });

        // Fresh link, blank row: we filled the name.
        expect(requesterContact.name).toBe('Original Name');

        // A person then corrects the phone locally, but leaves the name alone.
        await testPrisma.contact.update({
            where: { id: requesterContact.id },
            data: { phone: '+256799999999' },
        });

        await profiles().updateProfile(theirWs.id, themUser.id, {
            displayName: 'Renamed Ltd',
            phone: '+256700000002',
        });

        const after = await testPrisma.contact.findUniqueOrThrow({ where: { id: requesterContact.id } });
        // The name was ours to keep fresh...
        expect(after.name).toBe('Renamed Ltd');
        // ...but the hand-corrected phone is left exactly as the human set it.
        expect(after.phone).toBe('+256799999999');
    });
});

describe('contact connections — disconnecting', () => {
    beforeEach(resetDatabase);

    it('stops updates both ways but leaves the details each side already holds', async () => {
        const meUser = await createUser({ email: `d1-${randomUUID()}@test.local` });
        const themUser = await createUser({ email: `d2-${randomUUID()}@test.local` });

        const myWs = await workspaceWithProfile(meUser.id, { displayName: 'Disc A', email: 'a@d.test' });
        const theirWs = await workspaceWithProfile(themUser.id, {
            displayName: 'Disc B', email: themUser.email,
        });

        const request = await contactLinks().createRequest(myWs.id, meUser.id, {
            email: themUser.email, requestedType: 'CUSTOMER',
        });
        const { requesterContact, recipientContact } = await contactLinks().acceptRequest(
            request.id, themUser.id, { workspaceId: theirWs.id },
        );

        await contactLinks().unlinkContact(myWs.id, requesterContact.id, meUser.id);

        // Both rows survive with their data; neither is still linked.
        for (const id of [requesterContact.id, recipientContact.id]) {
            const contact = await testPrisma.contact.findUniqueOrThrow({ where: { id } });
            expect(contact.name).toBeTruthy();
            expect(contact.contactLinkId).toBeNull();
            expect(contact.linkedWorkspaceId).toBeNull();
        }

        const link = await testPrisma.contactLink.findFirstOrThrow();
        expect(link.state).toBe('REVOKED');

        // A later profile edit reaches nobody.
        await profiles().updateProfile(theirWs.id, themUser.id, { displayName: 'Changed After Revoke' });
        const stale = await testPrisma.contact.findUniqueOrThrow({ where: { id: requesterContact.id } });
        expect(stale.name).not.toBe('Changed After Revoke');
    });
});

describe('contact connections — looking someone up', () => {
    beforeEach(resetDatabase);

    it('reports a miss without erroring, so the caller can fall back to typing it in', async () => {
        const meUser = await createUser({ email: `l1-${randomUUID()}@test.local` });
        const myWs = await workspaceWithProfile(meUser.id, { displayName: 'Looker', email: 'l@test.local' });

        const result = await contactLinks().lookupRecipient(myWs.id, meUser.id, 'nobody@nowhere.test');
        expect(result.found).toBe(false);
    });

    it('surfaces an existing contact to link into, and an in-flight request', async () => {
        const meUser = await createUser({ email: `l2-${randomUUID()}@test.local` });
        const themUser = await createUser({ email: `l3-${randomUUID()}@test.local` });
        const myWs = await workspaceWithProfile(meUser.id, { displayName: 'Looker 2', email: 'l2@test.local' });

        await testPrisma.contact.create({
            data: { workspaceId: myWs.id, name: 'Typed earlier', email: themUser.email, type: 'CUSTOMER' },
        });

        const before = await contactLinks().lookupRecipient(myWs.id, meUser.id, themUser.email);
        expect(before.found).toBe(true);
        expect(before.suggestedContact?.name).toBe('Typed earlier');
        expect(before.pendingRequest).toBeNull();

        await contactLinks().createRequest(myWs.id, meUser.id, {
            email: themUser.email, requestedType: 'CUSTOMER',
        });

        const after = await contactLinks().lookupRecipient(myWs.id, meUser.id, themUser.email);
        expect(after.pendingRequest).not.toBeNull();
    });
});

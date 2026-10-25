import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'node:crypto';
import { resetDatabase, testPrisma as db } from '../setup';
import { resolveService } from '../container';
import { createAccount, createCashbook, createUser, createWorkspace, addWorkspaceMember } from '../factories';
import { provisionWorkspaceAccounting, ensureCashbookLedgerAccount, ensureWalletLedgerAccount } from '../../core/ledger/coa.seed';
import { EntriesService } from '../../modules/entries/entries.service';
import { SharedEntriesService } from '../../modules/shared-entries/shared-entries.service';
import { ContactLinksService } from '../../modules/contact-links/contact-links.service';
import { CashbookRole } from '../../core/types';
import { ObligationsService } from '../../modules/cashbook-obligations/obligations.service';
import { PeerLinksService } from '../../modules/peer-links/peer-links.service';
import { purgeWorkspace } from '../../modules/account-deletion/account-deletion.service';

const entries = () => resolveService(EntriesService);
const shares = () => resolveService(SharedEntriesService);
const date = '2026-03-10T09:00:00.000Z';
let app: import('express').Express;
beforeAll(async () => {
    await import('../../config/container');
    app = (await import('../../app')).default;
});
beforeEach(resetDatabase);

async function side(userId: string, name: string) {
    const workspace = await createWorkspace(userId, { name });
    const book = await createCashbook(workspace.id, userId);
    const account = await createAccount(workspace.id, { allowNegative: true });
    await db.$transaction(async tx => {
        await provisionWorkspaceAccounting(tx, workspace.id, 'UGX');
        await ensureCashbookLedgerAccount(tx, book);
        const full = await tx.account.findUniqueOrThrow({ where: { id: account.id }, include: { accountType: true } });
        await ensureWalletLedgerAccount(tx, full, full.accountType.classification);
    });
    return { workspace, book, account };
}

async function fixture(type: 'INCOME' | 'EXPENSE' = 'EXPENSE') {
    const sender = await createUser();
    const recipient = await createUser();
    const a = await side(sender.id, 'Sender business');
    const b = await side(recipient.id, 'Recipient business');
    const contact = await db.contact.create({ data: { workspaceId: a.workspace.id, name: 'Customer', type: 'CUSTOMER', email: recipient.email.toUpperCase() } });
    const entry = await entries().createEntry(a.book.id, sender.id, {
        type, amount: '1250.125', chargeAmount: '10', description: 'Payment for supplies',
        accountId: a.account.id, contactId: contact.id, entryDate: date,
    });
    const share = await db.sharedEntry.findFirstOrThrow({ where: { sourceEntryId: entry.id } });
    const accept = { cashbookId: b.book.id, accountId: b.account.id, expectedVersion: entry.version };
    return { sender, recipient, a, b, contact, entry, share, accept };
}

describe('shared payment entries', () => {
    it.each(['INCOME', 'EXPENSE'] as const)('reverses %s once, preserves decimal amount/date and posts through the ledger', async type => {
        const f = await fixture(type);
        expect(await db.entry.count({ where: { cashbookId: f.b.book.id } })).toBe(0);
        expect((await db.account.findUniqueOrThrow({ where: { id: f.b.account.id } })).balance.toString()).toBe('0');
        const result = await shares().accept(f.share.id, f.recipient.id, f.accept);
        const entry = await db.entry.findUniqueOrThrow({ where: { id: result.entryId! }, include: { accountTransactions: true } });
        expect(entry.type).toBe(type === 'INCOME' ? 'EXPENSE' : 'INCOME');
        expect(entry.amount.toString()).toBe('1250.125');
        expect(entry.entryDate.toISOString()).toBe(date);
        expect(entry.chargeAmount).toBeNull();
        expect(entry.contactId).toBeNull();
        expect(entry.accountTransactions[0].accountId).toBe(f.b.account.id);
        const wallet = await db.account.findUniqueOrThrow({ where: { id: f.b.account.id } });
        expect(wallet.balance.toString()).toBe(type === 'INCOME' ? '-1250.125' : '1250.125');
        const totals = await db.journalLine.aggregate({ _sum: { debit: true, credit: true } });
        expect(totals._sum.debit?.equals(totals._sum.credit!)).toBe(true);
        expect(await db.entryAudit.count({ where: { entryId: entry.id, action: 'SHARED_ENTRY_ACCEPTED' } })).toBe(1);
        expect(await db.sharedEntry.count()).toBe(1);
    });

    it('accepts into the recipient’s personal workspace or another business where they have entry access', async () => {
        const f = await fixture();
        await db.workspace.update({ where: { id: f.b.workspace.id }, data: { type: 'PERSONAL' } });
        const otherOwner = await createUser();
        const other = await side(otherOwner.id, 'Employer');
        await addWorkspaceMember(other.workspace.id, f.recipient.id, 'ACCOUNTANT');
        const choices = await shares().destinations(f.share.id, f.recipient.id);
        expect(choices.map(c => c.id)).toEqual(expect.arrayContaining([f.b.book.id, other.book.id]));
        await shares().accept(f.share.id, f.recipient.id, { ...f.accept, cashbookId: other.book.id, accountId: other.account.id });
        expect(await db.entry.count({ where: { cashbookId: other.book.id } })).toBe(1);
        const recorded = (await shares().list(f.recipient.id, { page: 1, limit: 20 })).data[0];
        expect(recorded.acceptedEntry?.workspaceName).toBe('Employer');
        await db.workspaceMember.deleteMany({ where: { workspaceId: other.workspace.id, userId: f.recipient.id } });
        expect((await shares().list(f.recipient.id, { page: 1, limit: 20 })).data[0].acceptedEntry).toBeNull();
    });

    it('does not make an offer for an unmatched, unverified, inactive, self or ambiguous contact', async () => {
        const f = await fixture();
        for (const kind of ['unmatched', 'unverified', 'inactive', 'self']) {
            await db.user.update({ where: { id: f.recipient.id }, data: { isActive: kind !== 'inactive', emailVerified: kind !== 'unverified' } });
            await db.contact.update({ where: { id: f.contact.id }, data: { email: kind === 'self' ? f.sender.email : kind === 'unmatched' ? 'unknown@test.local' : f.recipient.email } });
            const row = await entries().createEntry(f.a.book.id, f.sender.id, { type: 'INCOME', amount: '1', description: kind, entryDate: date, contactId: f.contact.id, accountId: f.a.account.id });
            expect(await db.sharedEntry.count({ where: { sourceEntryId: row.id } })).toBe(0);
        }
        await createUser({ email: f.recipient.email.toUpperCase() });
        await db.contact.update({ where: { id: f.contact.id }, data: { email: f.recipient.email } });
        const ambiguous = await entries().createEntry(f.a.book.id, f.sender.id, { type: 'INCOME', amount: '1', description: 'Ambiguous email', entryDate: date, contactId: f.contact.id, accountId: f.a.account.id });
        expect(await db.sharedEntry.count({ where: { sourceEntryId: ambiguous.id } })).toBe(0);
    });

    it('rejects contacts and classifications from another tenant before posting', async () => {
        const f = await fixture();
        const badContact = await db.contact.create({ data: { workspaceId: f.b.workspace.id, name: 'Private contact', email: f.recipient.email } });
        await expect(entries().createEntry(f.a.book.id, f.sender.id, { type: 'INCOME', amount: '1', description: 'Invalid', entryDate: date, contactId: badContact.id })).rejects.toMatchObject({ code: 'INVALID_ENTRY_REFERENCE' });
        const category = await db.category.create({ data: { workspaceId: f.a.workspace.id, name: 'Private category' } });
        await expect(shares().accept(f.share.id, f.recipient.id, { ...f.accept, categoryId: category.id })).rejects.toMatchObject({ code: 'INVALID_ENTRY_REFERENCE' });
        expect((await db.sharedEntry.findUniqueOrThrow({ where: { id: f.share.id } })).status).toBe('PENDING');
        expect(await db.entry.count({ where: { cashbookId: f.b.book.id } })).toBe(0);
    });

    it('uses the connection’s signatory even when the business email is different', async () => {
        const f = await fixture();
        await db.sharedEntry.deleteMany();
        const linkRequest = await db.contactLinkRequest.create({ data: {
            requesterUserId: f.sender.id, requesterWorkspaceId: f.a.workspace.id,
            recipientUserId: f.recipient.id, recipientEmail: f.recipient.email,
            recipientWorkspaceId: f.b.workspace.id, expiresAt: new Date('2030-01-01'), status: 'ACCEPTED',
        } });
        const [workspaceAId, workspaceBId] = [f.a.workspace.id, f.b.workspace.id].sort();
        const link = await db.contactLink.create({ data: { workspaceAId, workspaceBId, requestId: linkRequest.id } });
        await db.contact.update({ where: { id: f.contact.id }, data: { linkedWorkspaceId: f.b.workspace.id, contactLinkId: link.id, email: 'billing@company.test' } });
        await entries().updateEntry(f.entry.id, f.sender.id, { description: 'Connected payment' });
        const share = await db.sharedEntry.findFirstOrThrow();
        expect(share.recipientUserId).toBe(f.recipient.id);
        await resolveService(ContactLinksService).unlinkContact(f.a.workspace.id, f.contact.id, f.sender.id);
        expect((await db.sharedEntry.findUniqueOrThrow({ where: { id: share.id } })).status).toBe('CANCELLED');
        await expect(shares().accept(share.id, f.recipient.id, { ...f.accept, expectedVersion: share.sourceVersion })).rejects.toThrow();
        // The frozen email left on the contact must not bypass disconnection.
        await db.contact.update({ where: { id: f.contact.id }, data: { email: f.recipient.email } });
        const later = await entries().createEntry(f.a.book.id, f.sender.id, { type: 'EXPENSE', amount: '10', description: 'After disconnect', accountId: f.a.account.id, contactId: f.contact.id, entryDate: date });
        expect(await db.sharedEntry.count({ where: { sourceEntryId: later.id } })).toBe(0);
    });

    it('isolates the inbox and all actions to the intended recipient', async () => {
        const f = await fixture();
        const outsider = await createUser();
        expect((await shares().list(outsider.id, { page: 1, limit: 20 })).data).toEqual([]);
        for (const user of [outsider, f.sender]) {
            await expect(shares().accept(f.share.id, user.id, f.accept)).rejects.toMatchObject({ statusCode: 404 });
            await expect(shares().decline(f.share.id, user.id)).rejects.toMatchObject({ statusCode: 404 });
            await expect(shares().destinations(f.share.id, user.id)).rejects.toMatchObject({ statusCode: 404 });
        }
    });

    it('filters archived books, other currencies and explicit viewer roles, and rechecks on accept', async () => {
        const f = await fixture();
        await db.cashbookMember.create({ data: { cashbookId: f.b.book.id, userId: f.recipient.id, role: 'VIEWER' } });
        expect(await shares().destinations(f.share.id, f.recipient.id)).toEqual([]);
        await expect(shares().accept(f.share.id, f.recipient.id, f.accept)).rejects.toThrow();
        await db.cashbookMember.deleteMany();
        await db.cashbook.update({ where: { id: f.b.book.id }, data: { archivedAt: new Date() } });
        expect(await shares().destinations(f.share.id, f.recipient.id)).toEqual([]);
        await expect(shares().accept(f.share.id, f.recipient.id, f.accept)).rejects.toThrow();
        await db.cashbook.update({ where: { id: f.b.book.id }, data: { archivedAt: null, currency: 'USD' } });
        expect(await shares().destinations(f.share.id, f.recipient.id)).toEqual([]);
        await expect(shares().accept(f.share.id, f.recipient.id, f.accept)).rejects.toMatchObject({ code: 'CURRENCY_MISMATCH' });
    });

    it('refuses the sender’s workspace, foreign accounts and archived accounts', async () => {
        const f = await fixture();
        await addWorkspaceMember(f.a.workspace.id, f.recipient.id, 'ADMIN');
        await expect(shares().accept(f.share.id, f.recipient.id, { ...f.accept, cashbookId: f.a.book.id, accountId: f.a.account.id })).rejects.toMatchObject({ code: 'SAME_WORKSPACE' });
        await expect(shares().accept(f.share.id, f.recipient.id, { ...f.accept, accountId: f.a.account.id })).rejects.toMatchObject({ code: 'INVALID_ACCOUNT' });
        await db.account.update({ where: { id: f.b.account.id }, data: { archivedAt: new Date() } });
        await expect(shares().accept(f.share.id, f.recipient.id, f.accept)).rejects.toMatchObject({ code: 'ACCOUNT_ARCHIVED' });
    });

    it('rolls acceptance back on insufficient funds and closed periods', async () => {
        const f = await fixture('INCOME');
        await db.account.update({ where: { id: f.b.account.id }, data: { allowNegative: false } });
        await expect(shares().accept(f.share.id, f.recipient.id, f.accept)).rejects.toMatchObject({ code: 'INSUFFICIENT_FUNDS' });
        expect(await db.entry.count({ where: { cashbookId: f.b.book.id } })).toBe(0);
        expect((await db.sharedEntry.findUniqueOrThrow({ where: { id: f.share.id } })).status).toBe('PENDING');
        await db.account.update({ where: { id: f.b.account.id }, data: { allowNegative: true } });
        await db.fiscalPeriod.create({ data: { workspaceId: f.b.workspace.id, startDate: new Date('2026-03-01'), endDate: new Date('2026-03-31'), status: 'CLOSED' } });
        await expect(shares().accept(f.share.id, f.recipient.id, f.accept)).rejects.toMatchObject({ code: 'PERIOD_CLOSED' });
        expect(await db.entry.count({ where: { cashbookId: f.b.book.id } })).toBe(0);
    });

    it('preserves the original date in provenance when choosing a current recording date', async () => {
        const f = await fixture();
        await db.cashbook.update({ where: { id: f.b.book.id }, data: { allowBackdate: false } });
        await expect(shares().accept(f.share.id, f.recipient.id, f.accept)).rejects.toMatchObject({ code: 'BACKDATE_NOT_ALLOWED' });
        const now = new Date().toISOString();
        const result = await shares().accept(f.share.id, f.recipient.id, { ...f.accept, entryDate: now });
        expect((await db.entry.findUniqueOrThrow({ where: { id: result.entryId! } })).entryDate.toISOString()).toBe(now);
        expect((await db.sharedEntry.findUniqueOrThrow({ where: { id: f.share.id } })).entryDate.toISOString()).toBe(date);
    });

    it('collapses concurrent accepts and retries to one entry and one wallet movement', async () => {
        const f = await fixture();
        const results = await Promise.all(Array.from({ length: 5 }, () => shares().accept(f.share.id, f.recipient.id, f.accept)));
        expect(new Set(results.map(r => r.entryId)).size).toBe(1);
        expect(await db.entry.count({ where: { cashbookId: f.b.book.id } })).toBe(1);
        expect((await db.account.findUniqueOrThrow({ where: { id: f.b.account.id } })).balance.toString()).toBe('1250.125');
    });

    it('updates pending snapshots and rejects a stale review', async () => {
        const f = await fixture();
        const updated = await entries().updateEntry(f.entry.id, f.sender.id, { amount: '2000', expectedVersion: f.entry.version });
        await expect(shares().accept(f.share.id, f.recipient.id, f.accept)).rejects.toMatchObject({ statusCode: 409 });
        const latest = (await shares().list(f.recipient.id, { page: 1, limit: 20 })).data[0];
        expect(latest.amount.toString()).toBe('2000');
        await shares().accept(f.share.id, f.recipient.id, { ...f.accept, expectedVersion: updated.version });
        expect((await db.account.findUniqueOrThrow({ where: { id: f.b.account.id } })).balance.toString()).toBe('2000');
    });

    it('keeps accepted copies independent when the source is edited or reversed', async () => {
        const f = await fixture();
        const accepted = await shares().accept(f.share.id, f.recipient.id, f.accept);
        await entries().updateEntry(f.entry.id, f.sender.id, { amount: '2000', expectedVersion: f.entry.version });
        expect((await shares().list(f.recipient.id, { page: 1, limit: 20 })).data[0].sourceState).toBe('CHANGED');
        await entries().deleteEntry(f.entry.id, f.sender.id, 'Correction', CashbookRole.PRIMARY_ADMIN);
        expect((await shares().list(f.recipient.id, { page: 1, limit: 20 })).data[0].sourceState).toBe('REVERSED');
        const copy = await db.entry.findUniqueOrThrow({ where: { id: accepted.entryId! } });
        expect(copy.status).toBe('POSTED');
        expect(copy.amount.toString()).toBe('1250.125');
    });

    it('cancels pending offers on source reversal and never reopens a decline', async () => {
        const f = await fixture();
        await shares().decline(f.share.id, f.recipient.id, 'Already recorded');
        await entries().updateEntry(f.entry.id, f.sender.id, { description: 'Edited' });
        expect((await db.sharedEntry.findUniqueOrThrow({ where: { id: f.share.id } })).status).toBe('DECLINED');
        await expect(shares().accept(f.share.id, f.recipient.id, f.accept)).rejects.toThrow();
        const other = await entries().createEntry(f.a.book.id, f.sender.id, { type: 'EXPENSE', amount: '5', accountId: f.a.account.id, contactId: f.contact.id, description: 'Other', entryDate: date });
        await entries().deleteEntry(other.id, f.sender.id, 'Error', CashbookRole.PRIMARY_ADMIN);
        expect((await db.sharedEntry.findFirstOrThrow({ where: { sourceEntryId: other.id } })).status).toBe('CANCELLED');
    });

    it('prevents acceptance and decline racing into contradictory financial states', async () => {
        const f = await fixture();
        await Promise.allSettled([shares().accept(f.share.id, f.recipient.id, f.accept), shares().decline(f.share.id, f.recipient.id)]);
        const share = await db.sharedEntry.findUniqueOrThrow({ where: { id: f.share.id } });
        expect(await db.entry.count({ where: { cashbookId: f.b.book.id } })).toBe(share.status === 'ACCEPTED' ? 1 : 0);
        expect(['ACCEPTED', 'DECLINED']).toContain(share.status);
    });

    it('never bounces an imported entry back, even after a recipient edit', async () => {
        const f = await fixture();
        const reciprocal = await db.contact.create({ data: { workspaceId: f.b.workspace.id, name: 'Sender', email: f.sender.email } });
        const accepted = await shares().accept(f.share.id, f.recipient.id, f.accept);
        await entries().updateEntry(accepted.entryId!, f.recipient.id, { contactId: reciprocal.id });
        expect(await db.sharedEntry.count()).toBe(1);
    });

    it('settles a recipient receivable through the normal obligation and journal paths', async () => {
        const f = await fixture();
        const obligation = await resolveService(ObligationsService).createObligation(f.b.book.id, f.recipient.id, {
            type: 'RECEIVABLE', title: 'Customer balance', totalAmount: '2000',
        });
        const choices = await shares().options(f.share.id, f.recipient.id, f.b.book.id);
        expect(choices.obligations.map(o => o.id)).toContain(obligation.id);
        await shares().accept(f.share.id, f.recipient.id, { ...f.accept, obligationId: obligation.id, chargeAmount: '5' });
        const after = await db.cashbookObligation.findUniqueOrThrow({ where: { id: obligation.id } });
        expect(after.outstandingAmount.toString()).toBe('749.875');
        expect(after.status).toBe('PARTIAL');
        expect((await db.account.findUniqueOrThrow({ where: { id: f.b.account.id } })).balance.toString()).toBe('1245.125');
    });

    it('keeps peer loan payments in the existing settlement flow only', async () => {
        const f = await fixture();
        const peer = resolveService(PeerLinksService);
        const proposal = await peer.createPeerLink(f.a.book.id, f.sender.id, {
            direction: 'BORROWING', counterpartyEmail: f.recipient.email, title: 'Loan', principalAmount: '2000',
        });
        await peer.acceptPeerLink(proposal.id, f.recipient.id, { cashbookId: f.b.book.id });
        const obligation = await db.cashbookObligation.findFirstOrThrow({ where: { cashbookId: f.a.book.id, peerLinkId: proposal.id } });
        const payment = await entries().createEntry(f.a.book.id, f.sender.id, {
            type: 'EXPENSE', amount: '50', description: 'Repayment', entryDate: date,
            contactId: f.contact.id, accountId: f.a.account.id, obligationId: obligation.id,
        });
        expect(await db.sharedEntry.count({ where: { sourceEntryId: payment.id } })).toBe(0);
        expect(await db.peerLinkSettlement.count({ where: { entryId: payment.id } })).toBe(1);
    });

    it('serializes acceptance against a source edit without recording an unseen amount', async () => {
        const f = await fixture();
        const [accepted] = await Promise.allSettled([
            shares().accept(f.share.id, f.recipient.id, f.accept),
            entries().updateEntry(f.entry.id, f.sender.id, { amount: '3000', expectedVersion: f.entry.version }),
        ]);
        if (accepted.status === 'fulfilled') {
            const copy = await db.entry.findUniqueOrThrow({ where: { id: accepted.value.entryId! } });
            expect(copy.amount.toString()).toBe('1250.125');
            expect((await shares().list(f.recipient.id, { page: 1, limit: 20 })).data[0].sourceState).toBe('CHANGED');
        } else {
            expect(await db.entry.count({ where: { cashbookId: f.b.book.id } })).toBe(0);
        }
    });

    it('keeps provenance and the accepted copy after a source is purged', async () => {
        const f = await fixture();
        const copy = await shares().accept(f.share.id, f.recipient.id, f.accept);
        const purge = (workspaceId: string) => db.$transaction(async tx => {
            await tx.$executeRawUnsafe("SET LOCAL app.allow_ledger_maintenance = 'on'");
            await purgeWorkspace(tx, workspaceId);
        });
        await purge(f.a.workspace.id);
        const result = (await shares().list(f.recipient.id, { page: 1, limit: 20 })).data[0];
        expect(result.sourceState).toBe('UNAVAILABLE');
        expect(result.acceptedEntry?.id).toBe(copy.entryId);
        expect((await shares().accept(f.share.id, f.recipient.id, f.accept)).alreadyAccepted).toBe(true);
        await purge(f.b.workspace.id);
        expect((await db.sharedEntry.findUniqueOrThrow({ where: { id: f.share.id } })).acceptedEntryId).toBeNull();
    });

    it('validates authentication, recipient ownership, UUIDs and required account over HTTP', async () => {
        const f = await fixture();
        const { config } = await import('../../config');
        const cookie = (id: string, email: string) => `accessToken=${jwt.sign({ userId: id, email, jti: randomUUID() }, config.JWT_ACCESS_SECRET, { expiresIn: '15m' })}`;
        const auth = cookie(f.recipient.id, f.recipient.email);
        expect((await request(app).get('/api/v1/shared-entries')).status).toBe(401);
        expect((await request(app).get('/api/v1/shared-entries/bad-id/destinations').set('Cookie', auth)).status).toBe(400);
        expect((await request(app).get(`/api/v1/shared-entries/${f.share.id}/destinations`).set('Cookie', cookie(f.sender.id, f.sender.email))).status).toBe(404);
        expect((await request(app).post(`/api/v1/shared-entries/${f.share.id}/accept`).set('Cookie', auth).send({ cashbookId: f.b.book.id, expectedVersion: 1 })).status).toBe(400);
        expect((await request(app).post(`/api/v1/shared-entries/${f.share.id}/accept`).set('Cookie', auth).send({ ...f.accept, amount: '1' })).status).toBe(400);
        const ok = await request(app).post(`/api/v1/shared-entries/${f.share.id}/accept`).set('Cookie', auth).send(f.accept);
        expect(ok.status, JSON.stringify(ok.body)).toBe(200);
        const list = await request(app).get('/api/v1/shared-entries').set('Cookie', auth);
        expect(list.body.data.data).toHaveLength(1);
        expect(list.body.data.data[0]).not.toHaveProperty('sourceEntry');
        expect(list.body.data.data[0]).not.toHaveProperty('sourceWorkspaceId');
        const wrongBook = await request(app).get(`/api/v1/entries/${f.entry.id}/sharing/cashbook/${f.b.book.id}`).set('Cookie', auth);
        expect(wrongBook.status).toBe(404);
        const senderStatus = await request(app).get(`/api/v1/entries/${f.entry.id}/sharing/cashbook/${f.a.book.id}`).set('Cookie', cookie(f.sender.id, f.sender.email));
        expect(senderStatus.body.data.deliveries[0].status).toBe('ACCEPTED');
        expect(JSON.stringify(senderStatus.body.data)).not.toContain(f.b.workspace.id);
        expect(JSON.stringify(senderStatus.body.data)).not.toContain(f.b.account.id);
    });
});

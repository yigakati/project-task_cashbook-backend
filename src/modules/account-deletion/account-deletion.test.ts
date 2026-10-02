/**
 * Account deletion, end to end.
 *
 * The books are built through the real services — journals, wallets, a
 * reversal, a transfer, stored files — because the purge has to get past the
 * ledger's append-only trigger and its restricting foreign keys, and a
 * hand-written fixture would not have them.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import bcrypt from 'bcryptjs';
import { EntryType, WorkspaceRole, WorkspaceType } from '@prisma/client';
import { CashbookRole } from '../../core/types';

// Captures every email instead of sending it, so the confirmation link can be read.
const sent: Array<{ to: string; subject: string; html: string }> = [];
vi.mock('../../config/email', () => ({
    sendEmail: vi.fn(async (message: { to: string; subject: string; html: string }) => {
        sent.push(message);
    }),
}));

import { resetDatabase, testPrisma } from '../../test/setup';
import { resolveService } from '../../test/container';
import { addWorkspaceMember, createInventoryItem, createUser, createWorkspace } from '../../test/factories';
import { InvoicingService } from '../invoicing/invoicing.service';
import { AccountDeletionService, tombstoneEmail } from './account-deletion.service';
import { CashbooksService } from '../cashbooks/cashbooks.service';
import { AccountsService } from '../accounts/accounts.service';
import { EntriesService } from '../entries/entries.service';
import { StorageService } from '../files/storage.service';
import { LedgerIntegrityService } from '../../core/ledger/integrity.service';
import { config } from '../../config';

const deletion = () => resolveService(AccountDeletionService);
const now = () => new Date().toISOString();
const DAY = 86_400_000;

async function withPassword(password = 'Correct-horse-1') {
    const user = await createUser();
    await testPrisma.user.update({
        where: { id: user.id },
        data: { passwordHash: await bcrypt.hash(password, 4) },
    });
    return { user, password };
}

/** A workspace with real books: wallets, entries, a reversal, a transfer, files. */
async function realBooks(ownerId: string, type: WorkspaceType = WorkspaceType.BUSINESS) {
    const workspace = await createWorkspace(ownerId);
    if (type !== WorkspaceType.BUSINESS) {
        await testPrisma.workspace.update({ where: { id: workspace.id }, data: { type } });
    }
    const cashbook = await resolveService(CashbooksService).createCashbook(workspace.id, ownerId, {
        name: 'Main book', allowBackdate: true,
    });
    const bank = await testPrisma.accountType.findFirstOrThrow({ where: { workspaceId: workspace.id, name: 'Bank' } });
    const accounts = resolveService(AccountsService);
    const walletA = await accounts.createAccount(workspace.id, ownerId, {
        accountTypeId: bank.id, name: 'MoMo', currency: 'UGX', initialBalance: '50000',
    });
    const walletB = await accounts.createAccount(workspace.id, ownerId, {
        accountTypeId: bank.id, name: 'Bank', currency: 'UGX', initialBalance: '10000',
    });

    const entries = resolveService(EntriesService);
    await entries.createEntry(cashbook.id, ownerId, {
        type: EntryType.INCOME, amount: '20000', description: 'Sale', accountId: walletA.id, entryDate: now(),
    });
    const mistake = await entries.createEntry(cashbook.id, ownerId, {
        type: EntryType.EXPENSE, amount: '3000', chargeAmount: '100', description: 'Typo', accountId: walletA.id, entryDate: now(),
    });
    await entries.deleteEntry(mistake.id, ownerId, 'Entered twice', CashbookRole.PRIMARY_ADMIN);
    await accounts.transferBetweenAccounts(workspace.id, ownerId, {
        fromAccountId: walletA.id, toAccountId: walletB.id, amount: '1000', description: 'Float',
    });

    const attachment = await testPrisma.attachment.create({
        data: {
            workspaceId: workspace.id, cashbookId: cashbook.id, entryId: mistake.id, uploadedById: ownerId,
            fileName: 'receipt.pdf', mimeType: 'application/pdf', fileSize: 1000, s3Key: `attachments/${randomUUID()}.pdf`,
        },
    });
    const logoKey = `logos/${workspace.id}-1.png`;
    await testPrisma.invoiceSettings.create({ data: { workspaceId: workspace.id, logoKey, logoSize: 500 } });

    return { workspace, cashbook, walletA, walletB, objectKeys: [attachment.s3Key, logoKey] };
}

async function makeDue(requestId: string) {
    await testPrisma.accountDeletionRequest.update({
        where: { id: requestId },
        data: { scheduledFor: new Date(Date.now() - 1000) },
    });
}

const tokenFrom = (html: string) => decodeURIComponent(/token=([^"&]+)/.exec(html)?.[1] ?? '');

describe('account deletion', () => {
    beforeEach(async () => {
        await resetDatabase();
        sent.length = 0;
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe('what it would do', () => {
        it('deletes what only they use, leaves the businesses they belong to, and refuses shared ones', async () => {
            const { user } = await withPassword();
            const colleague = await createUser();

            const personal = await createWorkspace(user.id);
            await testPrisma.workspace.update({ where: { id: personal.id }, data: { type: WorkspaceType.PERSONAL } });
            const solo = await createWorkspace(user.id, { name: 'Side hustle' });
            const shared = await createWorkspace(user.id, { name: 'Family shop' });
            await addWorkspaceMember(shared.id, colleague.id, WorkspaceRole.ADMIN);
            const employer = await createWorkspace(colleague.id, { name: 'Employer Ltd' });
            await addWorkspaceMember(employer.id, user.id, WorkspaceRole.MEMBER);

            const plan = await deletion().plan(user.id);

            expect(plan.workspacesToDelete.map((w) => w.id).sort()).toEqual([personal.id, solo.id].sort());
            expect(plan.membershipsToLeave).toEqual([{ workspaceId: employer.id, name: 'Employer Ltd', role: 'MEMBER' }]);
            expect(plan.blockers).toEqual([
                expect.objectContaining({
                    code: 'OWNS_SHARED_WORKSPACE',
                    workspaces: [{ id: shared.id, name: 'Family shop', otherMembers: 1 }],
                }),
            ]);
        });

        it('treats an already-deleted business as theirs to purge, not as a blocker', async () => {
            const { user } = await withPassword();
            const closed = await createWorkspace(user.id);
            await addWorkspaceMember(closed.id, (await createUser()).id);
            await testPrisma.workspace.update({ where: { id: closed.id }, data: { isActive: false } });

            const plan = await deletion().plan(user.id);
            expect(plan.blockers).toEqual([]);
            expect(plan.workspacesToDelete.map((w) => w.id)).toEqual([closed.id]);
        });

        it('refuses superadmins', async () => {
            const { user } = await withPassword();
            await testPrisma.user.update({ where: { id: user.id }, data: { isSuperAdmin: true } });

            const plan = await deletion().plan(user.id);
            expect(plan.blockers.map((b) => b.code)).toEqual(['SUPER_ADMIN']);
        });
    });

    describe('asking in the app', () => {
        it('needs the password, then schedules after the grace period and ends every session', async () => {
            const { user, password } = await withPassword();
            await testPrisma.refreshToken.create({
                data: { userId: user.id, tokenHash: 'x', expiresAt: new Date(Date.now() + DAY) },
            });

            await expect(deletion().requestFromApp(user.id, { password: 'wrong' }))
                .rejects.toMatchObject({ code: 'INVALID_PASSWORD' });

            const request = await deletion().requestFromApp(user.id, { password, reason: 'Moving on' });
            expect(request.status).toBe('SCHEDULED');
            const graceMs = config.ACCOUNT_DELETION_GRACE_DAYS * DAY;
            expect(Math.abs(request.scheduledFor!.getTime() - (Date.now() + graceMs))).toBeLessThan(60_000);

            expect(await testPrisma.refreshToken.count({ where: { userId: user.id, isRevoked: false } })).toBe(0);
            expect(sent.map((m) => m.subject)).toEqual(['Your account is scheduled for deletion']);

            // Asking again changes nothing.
            const again = await deletion().requestFromApp(user.id, { password });
            expect(again.id).toBe(request.id);
        });

        it('asks an account with no password to type its email instead', async () => {
            const user = await createUser();
            // Signed up with Google: no password to re-enter.
            await testPrisma.user.update({ where: { id: user.id }, data: { passwordHash: null } });

            await expect(deletion().requestFromApp(user.id, { confirmEmail: 'someone@else.com' }))
                .rejects.toMatchObject({ code: 'CONFIRMATION_MISMATCH' });
            await expect(deletion().requestFromApp(user.id, { confirmEmail: user.email.toUpperCase() }))
                .resolves.toMatchObject({ status: 'SCHEDULED' });
        });

        it('says what is in the way instead of scheduling', async () => {
            const { user, password } = await withPassword();
            const shared = await createWorkspace(user.id);
            await addWorkspaceMember(shared.id, (await createUser()).id);

            await expect(deletion().requestFromApp(user.id, { password }))
                .rejects.toMatchObject({ code: 'ACCOUNT_DELETION_BLOCKED', blockers: [expect.objectContaining({ code: 'OWNS_SHARED_WORKSPACE' })] });
            expect(await testPrisma.accountDeletionRequest.count()).toBe(0);
        });

        it('can be cancelled until it runs', async () => {
            const { user, password } = await withPassword();
            await deletion().requestFromApp(user.id, { password });

            const cancelled = await deletion().cancelFromApp(user.id);
            expect(cancelled.status).toBe('CANCELLED');
            expect((await deletion().getForUser(user.id)).request).toBeNull();
            await expect(deletion().cancelFromApp(user.id)).rejects.toMatchObject({ code: 'NOT_FOUND' });
        });
    });

    describe('asking on the website', () => {
        it('reveals nothing about addresses without an account', async () => {
            await expect(deletion().requestFromWeb({ email: 'nobody@nowhere.test' })).resolves.toBeUndefined();
            expect(sent).toHaveLength(0);
            expect(await testPrisma.accountDeletionRequest.count()).toBe(0);
        });

        it('schedules only once the emailed link is used, and only once', async () => {
            const { user } = await withPassword();

            await deletion().requestFromWeb({ email: user.email.toUpperCase(), reason: 'No longer needed' });
            const pending = await testPrisma.accountDeletionRequest.findFirstOrThrow({ where: { userId: user.id } });
            expect(pending.status).toBe('PENDING_VERIFICATION');
            expect(sent[0].to).toBe(user.email);

            const token = tokenFrom(sent[0].html);
            // The link holds the secret; the database holds only its hash.
            expect(pending.verificationTokenHash).not.toBe(token);

            const result = await deletion().confirmFromWeb(token);
            expect(result.status).toBe('SCHEDULED');
            await expect(deletion().confirmFromWeb(token)).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
        });

        it('does not let the form flood an inbox', async () => {
            const { user } = await withPassword();
            await deletion().requestFromWeb({ email: user.email });
            await deletion().requestFromWeb({ email: user.email });
            expect(sent).toHaveLength(1);
        });

        it('refuses an expired link', async () => {
            const { user } = await withPassword();
            await deletion().requestFromWeb({ email: user.email });
            await testPrisma.accountDeletionRequest.updateMany({
                where: { userId: user.id },
                data: { verificationExpiresAt: new Date(Date.now() - 1000) },
            });

            await expect(deletion().confirmFromWeb(tokenFrom(sent[0].html)))
                .rejects.toMatchObject({ code: 'TOKEN_EXPIRED' });
        });

        it('keeps a verified request on hold when something is in the way', async () => {
            const { user } = await withPassword();
            const shared = await createWorkspace(user.id);
            await addWorkspaceMember(shared.id, (await createUser()).id);

            await deletion().requestFromWeb({ email: user.email });
            const result = await deletion().confirmFromWeb(tokenFrom(sent[0].html));

            expect(result.status).toBe('BLOCKED');
            expect(sent.at(-1)?.subject).toBe('Your account deletion is on hold');
        });
    });

    describe('carrying it out', () => {
        it('purges their own books entirely, leaves other businesses intact, and anonymises the account', async () => {
            const { user, password } = await withPassword();
            const originalEmail = user.email;
            const deleteObject = vi.spyOn(StorageService.prototype, 'deleteObject').mockResolvedValue(undefined);

            const personal = await realBooks(user.id, WorkspaceType.PERSONAL);

            // They also worked at someone else's business and posted there.
            const employerOwner = await createUser();
            const employer = await realBooks(employerOwner.id);
            await addWorkspaceMember(employer.workspace.id, user.id, WorkspaceRole.MEMBER);
            await testPrisma.cashbookMember.create({
                data: { cashbookId: employer.cashbook.id, userId: user.id, role: 'DATA_OPERATOR' },
            });
            const theirWorkAtEmployer = await resolveService(EntriesService).createEntry(employer.cashbook.id, user.id, {
                type: EntryType.INCOME, amount: '7000', description: 'Till takings', accountId: employer.walletA.id, entryDate: now(),
            });

            await testPrisma.loginHistory.create({ data: { userId: user.id, ipAddress: '10.0.0.1', status: 'SUCCESS' } });
            await testPrisma.auditLog.create({
                data: { userId: user.id, action: 'USER_LOGGED_IN', resource: 'auth', ipAddress: '10.0.0.1', userAgent: 'Phone' },
            });

            const request = await deletion().requestFromApp(user.id, { password });
            await makeDue(request.id);
            const processed = await deletion().processDue();
            const outcome = await testPrisma.accountDeletionRequest.findUniqueOrThrow({ where: { id: request.id } });
            expect(outcome.failureReason).toBeNull();
            expect(processed).toBe(1);

            // Their workspace is gone, ledger and all.
            expect(await testPrisma.workspace.findUnique({ where: { id: personal.workspace.id } })).toBeNull();
            expect(await testPrisma.journalEntry.count({ where: { workspaceId: personal.workspace.id } })).toBe(0);
            expect(await testPrisma.account.count({ where: { workspaceId: personal.workspace.id } })).toBe(0);
            expect(deleteObject.mock.calls.map(([key]) => key).sort()).toEqual([...personal.objectKeys].sort());

            // The employer's books are untouched and still balance; the entry
            // they posted there stays, now attributed to "Deleted user".
            const kept = await testPrisma.entry.findUniqueOrThrow({ where: { id: theirWorkAtEmployer.id } });
            expect(kept.createdById).toBe(user.id);
            const report = await resolveService(LedgerIntegrityService).verifyWorkspace(employer.workspace.id);
            expect(report.ok).toBe(true);
            expect(await testPrisma.workspaceMember.count({ where: { userId: user.id } })).toBe(0);
            expect(await testPrisma.cashbookMember.count({ where: { userId: user.id } })).toBe(0);

            // The identity is gone.
            const tombstone = await testPrisma.user.findUniqueOrThrow({ where: { id: user.id } });
            expect(tombstone).toMatchObject({
                email: tombstoneEmail(user.id),
                firstName: 'Deleted',
                lastName: 'user',
                passwordHash: null,
                isActive: false,
            });
            expect(tombstone.deletedAt).toBeInstanceOf(Date);
            expect(await testPrisma.loginHistory.count({ where: { userId: user.id } })).toBe(0);
            expect(await testPrisma.refreshToken.count({ where: { userId: user.id } })).toBe(0);
            const audit = await testPrisma.auditLog.findFirstOrThrow({ where: { userId: user.id, action: 'USER_LOGGED_IN' } });
            expect(audit).toMatchObject({ ipAddress: null, userAgent: null });

            // The record of what happened keeps counts, not the address.
            const done = await testPrisma.accountDeletionRequest.findUniqueOrThrow({ where: { id: request.id } });
            expect(done.status).toBe('COMPLETED');
            expect(done.contactEmail).toBeNull();
            expect(done.summary).toMatchObject({ workspacesDeleted: 1, filesDeleted: 2, membershipsRemoved: 1 });
            expect(sent.at(-1)).toMatchObject({ to: originalEmail, subject: 'Your account has been deleted' });

            // The address is free to sign up with again.
            await expect(createUser({ email: originalEmail })).resolves.toBeTruthy();
        });

        it('also purges invoices, receivables and stock movements', async () => {
            const { user, password } = await withPassword();
            vi.spyOn(StorageService.prototype, 'deleteObject').mockResolvedValue(undefined);
            const books = await realBooks(user.id);

            // A sent, part-paid invoice for stocked goods: an obligation, a
            // payment entry, a stock-out and their journals.
            const customer = await testPrisma.contact.create({
                data: { workspaceId: books.workspace.id, name: 'Acme', type: 'CUSTOMER' },
            });
            const item = await createInventoryItem(books.workspace.id, { quantityOnHand: 10, averageCost: '100' });
            const invoicing = resolveService(InvoicingService);
            const invoice = await invoicing.createInvoice(books.workspace.id, user.id, {
                customerId: customer.id,
                issueDate: now(),
                dueDate: new Date(Date.now() + 7 * DAY).toISOString(),
                currency: 'UGX',
                cashbookId: books.cashbook.id,
                items: [{ name: 'Widget', quantity: '2', unitPrice: '500', lineType: 'SALE', inventoryItemId: item.id }],
            });
            await invoicing.sendInvoice(invoice!.id, books.workspace.id, user.id, {
                paymentAmount: '400', accountId: books.walletA.id,
            } as never);
            expect(await testPrisma.inventoryTransaction.count({ where: { itemId: item.id } })).toBeGreaterThan(0);

            const request = await deletion().requestFromApp(user.id, { password });
            await makeDue(request.id);
            await deletion().processDue();

            const outcome = await testPrisma.accountDeletionRequest.findUniqueOrThrow({ where: { id: request.id } });
            expect(outcome.failureReason).toBeNull();
            expect(outcome.status).toBe('COMPLETED');
            expect(await testPrisma.workspace.findUnique({ where: { id: books.workspace.id } })).toBeNull();
            expect(await testPrisma.invoice.count({ where: { workspaceId: books.workspace.id } })).toBe(0);
            expect(await testPrisma.inventoryItem.count({ where: { workspaceId: books.workspace.id } })).toBe(0);
        });

        it('waits for the grace period, and never runs a cancelled request', async () => {
            const { user, password } = await withPassword();
            const request = await deletion().requestFromApp(user.id, { password });

            expect(await deletion().processDue()).toBe(0);

            await deletion().cancelFromApp(user.id);
            await makeDue(request.id);
            expect(await deletion().processDue()).toBe(0);
            expect((await testPrisma.user.findUniqueOrThrow({ where: { id: user.id } })).deletedAt).toBeNull();
        });

        it('puts the request on hold if something got in the way during the grace period', async () => {
            const { user, password } = await withPassword();
            const workspace = await createWorkspace(user.id);
            const request = await deletion().requestFromApp(user.id, { password });

            // They invited someone in after asking.
            await addWorkspaceMember(workspace.id, (await createUser()).id);
            await makeDue(request.id);
            await deletion().processDue();

            const after = await testPrisma.accountDeletionRequest.findUniqueOrThrow({ where: { id: request.id } });
            expect(after.status).toBe('BLOCKED');
            expect((await testPrisma.user.findUniqueOrThrow({ where: { id: user.id } })).deletedAt).toBeNull();
        });

        it('expires confirmation links nobody used', async () => {
            const { user } = await withPassword();
            await deletion().requestFromWeb({ email: user.email });
            await testPrisma.accountDeletionRequest.updateMany({
                where: { userId: user.id },
                data: { verificationExpiresAt: new Date(Date.now() - 1000) },
            });

            await deletion().processDue();
            const request = await testPrisma.accountDeletionRequest.findFirstOrThrow({ where: { userId: user.id } });
            expect(request.status).toBe('EXPIRED');
        });
    });

    describe('superadmin', () => {
        it('can schedule for a verified person, process it at once, and see what happened', async () => {
            const admin = await createUser();
            const { user } = await withPassword();
            vi.spyOn(StorageService.prototype, 'deleteObject').mockResolvedValue(undefined);

            const scheduled = await deletion().scheduleForUser(user.id, admin.id, { reason: 'Asked by phone', note: 'ID checked' });
            expect(scheduled).toMatchObject({ status: 'SCHEDULED', source: 'ADMIN' });

            const processed = await deletion().processNow(scheduled.id, admin.id);
            expect(processed.status).toBe('COMPLETED');
            expect(processed.handledBy).toMatchObject({ firstName: admin.firstName });

            const listed = await deletion().list({ page: 1, limit: 10, status: 'COMPLETED' });
            expect(listed.total).toBe(1);
        });

        it('can cancel, but not once the work has started', async () => {
            const admin = await createUser();
            const { user, password } = await withPassword();
            const request = await deletion().requestFromApp(user.id, { password });

            await expect(deletion().cancelByAdmin(request.id, admin.id, 'User called')).resolves.toMatchObject({ status: 'CANCELLED' });

            const second = await deletion().requestFromApp(user.id, { password });
            await testPrisma.accountDeletionRequest.update({ where: { id: second.id }, data: { status: 'PROCESSING' } });
            await expect(deletion().cancelByAdmin(second.id, admin.id)).rejects.toMatchObject({ code: 'INVALID_STATUS' });
        });
    });
});

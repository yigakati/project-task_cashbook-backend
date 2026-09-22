/**
 * Retiring a book, and retiring an account.
 *
 * The rule both follow: anything that has recorded history is archived, never
 * deleted. Deleting stays available only while nothing has ever been recorded,
 * where there is no history to lose.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { Decimal } from '@prisma/client/runtime/library';
import { EntryType } from '@prisma/client';
import { resetDatabase, testPrisma } from '../../test/setup';
import { resolveService } from '../../test/container';
import { createAccount, createCashbook, createUser, createWorkspace } from '../../test/factories';
import { CashbooksService } from './cashbooks.service';
import { EntriesService } from '../entries/entries.service';
import { AccountsService } from '../accounts/accounts.service';
import { WorkspaceRole } from '../../core/types';

const books = () => resolveService(CashbooksService);
const entries = () => resolveService(EntriesService);
const accounts = () => resolveService(AccountsService);

async function addEntry(cashbookId: string, createdById: string, isDeleted = false) {
    return testPrisma.entry.create({
        data: {
            cashbookId,
            type: EntryType.INCOME,
            amount: new Decimal('1000'),
            description: 'Recorded income',
            entryDate: new Date(),
            createdById,
            isDeleted,
        },
    });
}

async function setup() {
    const owner = await createUser();
    const workspace = await createWorkspace(owner.id);
    const book = await createCashbook(workspace.id, owner.id);
    return { owner, workspace, book };
}

const listActive = (workspaceId: string, userId: string) =>
    books().getCashbooks(workspaceId, userId, WorkspaceRole.OWNER);

const listWithArchived = (workspaceId: string, userId: string) =>
    books().getCashbooks(workspaceId, userId, WorkspaceRole.OWNER, true);

describe('cashbook lifecycle', () => {
    beforeEach(async () => {
        await resetDatabase();
    });

    describe('deleting', () => {
        it('refuses a book that has entries, and points at archiving', async () => {
            const { owner, workspace, book } = await setup();
            await addEntry(book.id, owner.id);

            await expect(books().deleteCashbook(book.id, owner.id)).rejects.toMatchObject({
                code: 'DELETE_RESTRICTED',
            });
            await expect(books().deleteCashbook(book.id, owner.id)).rejects.toThrow(/archive it instead/i);

            const [still] = await listActive(workspace.id, owner.id);
            expect(still.id).toBe(book.id);
        });

        it('still refuses when the only entry has since been deleted', async () => {
            const { owner, book } = await setup();
            // A reversed entry is still this book's history, and its journals
            // and audit trail keep pointing at the book.
            await addEntry(book.id, owner.id, true);

            await expect(books().deleteCashbook(book.id, owner.id)).rejects.toMatchObject({
                code: 'DELETE_RESTRICTED',
            });
        });

        it('removes a book that never recorded anything', async () => {
            const { owner, workspace, book } = await setup();

            await books().deleteCashbook(book.id, owner.id);

            const after = await testPrisma.cashbook.findUniqueOrThrow({ where: { id: book.id } });
            expect(after.isActive).toBe(false);
            expect(await listActive(workspace.id, owner.id)).toHaveLength(0);
        });

        it('reports what the client needs to offer the right action', async () => {
            const { owner, workspace, book } = await setup();
            const empty = await createCashbook(workspace.id, owner.id);
            await addEntry(book.id, owner.id);

            const listed = await listActive(workspace.id, owner.id);
            expect(listed.find((b) => b.id === book.id)).toMatchObject({ totalEntries: 1, canDelete: false });
            expect(listed.find((b) => b.id === empty.id)).toMatchObject({ totalEntries: 0, canDelete: true });
        });
    });

    describe('archiving', () => {
        it('takes the book out of the active list without losing it', async () => {
            const { owner, workspace, book } = await setup();
            await addEntry(book.id, owner.id);

            const archived = await books().setArchived(book.id, owner.id, true);
            expect(archived.archivedAt).toBeInstanceOf(Date);

            expect(await listActive(workspace.id, owner.id)).toHaveLength(0);
            const withArchived = await listWithArchived(workspace.id, owner.id);
            expect(withArchived.map((b) => b.id)).toEqual([book.id]);

            // Still readable on its own, which is the point of archiving.
            await expect(books().getCashbook(book.id)).resolves.toMatchObject({ id: book.id });
        });

        it('refuses new entries while archived, and takes them again once restored', async () => {
            const { owner, book } = await setup();
            await books().setArchived(book.id, owner.id, true);

            const entry = {
                type: EntryType.INCOME,
                amount: '500',
                description: 'Sale',
                entryDate: new Date().toISOString(),
            };

            await expect(
                entries().createEntry(book.id, owner.id, entry as never),
            ).rejects.toMatchObject({ code: 'CASHBOOK_ARCHIVED' });

            await books().setArchived(book.id, owner.id, false);

            // Whatever else this call needs, being archived is no longer the
            // reason it could fail.
            const afterRestore = await entries()
                .createEntry(book.id, owner.id, entry as never)
                .then(() => null, (error: { code?: string }) => error.code);
            expect(afterRestore).not.toBe('CASHBOOK_ARCHIVED');
        });

        it('archiving an already-archived book records nothing twice', async () => {
            const { owner, book } = await setup();

            await books().setArchived(book.id, owner.id, true);
            await books().setArchived(book.id, owner.id, true);

            const logged = await testPrisma.auditLog.count({
                where: { resourceId: book.id, action: 'CASHBOOK_ARCHIVED' },
            });
            expect(logged).toBe(1);
        });

        it('lets an archived book still be deleted when it never recorded anything', async () => {
            const { owner, book } = await setup();

            await books().setArchived(book.id, owner.id, true);
            await expect(books().deleteCashbook(book.id, owner.id)).resolves.not.toThrow();
        });

        it('restores a book to the active list', async () => {
            const { owner, workspace, book } = await setup();

            await books().setArchived(book.id, owner.id, true);
            const restored = await books().setArchived(book.id, owner.id, false);

            expect(restored.archivedAt).toBeNull();
            expect((await listActive(workspace.id, owner.id)).map((b) => b.id)).toEqual([book.id]);
        });
    });

    describe('accounts follow the same rule', () => {
        it('refuses an account whose only activity is a transfer', async () => {
            const { owner, workspace } = await setup();
            const from = await createAccount(workspace.id);
            const to = await createAccount(workspace.id);

            // A transfer writes no account_transactions row, so counting only
            // those let this through — and the restricting foreign key then
            // failed in the database instead of telling the user to archive.
            await testPrisma.accountTransfer.create({
                data: {
                    workspaceId: workspace.id,
                    fromAccountId: from.id,
                    toAccountId: to.id,
                    amount: new Decimal('100'),
                    description: 'Moved float',
                    transferredAt: new Date(),
                    createdById: owner.id,
                },
            });

            await expect(
                accounts().deleteAccount(from.id, workspace.id, owner.id),
            ).rejects.toMatchObject({ code: 'DELETE_RESTRICTED' });
            await expect(
                accounts().deleteAccount(to.id, workspace.id, owner.id),
            ).rejects.toMatchObject({ code: 'DELETE_RESTRICTED' });
        });

        it('deletes an account that never recorded anything', async () => {
            const { owner, workspace } = await setup();
            const account = await createAccount(workspace.id);

            await accounts().deleteAccount(account.id, workspace.id, owner.id);

            expect(await testPrisma.account.findUnique({ where: { id: account.id } })).toBeNull();
        });
    });
});

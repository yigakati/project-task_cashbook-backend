/**
 * The book's entry list: filters, paging, totals and the running balance.
 *
 * The list used to be fetched without paging parameters, so the API's default
 * page of 20 was all anyone ever saw, and the browser summed a running balance
 * from zero over that slice. These tests pin the server-side replacement.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { Decimal } from '@prisma/client/runtime/library';
import { EntryStatus, EntryType, TransactionSourceType, WorkspaceRole } from '@prisma/client';
import { resetDatabase, testPrisma } from '../../test/setup';
import { resolveService } from '../../test/container';
import {
    addWorkspaceMember,
    createAccount,
    createCashbook,
    createUser,
    createWorkspace,
} from '../../test/factories';
import { EntriesService } from './entries.service';
import { entryQuerySchema } from './entries.dto';

const service = () => resolveService(EntriesService);
const list = (cashbookId: string, query: Record<string, unknown> = {}) =>
    service().getEntries(cashbookId, entryQuerySchema.parse(query));

const day = (n: number) => new Date(Date.UTC(2026, 0, n, 12));

async function addEntry(
    cashbookId: string,
    createdById: string,
    o: {
        type?: EntryType;
        amount?: string;
        charge?: string;
        date?: Date;
        description?: string;
        status?: EntryStatus;
    } = {},
) {
    const reversed = o.status === EntryStatus.REVERSED;
    return testPrisma.entry.create({
        data: {
            cashbookId,
            createdById,
            type: o.type ?? EntryType.INCOME,
            amount: new Decimal(o.amount ?? '100'),
            chargeAmount: o.charge ? new Decimal(o.charge) : null,
            description: o.description ?? 'Entry',
            entryDate: o.date ?? day(1),
            status: o.status ?? EntryStatus.POSTED,
            isDeleted: reversed,
        },
    });
}

async function linkToWallet(entry: { id: string; type: EntryType; amount: Decimal }, workspaceId: string, accountId: string) {
    return testPrisma.accountTransaction.create({
        data: {
            workspaceId,
            accountId,
            sourceType: TransactionSourceType.CASHBOOK_ENTRY,
            sourceId: entry.id,
            type: entry.type,
            amount: entry.amount,
            description: 'Linked',
        },
    });
}

async function setup() {
    const owner = await createUser();
    const workspace = await createWorkspace(owner.id);
    const book = await createCashbook(workspace.id, owner.id);
    return { owner, workspace, book };
}

describe('entry list', () => {
    beforeEach(async () => {
        await resetDatabase();
    });

    describe('query parsing', () => {
        it('reads includeReversed=false as false', () => {
            // z.coerce.boolean() turned the string "false" into true.
            expect(entryQuerySchema.parse({ includeReversed: 'false' }).includeReversed).toBe(false);
            expect(entryQuerySchema.parse({ includeReversed: 'true' }).includeReversed).toBe(true);
            expect(entryQuerySchema.parse({}).includeReversed).toBe(false);
        });

        it('refuses a range that ends before it starts', () => {
            expect(() => entryQuerySchema.parse({
                startDate: day(5).toISOString(),
                endDate: day(1).toISOString(),
            })).toThrow();
        });
    });

    describe('paging', () => {
        it('reaches entries beyond the first page', async () => {
            const { owner, book } = await setup();
            for (let i = 1; i <= 30; i++) await addEntry(book.id, owner.id, { date: day(i) });

            const second = await list(book.id, { page: 2, limit: 20 });
            expect(second.data).toHaveLength(10);
            expect(second.pagination).toMatchObject({ total: 30, totalPages: 2 });
        });

        it('never repeats or skips same-day entries across pages', async () => {
            const { owner, book } = await setup();
            for (let i = 0; i < 25; i++) await addEntry(book.id, owner.id, { date: day(3) });

            const first = await list(book.id, { page: 1, limit: 10 });
            const second = await list(book.id, { page: 2, limit: 10 });
            const third = await list(book.id, { page: 3, limit: 10 });
            const ids = [...first.data, ...second.data, ...third.data].map((e) => e.id);

            expect(new Set(ids).size).toBe(25);
        });

        it('hides reversed entries unless asked', async () => {
            const { owner, book } = await setup();
            await addEntry(book.id, owner.id);
            await addEntry(book.id, owner.id, { status: EntryStatus.REVERSED });

            expect((await list(book.id, { includeReversed: 'false' })).data).toHaveLength(1);
            expect((await list(book.id, { includeReversed: 'true' })).data).toHaveLength(2);
        });
    });

    describe('running balance', () => {
        it('is right on every page, not just the first', async () => {
            const { owner, book } = await setup();
            for (let i = 1; i <= 25; i++) await addEntry(book.id, owner.id, { amount: '100', date: day(i) });

            const first = await list(book.id, { page: 1, limit: 10 });
            expect(first.runningBalance.available).toBe(true);
            expect(first.data[0].runningBalance).toBe('2500');   // day 25
            expect(first.data[9].runningBalance).toBe('1600');   // day 16

            const last = await list(book.id, { page: 3, limit: 10 });
            expect(last.data[0].runningBalance).toBe('500');     // day 5
            expect(last.data[4].runningBalance).toBe('100');     // day 1
        });

        it('applies charges, and leaves wallet-linked and reversed entries out', async () => {
            const { owner, workspace, book } = await setup();
            const wallet = await createAccount(workspace.id);

            await addEntry(book.id, owner.id, { amount: '1000', charge: '5', date: day(1) });   // +995
            await addEntry(book.id, owner.id, { type: EntryType.EXPENSE, amount: '200', charge: '10', date: day(2) }); // -210
            const linked = await addEntry(book.id, owner.id, { amount: '500', date: day(3) });  // 0
            await linkToWallet(linked, workspace.id, wallet.id);
            await addEntry(book.id, owner.id, { amount: '300', date: day(4), status: EntryStatus.REVERSED }); // 0

            const result = await list(book.id, { includeReversed: 'true', sortOrder: 'asc' });
            expect(result.data.map((e) => e.runningBalance)).toEqual(['995', '785', '785', '785']);
        });

        it('keeps the true opening balance when filtered to a date range', async () => {
            const { owner, book } = await setup();
            for (let i = 1; i <= 10; i++) await addEntry(book.id, owner.id, { amount: '100', date: day(i) });

            const result = await list(book.id, {
                startDate: day(6).toISOString(),
                endDate: day(10).toISOString(),
                sortOrder: 'asc',
            });
            // A statement for days 6–10 opens at the 500 carried in from days 1–5.
            expect(result.data[0].runningBalance).toBe('600');
        });

        it('is withheld when the rows are a subset', async () => {
            const { owner, book } = await setup();
            await addEntry(book.id, owner.id);

            for (const filter of [{ type: 'INCOME' }, { search: 'x' }, { memberId: owner.id }, { accountId: 'none' }]) {
                const result = await list(book.id, filter);
                expect(result.runningBalance.available).toBe(false);
                expect(result.data.every((e) => e.runningBalance === null)).toBe(true);
            }
        });
    });

    describe('filters', () => {
        it('narrows by type, person, wallet, text and date — together', async () => {
            const { owner, workspace, book } = await setup();
            const colleague = await createUser();
            const wallet = await createAccount(workspace.id);

            const target = await addEntry(book.id, colleague.id, {
                type: EntryType.EXPENSE, amount: '25000', description: 'Fuel for van', date: day(10),
            });
            await linkToWallet(target, workspace.id, wallet.id);
            await addEntry(book.id, colleague.id, { type: EntryType.INCOME, description: 'Fuel refund', date: day(10) });
            await addEntry(book.id, owner.id, { type: EntryType.EXPENSE, description: 'Fuel for van', date: day(10) });
            await addEntry(book.id, colleague.id, { type: EntryType.EXPENSE, description: 'Fuel for van', date: day(20) });

            const result = await list(book.id, {
                type: 'EXPENSE',
                memberId: colleague.id,
                accountId: wallet.id,
                search: 'fuel',
                startDate: day(1).toISOString(),
                endDate: day(15).toISOString(),
            });
            expect(result.data.map((e) => e.id)).toEqual([target.id]);
        });

        it('finds an exact amount, with or without thousands separators', async () => {
            const { owner, book } = await setup();
            const match = await addEntry(book.id, owner.id, { amount: '25000' });
            await addEntry(book.id, owner.id, { amount: '2500' });

            expect((await list(book.id, { search: '25,000' })).data.map((e) => e.id)).toEqual([match.id]);
        });

        it("separates book cash from a wallet's entries", async () => {
            const { owner, workspace, book } = await setup();
            const wallet = await createAccount(workspace.id);
            const linked = await addEntry(book.id, owner.id);
            await linkToWallet(linked, workspace.id, wallet.id);
            const cash = await addEntry(book.id, owner.id);

            expect((await list(book.id, { accountId: 'none' })).data.map((e) => e.id)).toEqual([cash.id]);
            expect((await list(book.id, { accountId: wallet.id })).data.map((e) => e.id)).toEqual([linked.id]);
        });
    });

    describe('totals', () => {
        it('cover every matching entry, count charges on income as money out, and skip reversals', async () => {
            const { owner, book } = await setup();
            for (let i = 0; i < 25; i++) await addEntry(book.id, owner.id, { amount: '100', date: day(1) });
            await addEntry(book.id, owner.id, { amount: '1000', charge: '20', date: day(2) });
            await addEntry(book.id, owner.id, { type: EntryType.EXPENSE, amount: '300', charge: '5', date: day(3) });
            await addEntry(book.id, owner.id, { amount: '9999', date: day(4), status: EntryStatus.REVERSED });

            // One page of 10, but the totals are for all 27 live entries.
            const result = await list(book.id, { limit: 10, includeReversed: 'true' });
            expect(result.summary).toEqual({
                moneyIn: '3500',       // 25 × 100 + 1000
                moneyOut: '325',       // 20 charge + 300 + 5
                net: '3175',
                count: 27,
            });
        });
    });

    describe('filter options', () => {
        it('lists who can reach the book and who has posted, and the wallets used', async () => {
            const { owner, workspace, book } = await setup();
            const bookMember = await createUser();
            const admin = await createUser();
            const outsider = await createUser();
            const former = await createUser();
            await addWorkspaceMember(workspace.id, bookMember.id, WorkspaceRole.MEMBER);
            await addWorkspaceMember(workspace.id, admin.id, WorkspaceRole.ADMIN);
            await addWorkspaceMember(workspace.id, outsider.id, WorkspaceRole.MEMBER);
            await testPrisma.cashbookMember.create({
                data: { cashbookId: book.id, userId: bookMember.id, role: 'DATA_OPERATOR' },
            });

            const wallet = await createAccount(workspace.id, { name: 'MTN MoMo' });
            const e1 = await addEntry(book.id, bookMember.id);
            await linkToWallet(e1, workspace.id, wallet.id);
            await addEntry(book.id, bookMember.id);
            // Posted, then lost access: their entries are still in the book.
            await addEntry(book.id, former.id);

            const options = await service().getEntryFilterOptions(book.id, true);
            const byId = new Map(options.members.map((m) => [m.id, m]));

            expect(byId.get(bookMember.id)).toMatchObject({ entryCount: 2, hasAccess: true, role: 'DATA_OPERATOR' });
            expect(byId.get(admin.id)).toMatchObject({ entryCount: 0, hasAccess: true, role: 'ADMIN' });
            expect(byId.get(owner.id)).toMatchObject({ hasAccess: true, role: 'OWNER' });
            expect(byId.get(former.id)).toMatchObject({ entryCount: 1, hasAccess: false });
            expect(byId.has(outsider.id)).toBe(false);
            expect(options.members[0].id).toBe(bookMember.id); // most active first

            expect(options.accounts).toEqual([{ id: wallet.id, name: 'MTN MoMo', archived: false, entryCount: 1 }]);
            expect(options.bookCashEntryCount).toBe(2);
        });

        it('shows only people whose entries are visible when the roster is not', async () => {
            const { workspace, book } = await setup();
            const poster = await createUser();
            const admin = await createUser();
            await addWorkspaceMember(workspace.id, admin.id, WorkspaceRole.ADMIN);
            await addEntry(book.id, poster.id);

            const options = await service().getEntryFilterOptions(book.id, false);
            expect(options.members.map((m) => m.id)).toEqual([poster.id]);
        });
    });
});

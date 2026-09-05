/**
 * What a workspace is born with: wallets and its first cashbook.
 *
 * A new user — local signup, OAuth signup, or a new business — should never
 * have to learn what an account type is before recording their first
 * wallet-linked entry, nor what a cashbook is before their first entry. These
 * tests pin the seeds per currency: the wallets are the ways money is
 * actually held where that currency circulates (M-Pesa in Kenya, MTN MoMo in
 * Uganda, PayPal for USD, ...), plus the universal Bank and Cash on Hand,
 * and one "Cash Journal {year}" book.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { Prisma } from '@prisma/client';
import { resetDatabase, testPrisma } from '../setup';
import { resolveService } from '../container';
import { AuthService } from '../../modules/auth/auth.service';
import { WorkspacesService } from '../../modules/workspaces/workspaces.service';
import {
    seedDefaultWalletAccounts,
    seedDefaultCashbook,
} from '../../core/ledger/coa.seed';
import { WALLET_SEEDS_BY_CURRENCY } from '../../core/ledger/coa.template';
import { createWorkspace, createUser } from '../factories';

const auth = () => resolveService(AuthService);
const workspaces = () => resolveService(WorkspacesService);

/** The seeded wallet names for a currency, as the template promises. */
async function expectSeededWallets(workspaceId: string, currency: string) {
    const expected = WALLET_SEEDS_BY_CURRENCY[currency];
    expect(expected).toBeDefined();

    const accounts = await testPrisma.account.findMany({
        where: { workspaceId },
        include: { accountType: true },
        orderBy: { name: 'asc' },
    });

    expect(accounts.map((a: any) => a.name).sort())
        .toEqual(expected.map((w) => w.name).sort());

    for (const account of accounts) {
        expect(account.balance.toString()).toBe('0');
        expect(account.currency).toBe(currency);
        // Every seeded wallet is a real bookkeeping object: it carries a
        // ledger account, so movements post journal lines from day one.
        expect(account.ledgerAccountId).not.toBeNull();
        expect(account.accountType.classification).toBe('ASSET');

        // ...and each landed under its promised account type and icon.
        const seed = expected.find((w) => w.name === account.name)!;
        expect(account.accountType.name).toBe(seed.accountTypeName);
        expect(account.icon).toBe(seed.icon);
    }
}

/** The workspace is born with exactly one "Cash Journal {year}" book, wired
 *  to its ledger account. */
async function expectSeededCashbook(workspaceId: string, currency: string) {
    const year = new Date().getFullYear();
    const cashbooks = await testPrisma.cashbook.findMany({
        where: { workspaceId },
    });
    expect(cashbooks).toHaveLength(1);
    expect(cashbooks[0].name).toBe(`Cash Journal ${year}`);
    expect(cashbooks[0].currency).toBe(currency);
    expect(cashbooks[0].cashLedgerAccountId).not.toBeNull();
}

async function trialBalance(): Promise<string> {
    const rows = await testPrisma.journalLine.aggregate({ _sum: { debit: true, credit: true } });
    return new Prisma.Decimal(rows._sum.debit ?? 0).sub(rows._sum.credit ?? 0).toString();
}

describe('default wallet seeding', () => {
    beforeEach(resetDatabase);

    it('a local signup gets the wallets and cashbook with its personal workspace', async () => {
        await auth().register({
            email: 'new-user@test.local',
            password: 'Password1!',
            firstName: 'New',
            lastName: 'User',
        });

        const user = await testPrisma.user.findUniqueOrThrow({
            where: { email: 'new-user@test.local' },
        });
        const ws = await testPrisma.workspace.findFirstOrThrow({
            where: { ownerId: user.id, type: 'PERSONAL' },
        });

        await expectSeededWallets(ws.id, 'UGX');
        await expectSeededCashbook(ws.id, 'UGX');

        // The workspace is born ready to book: chart of accounts and default
        // account types arrived alongside the wallets.
        const chart = await testPrisma.ledgerAccount.count({ where: { workspaceId: ws.id } });
        expect(chart).toBeGreaterThan(0);
        const types = await testPrisma.accountType.count({ where: { workspaceId: ws.id } });
        expect(types).toBe(6);

        // Seeding posts nothing — no opening balances, journals stay flat.
        expect(await trialBalance()).toBe('0');
    });

    it('the signup country decides the personal workspace currency and its wallets', async () => {
        await auth().register({
            email: 'kenyan@test.local',
            password: 'Password1!',
            firstName: 'Ken',
            lastName: 'Yan',
            country: 'KE',
        });

        const user = await testPrisma.user.findUniqueOrThrow({
            where: { email: 'kenyan@test.local' },
        });
        const ws = await testPrisma.workspace.findFirstOrThrow({
            where: { ownerId: user.id, type: 'PERSONAL' },
        });

        expect(ws.defaultCurrency).toBe('KES');
        await expectSeededWallets(ws.id, 'KES');
        await expectSeededCashbook(ws.id, 'KES');
    });

    it('every supported currency seeds its own wallets — the researched set', async () => {
        const owner = await createUser();
        for (const [currency, seeds] of Object.entries(WALLET_SEEDS_BY_CURRENCY)) {
            const ws = await workspaces().createBusinessWorkspace(owner.id, {
                name: `Biz ${currency}`,
                type: 'BUSINESS',
                defaultCurrency: currency,
            } as any);

            await expectSeededWallets(ws.id, currency);
            await expectSeededCashbook(ws.id, currency);

            // USD is an online-money currency: PayPal rides the Digital
            // Wallet type, and no mobile money is seeded.
            if (currency === 'USD') {
                const accounts = await testPrisma.account.findMany({
                    where: { workspaceId: ws.id },
                    include: { accountType: true },
                });
                expect(accounts.some((a: any) => a.accountType.name === 'Digital Wallet')).toBe(true);
                expect(accounts.some((a: any) => a.accountType.name === 'Mobile Money')).toBe(false);
            }

            // Every currency's set carries the universal pair.
            expect(seeds.some((s) => s.name === 'Bank')).toBe(true);
            expect(seeds.some((s) => s.name === 'Cash on Hand')).toBe(true);
        }
    });

    it('a USD-based business is accepted and seeds PayPal, Bank, and Cash on Hand', async () => {
        const owner = await createUser();
        const ws = await workspaces().createBusinessWorkspace(owner.id, {
            name: 'Dollar Biz',
            type: 'BUSINESS',
            defaultCurrency: 'USD',
        } as any);

        expect(ws.defaultCurrency).toBe('USD');
        const accounts = await testPrisma.account.findMany({
            where: { workspaceId: ws.id },
            orderBy: { name: 'asc' },
        });
        expect(accounts.map((a: any) => a.name)).toEqual(['Bank', 'Cash on Hand', 'PayPal']);
        await expectSeededCashbook(ws.id, 'USD');
    });

    it('seeding is idempotent — running it again creates nothing new', async () => {
        const user = await createUser();
        const ws = await createWorkspace(user.id);

        await seedDefaultWalletAccounts(testPrisma, ws.id, 'UGX', user.id);
        await seedDefaultCashbook(testPrisma, ws.id, 'UGX', user.id);
        await seedDefaultWalletAccounts(testPrisma, ws.id, 'UGX', user.id);
        await seedDefaultCashbook(testPrisma, ws.id, 'UGX', user.id);

        expect(await testPrisma.account.count({ where: { workspaceId: ws.id } })).toBe(4);
        expect(await testPrisma.cashbook.count({ where: { workspaceId: ws.id } })).toBe(1);
    });

    it('an account the user already made under the same name is left alone', async () => {
        const user = await createUser();
        const ws = await createWorkspace(user.id);

        // The user created their own "Bank" account with a balance before any
        // seed ran — e.g. an older workspace, or a re-run after manual setup.
        await testPrisma.accountType.create({
            data: { workspaceId: ws.id, name: 'Bank', classification: 'ASSET' },
        });
        const bankType = await testPrisma.accountType.findUniqueOrThrow({
            where: { name_workspaceId: { name: 'Bank', workspaceId: ws.id } },
        });
        const existingBank = await testPrisma.account.create({
            data: {
                workspaceId: ws.id,
                accountTypeId: bankType.id,
                name: 'Bank',
                currency: 'UGX',
                balance: new Prisma.Decimal('50000'),
            },
        });

        await seedDefaultWalletAccounts(testPrisma, ws.id, 'UGX', user.id);

        // The other wallets arrived; the user's Bank row is untouched — same
        // id, same balance, and no ledger account bolted onto it behind their
        // back.
        const accounts = await testPrisma.account.findMany({
            where: { workspaceId: ws.id },
        });
        expect(accounts.map((a: any) => a.name).sort()).toEqual(
            ['Airtel Money', 'Bank', 'Cash on Hand', 'MTN MoMo'].sort(),
        );
        const bank = accounts.find((a: any) => a.name === 'Bank')!;
        expect(bank.id).toBe(existingBank.id);
        expect(bank.balance.toString()).toBe('50000');
        expect(bank.ledgerAccountId).toBeNull();
    });

    it('the cashbook seed leaves a workspace with an existing book untouched', async () => {
        const user = await createUser();
        const ws = await createWorkspace(user.id);

        await testPrisma.cashbook.create({
            data: {
                name: 'My Own Ledger',
                currency: 'UGX',
                workspaceId: ws.id,
            },
        });

        await seedDefaultCashbook(testPrisma, ws.id, 'UGX', user.id);

        const cashbooks = await testPrisma.cashbook.findMany({
            where: { workspaceId: ws.id },
        });
        expect(cashbooks.map((c: any) => c.name)).toEqual(['My Own Ledger']);
    });
});

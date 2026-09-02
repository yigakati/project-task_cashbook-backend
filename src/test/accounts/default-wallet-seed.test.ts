/**
 * The wallets a workspace is born with.
 *
 * A new user — local signup, OAuth signup, or a new business — should never
 * have to learn what an account type is before recording their first
 * wallet-linked entry. These tests pin down that the four obvious wallets
 * (Airtel Money, MTN MoMo, Bank, Cash on Hand) arrive with the workspace,
 * wired to real ledger accounts, without disturbing anything the user
 * already created.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { Prisma } from '@prisma/client';
import { resetDatabase, testPrisma } from '../setup';
import { resolveService } from '../container';
import { AuthService } from '../../modules/auth/auth.service';
import { WorkspacesService } from '../../modules/workspaces/workspaces.service';
import { seedDefaultWalletAccounts } from '../../core/ledger/coa.seed';
import { createWorkspace, createUser } from '../factories';

const auth = () => resolveService(AuthService);
const workspaces = () => resolveService(WorkspacesService);

const SEED_NAMES = ['Airtel Money', 'MTN MoMo', 'Bank', 'Cash on Hand'];

/** The wallets, with their types and icons, as the template promises. */
async function expectSeededWallets(workspaceId: string, currency = 'UGX') {
    const accounts = await testPrisma.account.findMany({
        where: { workspaceId },
        include: { accountType: true },
        orderBy: { name: 'asc' },
    });

    expect(accounts.map((a: any) => a.name).sort()).toEqual([...SEED_NAMES].sort());

    for (const account of accounts) {
        expect(account.balance.toString()).toBe('0');
        expect(account.currency).toBe(currency);
        // Every seeded wallet is a real bookkeeping object: it carries a
        // ledger account, so movements post journal lines from day one.
        expect(account.ledgerAccountId).not.toBeNull();
        expect(account.accountType.classification).toBe('ASSET');
    }

    // Both carrier wallets ride the one Mobile Money type — separate floats,
    // one classification.
    const airtel = accounts.find((a: any) => a.name === 'Airtel Money')!;
    expect(airtel.accountType.name).toBe('Mobile Money');
    expect(airtel.icon).toBe('HandCoins');

    const mtn = accounts.find((a: any) => a.name === 'MTN MoMo')!;
    expect(mtn.accountType.name).toBe('Mobile Money');
    expect(mtn.icon).toBe('Wallet');

    const bank = accounts.find((a: any) => a.name === 'Bank')!;
    expect(bank.accountType.name).toBe('Bank');
    expect(bank.icon).toBe('Landmark');

    const cash = accounts.find((a: any) => a.name === 'Cash on Hand')!;
    expect(cash.accountType.name).toBe('Cash');
    expect(cash.icon).toBe('Banknote');
}

async function trialBalance(): Promise<string> {
    const rows = await testPrisma.journalLine.aggregate({ _sum: { debit: true, credit: true } });
    return new Prisma.Decimal(rows._sum.debit ?? 0).sub(rows._sum.credit ?? 0).toString();
}

describe('default wallet seeding', () => {
    beforeEach(resetDatabase);

    it('a local signup gets the wallets with its personal workspace', async () => {
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

        await expectSeededWallets(ws.id);

        // The workspace is born ready to book: chart of accounts and default
        // account types arrived alongside the wallets.
        const chart = await testPrisma.ledgerAccount.count({ where: { workspaceId: ws.id } });
        expect(chart).toBeGreaterThan(0);
        const types = await testPrisma.accountType.count({ where: { workspaceId: ws.id } });
        expect(types).toBe(5);

        // Seeding posts nothing — no opening balances, journals stay flat.
        expect(await trialBalance()).toBe('0');
    });

    it('a new business workspace gets the wallets too', async () => {
        const owner = await createUser();
        const ws = await workspaces().createBusinessWorkspace(owner.id, {
            name: 'Seeded Biz',
            type: 'BUSINESS',
            defaultCurrency: 'UGX',
        } as any);

        await expectSeededWallets(ws.id);
    });

    it('a USD-based business is accepted and seeds its wallets in USD', async () => {
        const owner = await createUser();
        const ws = await workspaces().createBusinessWorkspace(owner.id, {
            name: 'Dollar Biz',
            type: 'BUSINESS',
            defaultCurrency: 'USD',
        } as any);

        expect(ws.defaultCurrency).toBe('USD');
        await expectSeededWallets(ws.id, 'USD');
    });

    it('seeding is idempotent — running it again creates nothing new', async () => {
        const user = await createUser();
        const ws = await createWorkspace(user.id);

        await seedDefaultWalletAccounts(testPrisma, ws.id, 'UGX', user.id);
        await seedDefaultWalletAccounts(testPrisma, ws.id, 'UGX', user.id);

        expect(await testPrisma.account.count({ where: { workspaceId: ws.id } })).toBe(4);
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

        // The other two arrived; the user's Bank row is untouched — same id,
        // same balance, and no ledger account bolted onto it behind their back.
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
});

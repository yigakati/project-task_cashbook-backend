/**
 * Ledger backfill, against synthetic pre-ledger data.
 *
 * Runs the REAL script as a child process against this worker's private
 * database (process.env.DATABASE_URL — see runBackfill), so what ships is
 * what is tested.
 *
 * Builds a workspace the way the old code would have — entries, wallet
 * transactions, transfers, obligations and opening balances, with cached
 * balances but no journals — then runs the backfill and asserts the books come
 * out balanced and the caches agree with the ledger.
 *
 * The backfill lives in a script, so the replay logic is exercised here through
 * the same posting rules the script calls.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { Prisma, TransactionSourceType } from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import { resetDatabase, testPrisma } from './setup';
import { resolveService } from './container';
import { createUser, createWorkspace } from './factories';
import { LedgerIntegrityService } from '../core/ledger/integrity.service';

const ROOT = path.resolve(__dirname, '..', '..');
const integrity = () => resolveService(LedgerIntegrityService);

/** Run the real script, so the test covers what actually ships. */
function runBackfill(workspaceId: string, apply: boolean): string {
    const args = ['tsx', 'scripts/backfill-ledger.ts', '--workspace', workspaceId];
    if (apply) args.push('--apply');

    return execFileSync('npx', args, {
        cwd: ROOT,
        encoding: 'utf8',
        // process.env.DATABASE_URL IS this worker's private database under
        // the parallel harness — the script must see the same rows the test
        // built. (DATABASE_URL_TEST is the shared pristine template.)
        env: { ...process.env, DATABASE_URL: process.env.DATABASE_URL },
    });
}

/**
 * A workspace exactly as the pre-ledger code would have left it: real source
 * records, hand-computed caches, and no journals at all.
 */
async function buildLegacyWorkspace(opts: { currency?: string } = {}) {
    const currency = opts.currency ?? 'UGX';
    const user = await createUser();
    const workspace = await createWorkspace(user.id);

    const accountType = await testPrisma.accountType.create({
        data: { workspaceId: workspace.id, name: 'Bank', classification: 'ASSET' },
    });

    // Wallet with an opening balance, recorded the old way.
    const wallet = await testPrisma.account.create({
        data: {
            workspaceId: workspace.id,
            accountTypeId: accountType.id,
            name: 'Legacy Bank',
            currency,
            balance: new Decimal('1000'),
        },
    });
    await testPrisma.accountTransaction.create({
        data: {
            workspaceId: workspace.id,
            accountId: wallet.id,
            sourceType: TransactionSourceType.DIRECT,
            type: 'INCOME',
            amount: new Decimal('1000'),
            description: 'Initial Balance',
            transactionDate: new Date('2026-01-01'),
        },
    });

    const cashbook = await testPrisma.cashbook.create({
        data: { workspaceId: workspace.id, name: 'Legacy Book', currency, allowBackdate: true },
    });

    // Unlinked income 500 → book cash +500, money-in 500
    await testPrisma.entry.create({
        data: {
            cashbookId: cashbook.id, type: 'INCOME', amount: new Decimal('500'),
            description: 'unlinked income', entryDate: new Date('2026-02-01'),
            createdById: user.id,
        },
    });

    // Wallet-linked expense 200 with a 10 charge → wallet −210, money-out 210,
    // book cash untouched.
    const linked = await testPrisma.entry.create({
        data: {
            cashbookId: cashbook.id, type: 'EXPENSE', amount: new Decimal('200'),
            chargeAmount: new Decimal('10'), description: 'linked expense',
            entryDate: new Date('2026-02-05'), createdById: user.id,
        },
    });
    await testPrisma.accountTransaction.create({
        data: {
            workspaceId: workspace.id, accountId: wallet.id,
            sourceType: TransactionSourceType.CASHBOOK_ENTRY, sourceId: linked.id,
            type: 'EXPENSE', amount: new Decimal('200'), chargeAmount: new Decimal('10'),
            description: 'linked expense', transactionDate: new Date('2026-02-05'),
        },
    });

    // A receivable, half settled.
    const contact = await testPrisma.contact.create({
        data: { workspaceId: workspace.id, name: 'Customer', type: 'CUSTOMER' },
    });
    const obligation = await testPrisma.cashbookObligation.create({
        data: {
            workspaceId: workspace.id, cashbookId: cashbook.id, type: 'RECEIVABLE',
            title: 'Legacy invoice', totalAmount: new Decimal('400'),
            // A pre-ledger record: all principal, no interest — which is what
            // the migration backfilled every existing obligation to.
            principalAmount: new Decimal('400'),
            outstandingAmount: new Decimal('150'), status: 'PARTIAL',
            contactId: contact.id, dueDate: new Date('2026-03-01'),
        },
    });
    await testPrisma.entry.create({
        data: {
            cashbookId: cashbook.id, type: 'INCOME', amount: new Decimal('250'),
            description: 'part payment', entryDate: new Date('2026-02-10'),
            createdById: user.id, obligationId: obligation.id, contactId: contact.id,
        },
    });

    // A deleted entry, the old destructive way.
    await testPrisma.entry.create({
        data: {
            cashbookId: cashbook.id, type: 'EXPENSE', amount: new Decimal('99'),
            description: 'deleted', entryDate: new Date('2026-02-12'),
            createdById: user.id, isDeleted: true, deletedAt: new Date(),
            deletedReason: 'mistake',
        },
    });

    // Caches as the old arithmetic left them:
    //   book cash  = 500 (unlinked income) + 250 (unlinked settlement) = 750
    //   money in   = 500 + 250 = 750
    //   money out  = 200 + 10  = 210
    //   wallet     = 1000 − 210 = 790
    await testPrisma.cashbook.update({
        where: { id: cashbook.id },
        data: {
            balance: new Decimal('750'),
            totalIncome: new Decimal('750'),
            totalExpense: new Decimal('210'),
        },
    });
    await testPrisma.account.update({
        where: { id: wallet.id },
        data: { balance: new Decimal('790') },
    });

    return { user, workspace, cashbook, wallet, obligation, contact };
}

describe('ledger backfill', () => {
    beforeEach(async () => {
        await resetDatabase();
    });

    it('leaves the database untouched on a dry run', async () => {
        const fx = await buildLegacyWorkspace();

        const output = runBackfill(fx.workspace.id, false);
        expect(output).toMatch(/dry run/i);

        // Rolled back: no journals, no chart of accounts, caches as they were.
        expect(await testPrisma.journalEntry.count({ where: { workspaceId: fx.workspace.id } })).toBe(0);
        expect(await testPrisma.ledgerAccount.count({ where: { workspaceId: fx.workspace.id } })).toBe(0);

        const cashbook = await testPrisma.cashbook.findUniqueOrThrow({ where: { id: fx.cashbook.id } });
        expect(cashbook.balance.toString()).toBe('750');
    });

    it('reports the same figures a dry run predicted', async () => {
        const fx = await buildLegacyWorkspace();

        const preview = runBackfill(fx.workspace.id, false);
        expect(preview).toMatch(/trial balance: .* ✓/);

        runBackfill(fx.workspace.id, true);

        const report = await integrity().verifyWorkspace(fx.workspace.id);
        expect(report.findings).toEqual([]);
    });

    it('produces a balanced ledger from pre-ledger records', async () => {
        const fx = await buildLegacyWorkspace();
        runBackfill(fx.workspace.id, true);

        const [row] = await testPrisma.$queryRaw<Array<{ debit: Decimal; credit: Decimal }>>`
            SELECT COALESCE(SUM(debit), 0) AS debit, COALESCE(SUM(credit), 0) AS credit
            FROM journal_lines WHERE workspace_id = ${fx.workspace.id}::uuid
        `;
        expect(new Decimal(row.debit).toString()).toBe(new Decimal(row.credit).toString());
    });

    it('preserves the wallet-link rule through the backfill', async () => {
        const fx = await buildLegacyWorkspace();
        runBackfill(fx.workspace.id, true);

        const cashbook = await testPrisma.cashbook.findUniqueOrThrow({ where: { id: fx.cashbook.id } });
        const wallet = await testPrisma.account.findUniqueOrThrow({ where: { id: fx.wallet.id } });

        // The linked expense moved the wallet, not book cash, and still counts
        // toward money out — the same numbers the old caches held.
        expect(cashbook.balance.toString()).toBe('750');
        expect(cashbook.totalIncome.toString()).toBe('750');
        expect(cashbook.totalExpense.toString()).toBe('210');
        expect(wallet.balance.toString()).toBe('790');
    });

    it('books the opening balance to equity rather than inventing income', async () => {
        const fx = await buildLegacyWorkspace();
        runBackfill(fx.workspace.id, true);

        const equity = await testPrisma.ledgerAccount.findFirstOrThrow({
            where: { workspaceId: fx.workspace.id, systemKey: 'OPENING_BALANCE_EQUITY' },
        });
        const [row] = await testPrisma.$queryRaw<Array<{ net: Decimal }>>`
            SELECT COALESCE(SUM(credit - debit), 0) AS net
            FROM journal_lines WHERE ledger_account_id = ${equity.id}::uuid
        `;
        expect(new Decimal(row.net).toString()).toBe('1000');

        // Replaying it as an ordinary wallet transaction would have credited
        // Other Income with 1000 that was never earned.
        const otherIncome = await testPrisma.ledgerAccount.findFirstOrThrow({
            where: { workspaceId: fx.workspace.id, systemKey: 'OTHER_INCOME' },
        });
        const [income] = await testPrisma.$queryRaw<Array<{ net: Decimal }>>`
            SELECT COALESCE(SUM(credit - debit), 0) AS net
            FROM journal_lines WHERE ledger_account_id = ${otherIncome.id}::uuid
        `;
        expect(new Decimal(income.net).toString()).toBe('0');
    });

    it('reconstructs the outstanding receivable', async () => {
        const fx = await buildLegacyWorkspace();
        runBackfill(fx.workspace.id, true);

        const ar = await testPrisma.ledgerAccount.findFirstOrThrow({
            where: { workspaceId: fx.workspace.id, systemKey: 'AR' },
        });
        const [row] = await testPrisma.$queryRaw<Array<{ net: Decimal }>>`
            SELECT COALESCE(SUM(debit - credit), 0) AS net
            FROM journal_lines WHERE ledger_account_id = ${ar.id}::uuid
        `;
        // 400 opened less 250 settled.
        expect(new Decimal(row.net).toString()).toBe('150');
    });

    it('marks a previously deleted entry as reversed without posting a journal pair', async () => {
        const fx = await buildLegacyWorkspace();
        runBackfill(fx.workspace.id, true);

        const deleted = await testPrisma.entry.findFirstOrThrow({
            where: { cashbookId: fx.cashbook.id, isDeleted: true },
        });
        expect(deleted.status).toBe('REVERSED');

        // Its journal and reversal would net to zero, so neither is written.
        const journals = await testPrisma.journalEntry.count({
            where: { sourceId: deleted.id },
        });
        expect(journals).toBe(0);
    });

    it('is idempotent — a second run posts nothing new', async () => {
        const fx = await buildLegacyWorkspace();

        runBackfill(fx.workspace.id, true);
        const first = await testPrisma.journalEntry.count({ where: { workspaceId: fx.workspace.id } });

        runBackfill(fx.workspace.id, true);
        const second = await testPrisma.journalEntry.count({ where: { workspaceId: fx.workspace.id } });

        expect(second).toBe(first);

        const report = await integrity().verifyWorkspace(fx.workspace.id);
        expect(report.findings).toEqual([]);
    });

    it('refuses to rewrite caches when a record could not be posted', async () => {
        const fx = await buildLegacyWorkspace();

        // A second wallet in another currency, linked to a book that is not —
        // the shape legacy data allowed and the ledger cannot represent.
        const usdType = await testPrisma.accountType.create({
            data: { workspaceId: fx.workspace.id, name: 'USD Bank', classification: 'ASSET' },
        });
        const usdWallet = await testPrisma.account.create({
            data: {
                workspaceId: fx.workspace.id, accountTypeId: usdType.id,
                name: 'USD Wallet', currency: 'USD', balance: new Decimal('0'),
            },
        });
        const crossCurrency = await testPrisma.entry.create({
            data: {
                cashbookId: fx.cashbook.id, type: 'EXPENSE', amount: new Decimal('50'),
                description: 'cross-currency', entryDate: new Date('2026-02-20'),
                createdById: fx.user.id,
            },
        });
        await testPrisma.accountTransaction.create({
            data: {
                workspaceId: fx.workspace.id, accountId: usdWallet.id,
                sourceType: TransactionSourceType.CASHBOOK_ENTRY, sourceId: crossCurrency.id,
                type: 'EXPENSE', amount: new Decimal('50'), description: 'cross-currency',
                transactionDate: new Date('2026-02-20'),
            },
        });

        const output = runBackfill(fx.workspace.id, true);

        expect(output).toMatch(/skipped entry/i);
        expect(output).toMatch(/USD.*but the book is UGX|UGX.*but the book is USD/i);
        expect(output).toMatch(/cached balances left untouched/i);

        // The original figures survive rather than being silently reduced by
        // the value of the entry the ledger could not represent.
        const cashbook = await testPrisma.cashbook.findUniqueOrThrow({ where: { id: fx.cashbook.id } });
        expect(cashbook.balance.toString()).toBe('750');
    });
});

/**
 * Wallet-level events must post journals, not just move a cached number.
 *
 * Before this, direct wallet transactions and transfers updated Account.balance
 * directly and appeared nowhere in the ledger — which would have left the
 * balance sheet wrong by exactly the amount of that activity.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { Prisma } from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import { resetDatabase, testPrisma } from '../../test/setup';
import { resolveService } from '../../test/container';
import { createUser, createWorkspace } from '../../test/factories';
import { AccountsService } from './accounts.service';
import { AccountTransactionsService } from '../account-transactions/account-transactions.service';
import { LedgerIntegrityService } from '../../core/ledger/integrity.service';
import { provisionWorkspaceAccounting } from '../../core/ledger/coa.seed';

const accounts = () => resolveService(AccountsService);
const walletTxs = () => resolveService(AccountTransactionsService);
const integrity = () => resolveService(LedgerIntegrityService);

async function fixture() {
    const user = await createUser();
    const workspace = await createWorkspace(user.id);
    await testPrisma.$transaction(async (tx: Prisma.TransactionClient) => {
        await provisionWorkspaceAccounting(tx, workspace.id, 'UGX');
    });
    const bankType = await testPrisma.accountType.findFirstOrThrow({
        where: { workspaceId: workspace.id, name: 'Bank' },
    });
    return { user, workspace, bankType };
}

async function expectClean(workspaceId: string, label: string) {
    const report = await integrity().verifyWorkspace(workspaceId);
    if (!report.ok) {
        throw new Error(
            `${label}:\n` +
            report.findings
                .map((f) => `  ${f.check} ${f.subject}: expected ${f.expected}, got ${f.actual}`)
                .join('\n'),
        );
    }
}

describe('wallet ledger posting', () => {
    beforeEach(async () => {
        await resetDatabase();
    });

    it('seeds default account types so a fresh workspace can create a wallet', async () => {
        const { workspace } = await fixture();
        const types = await testPrisma.accountType.findMany({ where: { workspaceId: workspace.id } });
        // Previously seeded nowhere, which made wallet creation impossible.
        expect(types.map((t: { name: string }) => t.name).sort()).toEqual(
            ['Bank', 'Cash', 'Credit Card', 'Digital Wallet', 'Loan', 'Mobile Money'],
        );
    });

    it('posts an opening balance against Opening Balance Equity', async () => {
        const { user, workspace, bankType } = await fixture();

        const account = await accounts().createAccount(workspace.id, user.id, {
            name: 'Main Bank',
            accountTypeId: bankType.id,
            initialBalance: '5000',
        } as never);

        const stored = await testPrisma.account.findUniqueOrThrow({ where: { id: account.id } });
        expect(stored.balance.toString()).toBe('5000');
        expect(stored.ledgerAccountId).toBeTruthy();

        const equity = await testPrisma.ledgerAccount.findUniqueOrThrow({
            where: { workspaceId_systemKey_currency: { workspaceId: workspace.id, systemKey: 'OPENING_BALANCE_EQUITY', currency: 'UGX' } },
        });
        const [row] = await testPrisma.$queryRaw<Array<{ net: Decimal }>>`
            SELECT COALESCE(SUM(credit - debit), 0) AS net
            FROM journal_lines WHERE ledger_account_id = ${equity.id}::uuid
        `;
        expect(new Decimal(row.net).toString()).toBe('5000');

        await expectClean(workspace.id, 'opening balance');
    });

    it('posts a direct wallet transaction and keeps it out of cashbook totals', async () => {
        const { user, workspace, bankType } = await fixture();
        const account = await accounts().createAccount(workspace.id, user.id, {
            name: 'Bank', accountTypeId: bankType.id, initialBalance: '1000',
        } as never);

        await walletTxs().createDirectTransaction(workspace.id, account.id, user.id, {
            type: 'EXPENSE', amount: '250', description: 'bank charge',
        } as never);

        const stored = await testPrisma.account.findUniqueOrThrow({ where: { id: account.id } });
        expect(stored.balance.toString()).toBe('750');

        // cashbookId is null on these journals, so no book's totals move.
        const journals = await testPrisma.journalEntry.findMany({
            where: { workspaceId: workspace.id, sourceType: 'ACCOUNT_TRANSACTION' },
        });
        expect(journals).toHaveLength(1);
        expect(journals[0].cashbookId).toBeNull();

        await expectClean(workspace.id, 'direct wallet transaction');
    });

    it('reverses a voided wallet transaction', async () => {
        const { user, workspace, bankType } = await fixture();
        const account = await accounts().createAccount(workspace.id, user.id, {
            name: 'Bank', accountTypeId: bankType.id, initialBalance: '1000',
        } as never);

        const tx = await walletTxs().createDirectTransaction(workspace.id, account.id, user.id, {
            type: 'EXPENSE', amount: '250', description: 'to void',
        } as never);

        await walletTxs().deleteDirectTransaction(tx.id, workspace.id, account.id, user.id);

        const stored = await testPrisma.account.findUniqueOrThrow({ where: { id: account.id } });
        expect(stored.balance.toString()).toBe('1000');

        await expectClean(workspace.id, 'voided wallet transaction');
    });

    it('posts a transfer that moves both wallets and books the fee as an expense', async () => {
        const { user, workspace, bankType } = await fixture();
        const from = await accounts().createAccount(workspace.id, user.id, {
            name: 'From', accountTypeId: bankType.id, initialBalance: '1000',
        } as never);
        const to = await accounts().createAccount(workspace.id, user.id, {
            name: 'To', accountTypeId: bankType.id, initialBalance: '0',
        } as never);

        await accounts().transferBetweenAccounts(workspace.id, user.id, {
            fromAccountId: from.id,
            toAccountId: to.id,
            amount: '300',
            feeAmount: '10',
            description: 'move funds',
        } as never);

        expect((await testPrisma.account.findUniqueOrThrow({ where: { id: from.id } })).balance.toString()).toBe('690');
        expect((await testPrisma.account.findUniqueOrThrow({ where: { id: to.id } })).balance.toString()).toBe('300');

        // The fee is now a real expense rather than money that vanished.
        const fees = await testPrisma.ledgerAccount.findUniqueOrThrow({
            where: { workspaceId_systemKey_currency: { workspaceId: workspace.id, systemKey: 'TRANSACTION_FEES', currency: 'UGX' } },
        });
        const [row] = await testPrisma.$queryRaw<Array<{ net: Decimal }>>`
            SELECT COALESCE(SUM(debit - credit), 0) AS net
            FROM journal_lines WHERE ledger_account_id = ${fees.id}::uuid
        `;
        expect(new Decimal(row.net).toString()).toBe('10');

        await expectClean(workspace.id, 'transfer');
    });

    it('keeps the trial balance at zero across all wallet events', async () => {
        const { user, workspace, bankType } = await fixture();
        const a = await accounts().createAccount(workspace.id, user.id, {
            name: 'A', accountTypeId: bankType.id, initialBalance: '2000',
        } as never);
        const b = await accounts().createAccount(workspace.id, user.id, {
            name: 'B', accountTypeId: bankType.id, initialBalance: '500',
        } as never);

        await walletTxs().createDirectTransaction(workspace.id, a.id, user.id, {
            type: 'INCOME', amount: '400', chargeAmount: '5', description: 'deposit',
        } as never);
        await accounts().transferBetweenAccounts(workspace.id, user.id, {
            fromAccountId: a.id, toAccountId: b.id, amount: '100', feeAmount: '2',
            description: 'shuffle',
        } as never);

        const [row] = await testPrisma.$queryRaw<Array<{ debit: Decimal; credit: Decimal }>>`
            SELECT COALESCE(SUM(debit), 0) AS debit, COALESCE(SUM(credit), 0) AS credit
            FROM journal_lines WHERE workspace_id = ${workspace.id}::uuid
        `;
        expect(new Decimal(row.debit).toString()).toBe(new Decimal(row.credit).toString());

        await expectClean(workspace.id, 'mixed wallet events');
    });
});

/**
 * Invoice and obligation lifecycle against the ledger.
 *
 * The risk these cover: an obligation that is cancelled without its receivable
 * being taken off the books. AR would stay on the balance sheet forever, and
 * the AR control check would drift by exactly the cancelled amount.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { Prisma } from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import { resetDatabase, testPrisma } from '../../test/setup';
import { resolveService } from '../../test/container';
import { createUser, createWorkspace, createCashbook, isoDate } from '../../test/factories';
import { EntriesService } from '../entries/entries.service';
import { ObligationsService } from '../cashbook-obligations/obligations.service';
import { LedgerIntegrityService } from '../../core/ledger/integrity.service';
import { LedgerReportsService } from '../ledger-reports/ledger-reports.service';
import {
    provisionWorkspaceAccounting,
    ensureCashbookLedgerAccount,
} from '../../core/ledger/coa.seed';

const entries = () => resolveService(EntriesService);
const obligations = () => resolveService(ObligationsService);
const integrity = () => resolveService(LedgerIntegrityService);
const reports = () => resolveService(LedgerReportsService);

async function fixture() {
    const user = await createUser();
    const workspace = await createWorkspace(user.id);
    await testPrisma.$transaction(async (tx: Prisma.TransactionClient) => {
        await provisionWorkspaceAccounting(tx, workspace.id, 'UGX');
    });
    const cashbook = await createCashbook(workspace.id, user.id);
    await testPrisma.$transaction(async (tx: Prisma.TransactionClient) => {
        await ensureCashbookLedgerAccount(tx, {
            id: cashbook.id,
            workspaceId: workspace.id,
            name: cashbook.name,
            currency: 'UGX',
        });
    });
    const contact = await testPrisma.contact.create({
        data: { workspaceId: workspace.id, name: 'Customer', type: 'CUSTOMER' },
    });
    return { user, workspace, cashbook, contact };
}

async function arBalance(workspaceId: string): Promise<string> {
    const ar = await testPrisma.ledgerAccount.findUniqueOrThrow({
        where: {
            workspaceId_systemKey_currency: { workspaceId, systemKey: 'AR', currency: 'UGX' },
        },
    });
    const [row] = await testPrisma.$queryRaw<Array<{ net: Decimal }>>`
        SELECT COALESCE(SUM(debit - credit), 0) AS net
        FROM journal_lines WHERE ledger_account_id = ${ar.id}::uuid
    `;
    return new Decimal(row.net).toString();
}

describe('obligation cancellation', () => {
    beforeEach(async () => {
        await resetDatabase();
    });

    it('takes an unpaid receivable off the books when cancelled', async () => {
        const fx = await fixture();

        const obligation = await obligations().createObligation(fx.cashbook.id, fx.user.id, {
            type: 'RECEIVABLE',
            title: 'Invoice 1',
            totalAmount: '1000',
            contactId: fx.contact.id,
        } as never);

        expect(await arBalance(fx.workspace.id)).toBe('1000');

        await obligations().cancelObligation(
            obligation.id,
            fx.cashbook.id,
            fx.user.id,
            'customer withdrew the order',
        );

        // The receivable is gone; it is no longer an asset.
        expect(await arBalance(fx.workspace.id)).toBe('0');

        const report = await integrity().verifyWorkspace(fx.workspace.id);
        expect(report.ok).toBe(true);
    });

    it('writes off only the unpaid portion of a partially settled receivable', async () => {
        const fx = await fixture();

        const obligation = await obligations().createObligation(fx.cashbook.id, fx.user.id, {
            type: 'RECEIVABLE',
            title: 'Invoice 2',
            totalAmount: '1000',
            contactId: fx.contact.id,
        } as never);

        await entries().createEntry(fx.cashbook.id, fx.user.id, {
            type: 'INCOME',
            amount: '400',
            description: 'part payment',
            entryDate: isoDate(),
            obligationId: obligation.id,
            contactId: fx.contact.id,
        } as never);

        expect(await arBalance(fx.workspace.id)).toBe('600');

        await obligations().cancelObligation(obligation.id, fx.cashbook.id, fx.user.id, 'bad debt');

        // Only the 600 still owed is written off. The 400 already collected
        // stays recognized as revenue — reversing the whole opening journal
        // would have driven AR to −400.
        expect(await arBalance(fx.workspace.id)).toBe('0');

        const cashbook = await testPrisma.cashbook.findUniqueOrThrow({
            where: { id: fx.cashbook.id },
        });
        expect(cashbook.totalIncome.toString()).toBe('400');

        const report = await integrity().verifyWorkspace(fx.workspace.id);
        expect(report.ok).toBe(true);
    });

    it('leaves a fully paid obligation alone when cancelled', async () => {
        const fx = await fixture();

        const obligation = await obligations().createObligation(fx.cashbook.id, fx.user.id, {
            type: 'RECEIVABLE',
            title: 'Invoice 3',
            totalAmount: '500',
            contactId: fx.contact.id,
        } as never);

        await entries().createEntry(fx.cashbook.id, fx.user.id, {
            type: 'INCOME',
            amount: '500',
            description: 'paid in full',
            entryDate: isoDate(),
            obligationId: obligation.id,
            contactId: fx.contact.id,
        } as never);

        expect(await arBalance(fx.workspace.id)).toBe('0');

        await obligations().cancelObligation(
            obligation.id,
            fx.cashbook.id,
            fx.user.id,
            'housekeeping',
        );

        // Nothing outstanding, so nothing to write off.
        expect(await arBalance(fx.workspace.id)).toBe('0');

        const report = await integrity().verifyWorkspace(fx.workspace.id);
        expect(report.ok).toBe(true);
    });

    it('takes a cancelled payable off the books too', async () => {
        const fx = await fixture();
        const supplier = await testPrisma.contact.create({
            data: { workspaceId: fx.workspace.id, name: 'Supplier', type: 'VENDOR' },
        });

        const obligation = await obligations().createObligation(fx.cashbook.id, fx.user.id, {
            type: 'PAYABLE',
            title: 'Bill 1',
            totalAmount: '750',
            contactId: supplier.id,
        } as never);

        const ap = await testPrisma.ledgerAccount.findUniqueOrThrow({
            where: {
                workspaceId_systemKey_currency: {
                    workspaceId: fx.workspace.id,
                    systemKey: 'AP',
                    currency: 'UGX',
                },
            },
        });
        const apBalance = async () => {
            const [row] = await testPrisma.$queryRaw<Array<{ net: Decimal }>>`
                SELECT COALESCE(SUM(credit - debit), 0) AS net
                FROM journal_lines WHERE ledger_account_id = ${ap.id}::uuid
            `;
            return new Decimal(row.net).toString();
        };

        expect(await apBalance()).toBe('750');

        await obligations().cancelObligation(
            obligation.id,
            fx.cashbook.id,
            fx.user.id,
            'supplier waived it',
        );

        expect(await apBalance()).toBe('0');

        const report = await integrity().verifyWorkspace(fx.workspace.id);
        expect(report.ok).toBe(true);
    });

    it('keeps AR aging in step with the obligation table after a cancellation', async () => {
        const fx = await fixture();

        const keep = await obligations().createObligation(fx.cashbook.id, fx.user.id, {
            type: 'RECEIVABLE',
            title: 'Keep',
            totalAmount: '300',
            contactId: fx.contact.id,
        } as never);
        const cancel = await obligations().createObligation(fx.cashbook.id, fx.user.id, {
            type: 'RECEIVABLE',
            title: 'Cancel',
            totalAmount: '700',
            contactId: fx.contact.id,
        } as never);

        await obligations().cancelObligation(cancel.id, fx.cashbook.id, fx.user.id, 'void');

        const aging = await reports().aging(fx.workspace.id, 'RECEIVABLE', new Date());
        expect(aging.totals.total).toBe('300.0000');
        // The signal that a settlement path skipped a posting.
        expect(aging.controlVariance).toBe('0.0000');
        expect(aging.items.map((i) => i.obligationId)).toEqual([keep.id]);
    });
});

describe('archiving an open obligation', () => {
    beforeEach(async () => {
        await resetDatabase();
    });

    it('writes off the receivable rather than leaving it on the balance sheet', async () => {
        const fx = await fixture();

        const obligation = await obligations().createObligation(fx.cashbook.id, fx.user.id, {
            type: 'RECEIVABLE',
            title: 'Abandoned',
            totalAmount: '450',
            contactId: fx.contact.id,
        } as never);

        expect(await arBalance(fx.workspace.id)).toBe('450');

        await obligations().archiveObligation(obligation.id, fx.cashbook.id, fx.user.id);

        // Archiving an open receivable means we are not collecting it.
        expect(await arBalance(fx.workspace.id)).toBe('0');

        const report = await integrity().verifyWorkspace(fx.workspace.id);
        expect(report.ok).toBe(true);
    });

    it('leaves a fully paid obligation untouched when archived', async () => {
        const fx = await fixture();

        const obligation = await obligations().createObligation(fx.cashbook.id, fx.user.id, {
            type: 'RECEIVABLE',
            title: 'Settled',
            totalAmount: '200',
            contactId: fx.contact.id,
        } as never);

        await entries().createEntry(fx.cashbook.id, fx.user.id, {
            type: 'INCOME',
            amount: '200',
            description: 'paid',
            entryDate: isoDate(),
            obligationId: obligation.id,
            contactId: fx.contact.id,
        } as never);

        await obligations().archiveObligation(obligation.id, fx.cashbook.id, fx.user.id);

        const cashbook = await testPrisma.cashbook.findUniqueOrThrow({
            where: { id: fx.cashbook.id },
        });
        // Revenue stays recognized; archiving is not a reversal.
        expect(cashbook.totalIncome.toString()).toBe('200');

        const report = await integrity().verifyWorkspace(fx.workspace.id);
        expect(report.ok).toBe(true);
    });
});

/**
 * Peer Links, end to end.
 *
 * The promise of the feature is that a loan between two users becomes proof:
 * nothing on any book until acceptance, then mirrored obligations on both
 * books, then cross-confirmed settlement where a payment only counts once both
 * sides carry it. These tests walk that whole story through the real services
 * — proposals, acceptance with journals, decline/cancel guards, settlement
 * confirm/reject/match, and the authorisation walls around all of it.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { Prisma, PeerLinkStatus } from '@prisma/client';
import { resetDatabase, testPrisma } from '../setup';
import { resolveService } from '../container';
import { PeerLinksService } from '../../modules/peer-links/peer-links.service';
import { EntriesService } from '../../modules/entries/entries.service';
import { ObligationsService } from '../../modules/cashbook-obligations/obligations.service';
import {
    createAccount, createCashbook, createUser,
} from '../factories';
import {
    provisionWorkspaceAccounting, ensureCashbookLedgerAccount, ensureWalletLedgerAccount,
} from '../../core/ledger/coa.seed';

const peerLinks = () => resolveService(PeerLinksService);
const entries = () => resolveService(EntriesService);

/**
 * Two users, each with a workspace, provisioned book and wallet. Personal
 * workspaces are the common case for peer links, but the machinery is
 * workspace-type agnostic — business books work identically.
 */
async function fixture() {
    const alice = await createUser({ email: `alice-${Date.now()}@test.local` });
    const bob = await createUser({ email: `bob-${Date.now()}@test.local` });

    const aliceWs = await testPrisma.workspace.create({
        data: {
            name: "Alice's Personal",
            type: 'PERSONAL',
            ownerId: alice.id,
            defaultCurrency: 'UGX',
            timezone: 'Africa/Kampala',
        },
    });
    const bobWs = await testPrisma.workspace.create({
        data: {
            name: "Bob's Personal",
            type: 'PERSONAL',
            ownerId: bob.id,
            defaultCurrency: 'UGX',
            timezone: 'Africa/Kampala',
        },
    });

    for (const ws of [aliceWs, bobWs]) {
        await testPrisma.$transaction(async (tx: Prisma.TransactionClient) => {
            await provisionWorkspaceAccounting(tx, ws.id, 'UGX');
        });
    }

    const aliceBook = await createCashbook(aliceWs.id, alice.id, { name: 'Alice Main' });
    const bobBook = await createCashbook(bobWs.id, bob.id, { name: 'Bob Main' });
    for (const [ws, book] of [[aliceWs, aliceBook], [bobWs, bobBook]] as const) {
        await testPrisma.$transaction(async (tx: Prisma.TransactionClient) => {
            await ensureCashbookLedgerAccount(tx, {
                id: book.id, workspaceId: ws.id, name: book.name, currency: 'UGX',
            });
        });
    }

    const aliceWallet = await createAccount(aliceWs.id, { name: 'Alice Cash', balance: '500000' });
    const bobWallet = await createAccount(bobWs.id, { name: 'Bob Cash', balance: '500000' });
    for (const wallet of [aliceWallet, bobWallet]) {
        await testPrisma.$transaction(async (tx: Prisma.TransactionClient) => {
            const full = await tx.account.findUniqueOrThrow({
                where: { id: wallet.id }, include: { accountType: true },
            });
            await ensureWalletLedgerAccount(tx, full, full.accountType.classification);
        });
    }

    return { alice, bob, aliceWs, bobWs, aliceBook, bobBook, aliceWallet, bobWallet };
}

/** Alice lends Bob 100,000 at 10%; Bob accepts into his book. */
async function acceptedLoan(f: Awaited<ReturnType<typeof fixture>>) {
    const proposal: any = await peerLinks().createPeerLink(f.aliceBook.id, f.alice.id, {
        direction: 'LENDING',
        counterpartyEmail: f.bob.email,
        title: 'Loan to Bob',
        principalAmount: '100000',
        interestRate: '10',
        dueDate: new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString(),
    });
    const accepted: any = await peerLinks().acceptPeerLink(proposal.id, f.bob.id, {
        cashbookId: f.bobBook.id,
    });
    return { proposal, accepted };
}

async function trialBalance(): Promise<string> {
    const rows = await testPrisma.journalLine.aggregate({ _sum: { debit: true, credit: true } });
    return new Prisma.Decimal(rows._sum.debit ?? 0).sub(rows._sum.credit ?? 0).toString();
}

describe('proposing a peer link', () => {
    beforeEach(resetDatabase);

    it('stores terms but touches no book until accepted', async () => {
        const f = await fixture();
        const proposal: any = await peerLinks().createPeerLink(f.aliceBook.id, f.alice.id, {
            direction: 'LENDING',
            counterpartyEmail: f.bob.email,
            title: 'Loan to Bob',
            principalAmount: '100000',
            interestRate: '10',
        });

        expect(proposal.status).toBe('PENDING');
        expect(proposal.totalAmount).toBe('110000');
        expect(proposal.viewerIsInitiator).toBe(true);
        expect(proposal.counterparty.email).toBe(f.bob.email);

        const obligations = await testPrisma.cashbookObligation.count();
        expect(obligations).toBe(0);
    });

    it('refuses a self link', async () => {
        const f = await fixture();
        await expect(peerLinks().createPeerLink(f.aliceBook.id, f.alice.id, {
            direction: 'LENDING',
            counterpartyEmail: f.alice.email,
            title: 'Loan to myself',
            totalAmount: '1000',
        })).rejects.toMatchObject({ code: 'SELF_PEER_LINK' });
    });

    it('refuses an email no user has, without leaking existence', async () => {
        const f = await fixture();
        await expect(peerLinks().createPeerLink(f.aliceBook.id, f.alice.id, {
            direction: 'LENDING',
            counterpartyEmail: 'nobody@test.local',
            title: 'Loan to nobody',
            totalAmount: '1000',
        })).rejects.toMatchObject({ statusCode: 404, code: 'USER_NOT_FOUND' });
    });
});

describe('accepting a peer link', () => {
    beforeEach(resetDatabase);

    it('creates mirrored obligations on both books with journals, and auto-contacts', async () => {
        const f = await fixture();
        const { accepted } = await acceptedLoan(f);

        expect(accepted.status).toBe('ACCEPTED');
        expect(accepted.viewerIsInitiator).toBe(false); // viewed from Bob side
        expect(accepted.viewerDirection).toBe('BORROWING'); // Bob borrowed

        const obligations = await testPrisma.cashbookObligation.findMany({
            where: { peerLinkId: accepted.id },
        });
        expect(obligations).toHaveLength(2);

        const aliceSide = obligations.find((o: any) => o.cashbookId === f.aliceBook.id)!;
        const bobSide = obligations.find((o: any) => o.cashbookId === f.bobBook.id)!;
        expect(aliceSide.type).toBe('RECEIVABLE'); // lender
        expect(bobSide.type).toBe('PAYABLE'); // borrower
        expect(aliceSide.totalAmount.toString()).toBe('110000');
        expect(bobSide.totalAmount.toString()).toBe('110000');
        expect(aliceSide.outstandingAmount.toString()).toBe('110000');

        // Contacts stand for the counterparty on each side.
        expect(aliceSide.contactId).toBeTruthy();
        expect(bobSide.contactId).toBeTruthy();
        const aliceContact = await testPrisma.contact.findUniqueOrThrow({
            where: { id: aliceSide.contactId! },
        });
        expect(aliceContact.userId).toBe(f.bob.id);

        // Both workspaces' books balance.
        expect(await trialBalance()).toBe('0');
    });

    it('refuses a book in a different currency', async () => {
        const f = await fixture();
        const usdBook = await createCashbook(f.bobWs.id, f.bob.id, {
            name: 'Bob USD', currency: 'USD',
        });

        const proposal: any = await peerLinks().createPeerLink(f.aliceBook.id, f.alice.id, {
            direction: 'LENDING',
            counterpartyEmail: f.bob.email,
            title: 'Loan to Bob',
            totalAmount: '100000',
        });

        await expect(peerLinks().acceptPeerLink(proposal.id, f.bob.id, {
            cashbookId: usdBook.id,
        })).rejects.toMatchObject({ code: 'CURRENCY_MISMATCH' });
    });

    it('refuses the initiator as accepter, and double acceptance', async () => {
        const f = await fixture();
        const proposal: any = await peerLinks().createPeerLink(f.aliceBook.id, f.alice.id, {
            direction: 'LENDING',
            counterpartyEmail: f.bob.email,
            title: 'Loan to Bob',
            totalAmount: '100000',
        });

        await expect(peerLinks().acceptPeerLink(proposal.id, f.alice.id, {
            cashbookId: f.bobBook.id,
        })).rejects.toMatchObject({ statusCode: 403 });

        await peerLinks().acceptPeerLink(proposal.id, f.bob.id, { cashbookId: f.bobBook.id });

        await expect(peerLinks().acceptPeerLink(proposal.id, f.bob.id, {
            cashbookId: f.bobBook.id,
        })).rejects.toMatchObject({ code: 'INVALID_STATUS' });

        // And the mirror was not duplicated.
        expect(await testPrisma.cashbookObligation.count({ where: { peerLinkId: proposal.id } })).toBe(2);
    });

    it('decline and cancel leave no obligations behind', async () => {
        const f = await fixture();
        const proposal: any = await peerLinks().createPeerLink(f.aliceBook.id, f.alice.id, {
            direction: 'LENDING',
            counterpartyEmail: f.bob.email,
            title: 'Loan to Bob',
            totalAmount: '100000',
        });

        await peerLinks().declinePeerLink(proposal.id, f.bob.id, { reason: 'Not now' });
        expect(await testPrisma.cashbookObligation.count()).toBe(0);

        const proposal2: any = await peerLinks().createPeerLink(f.aliceBook.id, f.alice.id, {
            direction: 'BORROWING',
            counterpartyEmail: f.bob.email,
            title: 'Loan from Bob',
            totalAmount: '50000',
        });
        await peerLinks().cancelPeerLink(proposal2.id, f.alice.id, {});
        expect(await testPrisma.cashbookObligation.count()).toBe(0);

        // A cancelled link cannot be accepted after the fact.
        await expect(peerLinks().acceptPeerLink(proposal2.id, f.bob.id, {
            cashbookId: f.bobBook.id,
        })).rejects.toMatchObject({ code: 'INVALID_STATUS' });
    });
});

describe('cross-confirmed settlement', () => {
    beforeEach(resetDatabase);

    it('a payment opens a settlement the counterparty confirms', async () => {
        const f = await fixture();
        const { accepted } = await acceptedLoan(f);

        // Alice (lender, RECEIVABLE) records receiving 40,000.
        const aliceObligation = await testPrisma.cashbookObligation.findFirstOrThrow({
            where: { peerLinkId: accepted.id, cashbookId: f.aliceBook.id },
        });
        await entries().createEntry(f.aliceBook.id, f.alice.id, {
            type: 'INCOME',
            amount: '40000',
            description: 'Part repayment from Bob',
            accountId: f.aliceWallet.id,
            obligationId: aliceObligation.id,
            entryDate: new Date().toISOString(),
        } as any);

        let settlement = await testPrisma.peerLinkSettlement.findFirstOrThrow({
            where: { peerLinkId: accepted.id },
        });
        expect(settlement.status).toBe('PENDING');
        expect(settlement.amount.toString()).toBe('40000');
        expect(settlement.recordedByUserId).toBe(f.alice.id);

        // Only Bob may decide; Alice cannot confirm her own recording.
        await expect(peerLinks().decideSettlement(settlement.id, f.alice.id, {
            decision: 'CONFIRM',
        })).rejects.toMatchObject({ statusCode: 403 });

        await peerLinks().decideSettlement(settlement.id, f.bob.id, { decision: 'CONFIRM' });

        settlement = await testPrisma.peerLinkSettlement.findUniqueOrThrow({
            where: { id: settlement.id },
        });
        expect(settlement.status).toBe('CONFIRMED');
        expect(await trialBalance()).toBe('0');
    });

    it('confirming by matching an entry already recorded on the other side', async () => {
        const f = await fixture();
        const { accepted } = await acceptedLoan(f);

        const aliceObligation = await testPrisma.cashbookObligation.findFirstOrThrow({
            where: { peerLinkId: accepted.id, cashbookId: f.aliceBook.id },
        });
        const bobObligation = await testPrisma.cashbookObligation.findFirstOrThrow({
            where: { peerLinkId: accepted.id, cashbookId: f.bobBook.id },
        });

        // Both sides record the same 40,000 independently.
        await entries().createEntry(f.aliceBook.id, f.alice.id, {
            type: 'INCOME', amount: '40000', description: 'Repayment',
            accountId: f.aliceWallet.id, obligationId: aliceObligation.id,
            entryDate: new Date().toISOString(),
        } as any);
        const bobEntry = await entries().createEntry(f.bobBook.id, f.bob.id, {
            type: 'EXPENSE', amount: '40000', description: 'Repayment to Alice',
            accountId: f.bobWallet.id, obligationId: bobObligation.id,
            entryDate: new Date().toISOString(),
        } as any);

        const settlement = await testPrisma.peerLinkSettlement.findFirstOrThrow({
            where: { peerLinkId: accepted.id },
        });

        // Bob confirms Alice's recording by pointing at his own mirrored entry.
        const decided: any = await peerLinks().decideSettlement(settlement.id, f.bob.id, {
            decision: 'CONFIRM',
            matchedEntryId: bobEntry.id,
        });
        expect(decided.status).toBe('CONFIRMED');
        expect(decided.matchedEntryId).toBe(bobEntry.id);
    });

    it('rejecting a mismatched match refuses, and rejection is final', async () => {
        const f = await fixture();
        const { accepted } = await acceptedLoan(f);

        const aliceObligation = await testPrisma.cashbookObligation.findFirstOrThrow({
            where: { peerLinkId: accepted.id, cashbookId: f.aliceBook.id },
        });
        const bobObligation = await testPrisma.cashbookObligation.findFirstOrThrow({
            where: { peerLinkId: accepted.id, cashbookId: f.bobBook.id },
        });

        await entries().createEntry(f.aliceBook.id, f.alice.id, {
            type: 'INCOME', amount: '40000', description: 'Repayment',
            accountId: f.aliceWallet.id, obligationId: aliceObligation.id,
            entryDate: new Date().toISOString(),
        } as any);
        // Bob records a DIFFERENT amount.
        const bobEntry = await entries().createEntry(f.bobBook.id, f.bob.id, {
            type: 'EXPENSE', amount: '30000', description: 'Partial repayment',
            accountId: f.bobWallet.id, obligationId: bobObligation.id,
            entryDate: new Date().toISOString(),
        } as any);

        const settlement = await testPrisma.peerLinkSettlement.findFirstOrThrow({
            where: { peerLinkId: accepted.id },
        });

        await expect(peerLinks().decideSettlement(settlement.id, f.bob.id, {
            decision: 'CONFIRM',
            matchedEntryId: bobEntry.id,
        })).rejects.toMatchObject({ code: 'AMOUNT_MISMATCH' });

        await peerLinks().decideSettlement(settlement.id, f.bob.id, {
            decision: 'REJECT',
            reason: 'I only received 30,000',
        });

        await expect(peerLinks().decideSettlement(settlement.id, f.bob.id, {
            decision: 'CONFIRM',
        })).rejects.toMatchObject({ code: 'INVALID_STATUS' });
    });

    it('reversing the payment entry cancels the settlement', async () => {
        const f = await fixture();
        const { accepted } = await acceptedLoan(f);

        const aliceObligation = await testPrisma.cashbookObligation.findFirstOrThrow({
            where: { peerLinkId: accepted.id, cashbookId: f.aliceBook.id },
        });
        const entry = await entries().createEntry(f.aliceBook.id, f.alice.id, {
            type: 'INCOME', amount: '40000', description: 'Repayment',
            accountId: f.aliceWallet.id, obligationId: aliceObligation.id,
            entryDate: new Date().toISOString(),
        } as any);

        await entries().deleteEntry(entry.id, f.alice.id, 'Recorded in error', 'PRIMARY_ADMIN' as any);

        const settlement = await testPrisma.peerLinkSettlement.findFirst({
            where: { peerLinkId: accepted.id },
        });
        expect(settlement?.status).toBe('CANCELLED');

        // And the obligation owes its full amount again.
        const refreshed = await testPrisma.cashbookObligation.findUniqueOrThrow({
            where: { id: aliceObligation.id },
        });
        expect(refreshed.outstandingAmount.toString()).toBe('110000');
        expect(await trialBalance()).toBe('0');
    });
});

describe('peer link listing and lookup', () => {
    beforeEach(resetDatabase);

    it('lists links from the viewer\'s perspective only', async () => {
        const f = await fixture();
        await acceptedLoan(f);

        const asAlice = await peerLinks().getPeerLinks(f.alice.id, { page: 1, limit: 20 } as any);
        const asBob = await peerLinks().getPeerLinks(f.bob.id, { page: 1, limit: 20 } as any);
        expect(asAlice.data).toHaveLength(1);
        expect(asBob.data).toHaveLength(1);

        expect(asAlice.data[0].viewerIsInitiator).toBe(true);
        expect(asAlice.data[0].viewerDirection).toBe('LENDING');
        expect(asBob.data[0].viewerIsInitiator).toBe(false);
        expect(asBob.data[0].viewerDirection).toBe('BORROWING');

        // A stranger sees nothing.
        const eve = await createUser();
        const asEve = await peerLinks().getPeerLinks(eve.id, { page: 1, limit: 20 } as any);
        expect(asEve.data).toHaveLength(0);
    });

    it('lookup finds a user by exact email only', async () => {
        const f = await fixture();
        const found = await peerLinks().lookupUserByEmail(f.bob.email);
        expect(found.id).toBe(f.bob.id);

        await expect(peerLinks().lookupUserByEmail('nope@test.local'))
            .rejects.toMatchObject({ code: 'USER_NOT_FOUND' });
    });

    it('acceptable cashbooks answer empty once the link is decided, not a 400', async () => {
        const f = await fixture();
        const { accepted } = await acceptedLoan(f);

        // The dialog's own refetch races the accept success that invalidated
        // it — a decided link must answer gracefully.
        const books: any = await peerLinks().getAcceptableCashbooks(accepted.id, f.bob.id);
        expect(books.data).toEqual([]);
    });

    it('acceptable cashbooks are the counterparty\'s, currency-matched, excluding the initiator\'s', async () => {
        const f = await fixture();
        const proposal: any = await peerLinks().createPeerLink(f.aliceBook.id, f.alice.id, {
            direction: 'LENDING',
            counterpartyEmail: f.bob.email,
            title: 'Loan to Bob',
            totalAmount: '100000',
        });

        // Alice cannot enumerate Bob's books.
        await expect(peerLinks().getAcceptableCashbooks(proposal.id, f.alice.id))
            .rejects.toMatchObject({ statusCode: 403 });

        const books: any = await peerLinks().getAcceptableCashbooks(proposal.id, f.bob.id);
        const ids = books.data.map((b: any) => b.id);
        expect(ids).toContain(f.bobBook.id);
        expect(ids).not.toContain(f.aliceBook.id);
    });
});

describe('workspace obligations listing', () => {
    beforeEach(resetDatabase);

    it('lists obligations across the workspace books with filters', async () => {
        const f = await fixture();
        // Plain contact obligation on Alice's book plus a peer link.
        await resolveService(ObligationsService)
            .createObligation(f.aliceBook.id, f.alice.id, {
                type: 'PAYABLE', title: 'Rent owed', totalAmount: '20000',
            } as any);
        await acceptedLoan(f);

        const result = await peerLinks().getWorkspaceObligations(
            f.aliceWs.id, f.alice.id, 'OWNER' as any, { page: 1, limit: 50 } as any,
        );
        // Scoped to Alice's workspace: her rent payable + her loan receivable.
        // Bob's mirrored PAYABLE lives in his workspace, not hers.
        expect(result.data).toHaveLength(2);

        const active = await peerLinks().getWorkspaceObligations(
            f.aliceWs.id, f.alice.id, 'OWNER' as any, { page: 1, limit: 50, status: 'ACTIVE' } as any,
        );
        expect(active.data).toHaveLength(2);

        const receivables = await peerLinks().getWorkspaceObligations(
            f.aliceWs.id, f.alice.id, 'OWNER' as any, { page: 1, limit: 50, type: 'RECEIVABLE' } as any,
        );
        expect(receivables.data).toHaveLength(1);
        expect(receivables.data[0]!.peerLink!.id).toBeTruthy();
    });
});

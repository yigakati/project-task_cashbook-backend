/**
 * Cross-workspace agreements — stock transfers and rental loans.
 *
 * The promise of both flows is that the app is the shared proof: what one
 * side's books record for the movement, the other side's books record its
 * mirror image, at the same per-unit value, in one atomic step. And for
 * rental agreements, that a promised loan actually holds its stock until the
 * borrower decides.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { WorkspaceType } from '@prisma/client';
import { resetDatabase, testPrisma } from '../setup';
import { resolveService } from '../container';
import { InventoryService } from '../../modules/inventory/inventory.service';
import { StockTransfersService } from '../../modules/inventory/stock-transfers.service';
import { RentalAgreementsService } from '../../modules/inventory/rental-agreements.service';
import { EntriesService } from '../../modules/entries/entries.service';
import { createWorkspace, createUser, createCashbook, createAccount } from '../factories';
import {
    provisionWorkspaceAccounting, ensureCashbookLedgerAccount, ensureWalletLedgerAccount,
} from '../../core/ledger/coa.seed';

const inventory = () => resolveService(InventoryService);
const transfers = () => resolveService(StockTransfersService);
const agreements = () => resolveService(RentalAgreementsService);

async function userWithWorkspace(email: string) {
    const user = await createUser({ email });
    // Mirrors production signup: a personal workspace alongside any others.
    const personal = await testPrisma.workspace.create({
        data: {
            name: `Personal ${user.id.slice(0, 6)}`,
            type: WorkspaceType.PERSONAL,
            ownerId: user.id,
            defaultCurrency: 'UGX',
            timezone: 'Africa/Kampala',
        },
    });
    const workspace = await createWorkspace(user.id);
    return { user, workspace, personal };
}

/** A user, workspace, stocked item (purchased at the given cost), and wallet. */
async function stockedOwner(email: string, itemName: string, quantity: number, unitCost: string) {
    const { user, workspace, personal } = await userWithWorkspace(email);
    await testPrisma.$transaction(async (tx: any) => {
        await provisionWorkspaceAccounting(tx, workspace.id, 'UGX');
    });

    const item: any = await inventory().createItem(workspace.id, user.id, {
        name: itemName, unit: 'pcs', commercialMode: 'SELL_AND_RENT', allowNegativeStock: false,
    } as any);
    // Stock the item through the ordinary purchase path.
    await inventory().createTransaction(workspace.id, user.id, {
        itemId: item.id, transactionType: 'PURCHASE', quantity, unitCost,
        notes: 'initial stock',
    } as any);

    const wallet = await createAccount(workspace.id, { name: 'Cash', balance: '1000000' });
    await testPrisma.$transaction(async (tx: any) => {
        const full = await tx.account.findUniqueOrThrow({
            where: { id: wallet.id }, include: { accountType: true },
        });
        await ensureWalletLedgerAccount(tx, full, full.accountType.classification);
    });

    return { user, workspace, personal, item: item as any, wallet };
}

/** A customer contact linked to the given user, in the lender's workspace. */
async function ensureCustomer(lenderWorkspaceId: string, user: { id: string; email: string; firstName?: string; lastName?: string }) {
    const existing = await testPrisma.contact.findFirst({
        where: { workspaceId: lenderWorkspaceId, userId: user.id },
    });
    if (existing) return existing;
    return testPrisma.contact.create({
        data: {
            workspaceId: lenderWorkspaceId,
            userId: user.id,
            type: 'STAFF',
            name: `${user.firstName ?? 'User'} ${user.lastName ?? user.email}`,
            email: user.email,
        },
    });
}

async function getStock(itemId: string) {
    return testPrisma.inventoryStock.findUniqueOrThrow({ where: { itemId } });
}

describe('stock requests', () => {
    beforeEach(resetDatabase);

    it('walks the full lifecycle: request (item-tied) → send (vendor out) → receive (requester in)', async () => {
        const vendor = await stockedOwner(`vendor-${Date.now()}@test.local`, 'Camera', 10, '40000');
        const requester = await userWithWorkspace(`req-${Date.now()}@test.local`);
        // The requester's own item — the request is made FROM it.
        const wanted: any = await inventory().createItem(requester.workspace.id, requester.user.id, {
            name: 'Camera', unit: 'pcs', commercialMode: 'SELL_AND_RENT', allowNegativeStock: false,
        } as any);

        // 1. REQUEST — tied to the requester's item and workspace. Nothing moves.
        const request: any = await transfers().createRequest(
            requester.workspace.id, requester.user.id,
            { itemId: wanted.id, quantity: 4, vendorEmail: vendor.user.email },
        );
        expect(request.status).toBe('PENDING');
        expect(request.recipientItemId).toBe(wanted.id);
        expect(request.recipientWorkspaceId).toBe(requester.workspace.id);
        expect((await getStock(vendor.item.id)).quantityOnHand).toBe(10);

        // 2. SEND — the vendor names their workspace + item; stock leaves.
        const sendOptions = await transfers().getSendOptions(request.id, vendor.user.id);
        expect(sendOptions.workspaces.map((w: any) => w.id)).toContain(vendor.workspace.id);
        // Only currency-matching items are offered.
        expect(sendOptions.items.map((i: any) => i.id)).toContain(vendor.item.id);

        const sent: any = await transfers().send(request.id, vendor.user.id, {
            senderWorkspaceId: vendor.workspace.id,
            senderItemId: vendor.item.id,
        });
        expect(sent.status).toBe('SENT');
        expect((await getStock(vendor.item.id)).quantityOnHand).toBe(6);

        // 3. RECEIVE — no choices; the stock lands in the requesting item.
        const completed: any = await transfers().receive(request.id, requester.user.id);
        expect(completed.status).toBe('COMPLETED');
        const receivedStock = await getStock(wanted.id);
        expect(receivedStock.quantityOnHand).toBe(4);
        expect(receivedStock.averageCost.toString()).toBe((await getStock(vendor.item.id)).averageCost.toString());

        // Both movements carry the same provenance.
        const [outTx, inTx] = await Promise.all([
            testPrisma.inventoryTransaction.findFirst({
                where: { itemId: vendor.item.id, transactionType: 'TRANSFER_OUT' },
            }),
            testPrisma.inventoryTransaction.findFirst({
                where: { itemId: wanted.id, transactionType: 'TRANSFER_IN' },
            }),
        ]);
        expect(outTx?.unitCost.toString()).toBe(inTx?.unitCost.toString());
        expect(outTx?.referenceId).toBe(inTx?.referenceId);
        expect(outTx?.referenceType).toBe('STOCK_TRANSFER');
    });

    it('scopes requests to their workspace: origin workspace only, vendor personal only, sending workspace after send', async () => {
        const vendor = await stockedOwner(`v2-${Date.now()}@test.local`, 'Lens', 8, '15000');
        const requester = await userWithWorkspace(`r2-${Date.now()}@test.local`);
        // Another workspace of the requester's — must NOT see the request.
        const requesterOther = await createWorkspace(requester.user.id);

        const wanted: any = await inventory().createItem(requester.workspace.id, requester.user.id, {
            name: 'Lens', unit: 'pcs', commercialMode: 'SELL_ONLY', allowNegativeStock: false,
        } as any);
        const request: any = await transfers().createRequest(
            requester.workspace.id, requester.user.id,
            { itemId: wanted.id, quantity: 2, vendorEmail: vendor.user.email },
        );

        // Requester's origin workspace sees it; their other workspace does not.
        const inOrigin = await transfers().list(requester.user.id, { workspaceId: requester.workspace.id, page: 1, limit: 50 } as any);
        expect(inOrigin.data.map((t: any) => t.id)).toContain(request.id);
        const inOther = await transfers().list(requester.user.id, { workspaceId: requesterOther.id, page: 1, limit: 50 } as any);
        expect(inOther.data.map((t: any) => t.id)).not.toContain(request.id);

        // Vendor sees the pending request only in their personal workspace.
        const vendorPersonalView = await transfers().list(vendor.user.id, { workspaceId: vendor.personal.id, page: 1, limit: 50 } as any);
        expect(vendorPersonalView.data.map((t: any) => t.id)).toContain(request.id);
        const vendorBusinessView = await transfers().list(vendor.user.id, { workspaceId: vendor.workspace.id, page: 1, limit: 50 } as any);
        expect(vendorBusinessView.data.map((t: any) => t.id)).not.toContain(request.id);

        // After the send, the request belongs to the vendor's sending
        // workspace — not even their personal workspace shows it.
        await transfers().send(request.id, vendor.user.id, {
            senderWorkspaceId: vendor.workspace.id,
            senderItemId: vendor.item.id,
        });
        const vendorPersonalAfter = await transfers().list(vendor.user.id, { workspaceId: vendor.personal.id, page: 1, limit: 50 } as any);
        expect(vendorPersonalAfter.data.map((t: any) => t.id)).not.toContain(request.id);
        const vendorBusinessAfter = await transfers().list(vendor.user.id, { workspaceId: vendor.workspace.id, page: 1, limit: 50 } as any);
        expect(vendorBusinessAfter.data.map((t: any) => t.id)).toContain(request.id);
        // ...and the requester still sees it in the origin workspace.
        const requesterAfter = await transfers().list(requester.user.id, { workspaceId: requester.workspace.id, page: 1, limit: 50 } as any);
        expect(requesterAfter.data.map((t: any) => t.id)).toContain(request.id);
    });

    it('the requester can cancel while pending; the vendor can decline; both leave stock untouched', async () => {
        const vendor = await stockedOwner(`v3-${Date.now()}@test.local`, 'Tripod', 8, '5000');
        const requester = await userWithWorkspace(`r3-${Date.now()}@test.local`);
        const wanted: any = await inventory().createItem(requester.workspace.id, requester.user.id, {
            name: 'Tripod', unit: 'pcs', commercialMode: 'SELL_ONLY', allowNegativeStock: false,
        } as any);

        const r1: any = await transfers().createRequest(
            requester.workspace.id, requester.user.id,
            { itemId: wanted.id, quantity: 2, vendorEmail: vendor.user.email },
        );
        await transfers().cancel(r1.id, requester.user.id);
        expect((await getStock(vendor.item.id)).quantityOnHand).toBe(8);

        const r2: any = await transfers().createRequest(
            requester.workspace.id, requester.user.id,
            { itemId: wanted.id, quantity: 3, vendorEmail: vendor.user.email },
        );
        await transfers().decline(r2.id, vendor.user.id, 'Out of stock');
        expect((await getStock(vendor.item.id)).quantityOnHand).toBe(8);
    });

    it('sent stock cannot be cancelled — only received; insufficient stock refuses the send', async () => {
        const vendor = await stockedOwner(`v4-${Date.now()}@test.local`, 'Light', 5, '5000');
        const requester = await userWithWorkspace(`r4-${Date.now()}@test.local`);
        const wanted: any = await inventory().createItem(requester.workspace.id, requester.user.id, {
            name: 'Light', unit: 'pcs', commercialMode: 'SELL_ONLY', allowNegativeStock: false,
        } as any);

        const request: any = await transfers().createRequest(
            requester.workspace.id, requester.user.id,
            { itemId: wanted.id, quantity: 2, vendorEmail: vendor.user.email },
        );

        // Asking for more than the vendor has fails at send, not at request.
        const tooBig: any = await transfers().createRequest(
            requester.workspace.id, requester.user.id,
            { itemId: wanted.id, quantity: 99, vendorEmail: vendor.user.email },
        );
        await expect(transfers().send(tooBig.id, vendor.user.id, {
            senderWorkspaceId: vendor.workspace.id,
            senderItemId: vendor.item.id,
        })).rejects.toMatchObject({ code: 'INSUFFICIENT_STOCK' });

        await transfers().send(request.id, vendor.user.id, {
            senderWorkspaceId: vendor.workspace.id,
            senderItemId: vendor.item.id,
        });
        // Once sent, the requester cannot cancel — coordinate a return instead.
        await expect(transfers().cancel(request.id, requester.user.id)).rejects.toMatchObject({ code: 'INVALID_STATUS' });
    });

    it('self-requests, unknown emails, accountless contacts, and foreign items are refused', async () => {
        const requester = await userWithWorkspace(`r5-${Date.now()}@test.local`);
        const foreign = await stockedOwner(`f5-${Date.now()}@test.local`, 'Boom', 5, '1000');
        const wanted: any = await inventory().createItem(requester.workspace.id, requester.user.id, {
            name: 'Boom', unit: 'pcs', commercialMode: 'SELL_ONLY', allowNegativeStock: false,
        } as any);

        await expect(transfers().createRequest(
            requester.workspace.id, requester.user.id,
            { itemId: wanted.id, quantity: 1, vendorEmail: requester.user.email },
        )).rejects.toMatchObject({ code: 'SELF_REQUEST' });

        await expect(transfers().createRequest(
            requester.workspace.id, requester.user.id,
            { itemId: wanted.id, quantity: 1, vendorEmail: 'ghost@test.local' },
        )).rejects.toMatchObject({ code: 'USER_NOT_FOUND' });

        // An item in someone else's workspace cannot be the request target.
        await expect(transfers().createRequest(
            requester.workspace.id, requester.user.id,
            { itemId: foreign.item.id, quantity: 1, vendorEmail: 'someone@test.local' },
        )).rejects.toMatchObject({ code: 'NOT_FOUND' });

        const walkIn = await testPrisma.contact.create({
            data: { workspaceId: requester.workspace.id, type: 'VENDOR', name: 'Walk In Vendor' },
        });
        await expect(transfers().createRequest(
            requester.workspace.id, requester.user.id,
            { itemId: wanted.id, quantity: 1, contactId: walkIn.id },
        )).rejects.toMatchObject({ code: 'CONTACT_HAS_NO_ACCOUNT' });
    });

    it('records the requester expense and vendor income once each, in the right workspaces', async () => {
        const vendor = await stockedOwner(`v6-${Date.now()}@test.local`, 'Mic', 5, '9000');
        const requester = await userWithWorkspace(`r6-${Date.now()}@test.local`);
        const requesterBook = await createCashbook(requester.workspace.id, requester.user.id);
        const vendorBook = await createCashbook(vendor.workspace.id, vendor.user.id);
        const wanted: any = await inventory().createItem(requester.workspace.id, requester.user.id, {
            name: 'Mic', unit: 'pcs', commercialMode: 'SELL_ONLY', allowNegativeStock: false,
        } as any);

        const request: any = await transfers().createRequest(
            requester.workspace.id, requester.user.id,
            { itemId: wanted.id, quantity: 2, vendorEmail: vendor.user.email },
        );
        await transfers().send(request.id, vendor.user.id, {
            senderWorkspaceId: vendor.workspace.id,
            senderItemId: vendor.item.id,
        });
        await transfers().receive(request.id, requester.user.id);

        // The vendor can record income as soon as the goods left (SENT+).
        const income: any = await transfers().recordIncome(request.id, vendor.user.id, {
            cashbookId: vendorBook.id,
        });
        expect(income.type).toBe('INCOME');
        expect(income.amount.toString()).toBe('18000');

        // The requester records the expense after receipt, in the origin workspace.
        const expense: any = await transfers().recordExpense(request.id, requester.user.id, {
            cashbookId: requesterBook.id,
        });
        expect(expense.type).toBe('EXPENSE');
        expect(expense.amount.toString()).toBe('18000');

        // Both are one-time.
        await expect(transfers().recordExpense(request.id, requester.user.id, {
            cashbookId: requesterBook.id,
        })).rejects.toMatchObject({ code: 'ALREADY_RECORDED' });
        await expect(transfers().recordIncome(request.id, vendor.user.id, {
            cashbookId: vendorBook.id,
        })).rejects.toMatchObject({ code: 'ALREADY_RECORDED' });
    });
});

describe('rental agreements', () => {
    beforeEach(resetDatabase);

    it('reserves stock at proposal, converts to rental on acceptance, releases on decline', async () => {
        const lender = await stockedOwner(`l-${Date.now()}@test.local`, 'Projector', 5, '120000');
        const borrower = await userWithWorkspace(`b-${Date.now()}@test.local`);

        const offer: any = await agreements().create(
            lender.workspace.id, lender.item.id, lender.user.id,
            {
                quantity: 2, borrowerEmail: borrower.user.email,
                periodUnit: 'WEEK', periodCount: 2, rate: '50000',
                startDate: new Date().toISOString(),
            },
        );
        expect(offer.status).toBe('PENDING');

        // Reserved: still on hand, no longer available.
        let stock = await getStock(lender.item.id);
        expect(stock.quantityOnHand).toBe(5);
        expect(stock.quantityReserved).toBe(2);

        // The reservation blocks an ordinary sale of the same units.
        await expect(inventory().createTransaction(lender.workspace.id, lender.user.id, {
            itemId: lender.item.id, transactionType: 'SALE', quantity: 4,
            notes: 'tries to take reserved units',
        } as any)).rejects.toMatchObject({ code: 'INSUFFICIENT_STOCK' });

        const accepted: any = await agreements().accept(
            offer.id, borrower.user.id,
            { borrowerWorkspaceId: borrower.workspace.id },
        );
        expect(accepted.status).toBe('ACCEPTED');
        expect(accepted.rentalId).not.toBeNull();

        // Reservation became rented-out.
        stock = await getStock(lender.item.id);
        expect(stock.quantityReserved).toBe(0);
        expect(stock.quantityRentedOut).toBe(2);
        expect(stock.quantityOnHand).toBe(5);

        // A rental + its line exist on the lender's books with the borrower
        // as counterparty.
        const rental = await testPrisma.inventoryRental.findUniqueOrThrow({
            where: { id: accepted.rentalId! },
            include: { lines: true, customer: true },
        });
        expect(rental.lines).toHaveLength(1);
        expect(rental.lines[0].quantity).toBe(2);
        expect(rental.lines[0].unitRate.toString()).toBe('50000');
        expect(rental.customerId).not.toBeNull();
        expect(rental.customer?.userId).toBe(borrower.user.id);

        // Second acceptance refused.
        await expect(agreements().accept(
            offer.id, borrower.user.id, { borrowerWorkspaceId: borrower.workspace.id },
        )).rejects.toMatchObject({ code: 'INVALID_STATUS' });
    });

    it('decline and cancel both release the reservation', async () => {
        const lender = await stockedOwner(`l2-${Date.now()}@test.local`, 'Tent', 6, '30000');
        const borrower = await userWithWorkspace(`b2-${Date.now()}@test.local`);

        const offer1: any = await agreements().create(
            lender.workspace.id, lender.item.id, lender.user.id,
            { quantity: 3, borrowerEmail: borrower.user.email, periodUnit: 'DAY', startDate: new Date().toISOString() },
        );
        await agreements().decline(offer1.id, borrower.user.id, 'No thanks');
        expect((await getStock(lender.item.id)).quantityReserved).toBe(0);

        const offer2: any = await agreements().create(
            lender.workspace.id, lender.item.id, lender.user.id,
            { quantity: 2, borrowerEmail: borrower.user.email, periodUnit: 'DAY', startDate: new Date().toISOString() },
        );
        await agreements().cancel(offer2.id, lender.user.id, 'Withdrawn');
        expect((await getStock(lender.item.id)).quantityReserved).toBe(0);
        expect((await getStock(lender.item.id)).quantityOnHand).toBe(6);
    });

    it('refuses lending to yourself and sell-only items', async () => {
        const lender = await stockedOwner(`l3-${Date.now()}@test.local`, 'Chair', 5, '2000');
        await expect(agreements().create(
            lender.workspace.id, lender.item.id, lender.user.id,
            { quantity: 1, borrowerEmail: lender.user.email, periodUnit: 'DAY', startDate: new Date().toISOString() },
        )).rejects.toMatchObject({ code: 'SELF_AGREEMENT' });

        const sellOnly: any = await inventory().createItem(lender.workspace.id, lender.user.id, {
            name: 'Soda', unit: 'pcs', commercialMode: 'SELL_ONLY', allowNegativeStock: false,
        } as any);
        const other = await userWithWorkspace(`x-${Date.now()}@test.local`);
        await expect(agreements().create(
            lender.workspace.id, sellOnly.id, lender.user.id,
            { quantity: 1, borrowerEmail: other.user.email, periodUnit: 'DAY', startDate: new Date().toISOString() },
        )).rejects.toMatchObject({ code: 'ITEM_NOT_RENTABLE' });
    });

    it('accepts a contract addressed by customerId and refuses accountless customers', async () => {
        const lender = await stockedOwner(`l5-${Date.now()}@test.local`, 'Booth', 4, '25000');

        // A customer contact linked to a real account.
        const borrowerUser = await createUser({ email: `b5-${Date.now()}@test.local` });
        const customer = await testPrisma.contact.create({
            data: {
                workspaceId: lender.workspace.id,
                userId: borrowerUser.id,
                type: 'STAFF',
                name: 'Linked Customer',
                email: borrowerUser.email,
            },
        });

        const offer: any = await agreements().create(
            lender.workspace.id, lender.item.id, lender.user.id,
            {
                quantity: 1,
                customerId: customer.id,
                periodUnit: 'DAY',
                startDate: new Date().toISOString(),
                rate: '10000',
            },
        );
        expect(offer.status).toBe('PENDING');
        expect(offer.borrowerUserId).toBe(borrowerUser.id);
        expect((await getStock(lender.item.id)).quantityReserved).toBe(1);

        // An accountless customer cannot be sent a contract — there is
        // nobody on the other side to accept it.
        // No userId on the row AND no matching email — truly accountless.
        const walkIn = await testPrisma.contact.create({
            data: { workspaceId: lender.workspace.id, type: 'CUSTOMER', name: 'Walk In' },
        });
        // But a normally-created customer whose email matches a platform
        // user CAN receive a contract, even without userId on the row.
        const emailUser = await createUser({ email: `em-${Date.now()}@test.local` });
        const emailCustomer = await testPrisma.contact.create({
            data: {
                workspaceId: lender.workspace.id,
                type: 'CUSTOMER',
                name: 'Email Only Customer',
                email: emailUser.email,
            },
        });
        const viaEmail: any = await agreements().create(
            lender.workspace.id, lender.item.id, lender.user.id,
            { quantity: 1, customerId: emailCustomer.id, periodUnit: 'DAY', startDate: new Date().toISOString() },
        );
        expect(viaEmail.borrowerUserId).toBe(emailUser.id);
        await expect(agreements().create(
            lender.workspace.id, lender.item.id, lender.user.id,
            { quantity: 1, customerId: walkIn.id, periodUnit: 'DAY', startDate: new Date().toISOString() },
        )).rejects.toMatchObject({ code: 'CUSTOMER_HAS_NO_ACCOUNT' });
    });

    it('restricts acceptance to owned/admin workspaces', async () => {
        const lender = await stockedOwner(`l6-${Date.now()}@test.local`, 'Lights', 5, '5000');
        const borrowerOwner = await createUser({ email: `b6-${Date.now()}@test.local` });
        const borrowerMember = await createUser({ email: `m6-${Date.now()}@test.local` });

        // Borrower-owned workspace + a workspace where they are a plain MEMBER.
        const ownedWs = await createWorkspace(borrowerOwner.id);
        const memberWs = await createWorkspace(borrowerMember.id);
        await testPrisma.workspaceMember.create({
            data: { workspaceId: memberWs.id, userId: borrowerOwner.id, role: 'MEMBER' },
        });

        const offer: any = await agreements().create(
            lender.workspace.id, lender.item.id, lender.user.id,
            { quantity: 1, customerId: (await ensureCustomer(lender.workspace.id, borrowerOwner)).id, periodUnit: 'DAY', startDate: new Date().toISOString(), rate: '1000' },
        );

        // Options list excludes the member workspace.
        const options = await agreements().getAcceptanceOptions(offer.id, borrowerOwner.id);
        expect(options.workspaces.map((w: any) => w.id)).toContain(ownedWs.id);
        expect(options.workspaces.map((w: any) => w.id)).not.toContain(memberWs.id);

        // Acceptance into the member workspace is refused outright.
        await expect(agreements().accept(offer.id, borrowerOwner.id, {
            borrowerWorkspaceId: memberWs.id,
        })).rejects.toMatchObject({ statusCode: 403 });

        // The owned workspace accepts fine.
        const accepted: any = await agreements().accept(offer.id, borrowerOwner.id, {
            borrowerWorkspaceId: ownedWs.id,
        });
        expect(accepted.status).toBe('ACCEPTED');
        expect(accepted.borrowerWorkspaceId).toBe(ownedWs.id);
    });

    it('records the borrower expense and the lender income after acceptance', async () => {
        const lender = await stockedOwner(`l7-${Date.now()}@test.local`, 'Speaker', 5, '8000');
        const borrower = await userWithWorkspace(`b7-${Date.now()}@test.local`);

        // A book in the borrower's workspace for the expense.
        const borrowerBook = await createCashbook(borrower.workspace.id, borrower.user.id);

        const offer: any = await agreements().create(
            lender.workspace.id, lender.item.id, lender.user.id,
            { quantity: 2, customerId: (await ensureCustomer(lender.workspace.id, borrower.user)).id, periodUnit: 'WEEK', periodCount: 2, startDate: new Date().toISOString(), rate: '5000' },
        );
        await agreements().accept(offer.id, borrower.user.id, {
            borrowerWorkspaceId: borrower.workspace.id,
        });

        // Borrower's expense: 2 x 5000 x 2 = 20000, in the accepted workspace.
        const expense: any = await agreements().recordBorrowerExpense(offer.id, borrower.user.id, {
            cashbookId: borrowerBook.id,
        });
        expect(expense.type).toBe('EXPENSE');
        expect(expense.amount.toString()).toBe('20000');

        // A book in another of the borrower's workspaces is refused.
        const otherWs = await createWorkspace(borrower.user.id);
        const otherBook = await createCashbook(otherWs.id, borrower.user.id);
        await expect(agreements().recordBorrowerExpense(offer.id, borrower.user.id, {
            cashbookId: otherBook.id,
        })).rejects.toMatchObject({ code: 'WRONG_WORKSPACE' });

        // Lender's income: same figure, in the lender's own book.
        const lenderBook = await createCashbook(lender.workspace.id, lender.user.id);
        const income: any = await agreements().recordLenderIncome(offer.id, lender.user.id, {
            cashbookId: lenderBook.id,
        });
        expect(income.type).toBe('INCOME');
        expect(income.amount.toString()).toBe('20000');

        // The borrower cannot record the lender's income.
        await expect(agreements().recordLenderIncome(offer.id, borrower.user.id, {
            cashbookId: lenderBook.id,
        })).rejects.toMatchObject({ statusCode: 403 });
    });

    it('refuses recording the expense or income twice — one-time entries', async () => {
        const lender = await stockedOwner(`l8-${Date.now()}@test.local`, 'Tent', 6, '30000');
        const borrower = await userWithWorkspace(`b8-${Date.now()}@test.local`);
        const borrowerBook = await createCashbook(borrower.workspace.id, borrower.user.id);
        const lenderBook = await createCashbook(lender.workspace.id, lender.user.id);

        const offer: any = await agreements().create(
            lender.workspace.id, lender.item.id, lender.user.id,
            { quantity: 1, customerId: (await ensureCustomer(lender.workspace.id, borrower.user)).id, periodUnit: 'DAY', startDate: new Date().toISOString(), rate: '7000' },
        );
        await agreements().accept(offer.id, borrower.user.id, { borrowerWorkspaceId: borrower.workspace.id });

        // First records succeed.
        await agreements().recordBorrowerExpense(offer.id, borrower.user.id, { cashbookId: borrowerBook.id });
        await agreements().recordLenderIncome(offer.id, lender.user.id, { cashbookId: lenderBook.id });

        // Seconds are refused — the API can never double-bill the contract.
        await expect(agreements().recordBorrowerExpense(offer.id, borrower.user.id, {
            cashbookId: borrowerBook.id,
        })).rejects.toMatchObject({ code: 'ALREADY_RECORDED' });
        await expect(agreements().recordLenderIncome(offer.id, lender.user.id, {
            cashbookId: lenderBook.id,
        })).rejects.toMatchObject({ code: 'ALREADY_RECORDED' });

        // Exactly one entry of each kind exists, exposed on the agreement.
        const refreshed: any = await agreements().getForUser(offer.id, lender.user.id);
        expect(refreshed.expenseEntry?.id).toBeTruthy();
        expect(refreshed.incomeEntry?.id).toBeTruthy();
    });

    it('lists from both parties\' perspectives', async () => {
        const lender = await stockedOwner(`l4-${Date.now()}@test.local`, 'Speaker', 5, '8000');
        const borrower = await userWithWorkspace(`b4-${Date.now()}@test.local`);
        await agreements().create(
            lender.workspace.id, lender.item.id, lender.user.id,
            { quantity: 1, borrowerEmail: borrower.user.email, periodUnit: 'MONTH', startDate: new Date().toISOString() },
        );

        const asLender = await agreements().list(lender.user.id, {} as any);
        const asBorrower = await agreements().list(borrower.user.id, {} as any);
        const asLent = await agreements().list(lender.user.id, { direction: 'lent' } as any);
        expect(asLender.data).toHaveLength(1);
        expect(asBorrower.data).toHaveLength(1);
        expect(asLent.data).toHaveLength(1);

        // A stranger sees nothing.
        const stranger = await createUser();
        const asStranger = await agreements().list(stranger.id, {} as any);
        expect(asStranger.data).toHaveLength(0);
    });
});

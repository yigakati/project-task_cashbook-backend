/**
 * Idempotent chart-of-accounts provisioning.
 *
 * Every function here is safe to call repeatedly: they are invoked inline during
 * workspace / cashbook / wallet creation, and again by the backfill script for
 * data that predates the ledger.
 */
import { AccountClassification, LedgerAccountClass, LedgerAccountOrigin, Prisma } from '@prisma/client';
import { AuditAction } from '../../core/types';
import {
    BOOK_CASH_PARENT_CODE,
    CHART_OF_ACCOUNTS,
    DEFAULT_ACCOUNT_TYPES,
    WalletSeed,
    WALLET_ASSET_PARENT_CODE,
    WALLET_LIABILITY_PARENT_CODE,
    normalBalanceFor,
    walletSeedForCurrency,
} from './coa.template';
import type { SystemLedgerKey } from './ledger.types';

export type SystemAccountMap = Map<SystemLedgerKey, string>;

/**
 * Account code for a currency-scoped variant.
 *
 * The workspace's own currency uses the bare template code; any other currency
 * gets a suffixed sibling, e.g. `4100-USD`.
 */
function scopedCode(code: string, currency: string, baseCurrency: string): string {
    return currency === baseCurrency ? code : `${code}-${currency}`;
}

/**
 * Create this workspace's chart of accounts if absent, and return the
 * systemKey -> ledgerAccountId map that posting rules resolve against.
 *
 * @param currency  The currency this chart is denominated in.
 * @param baseCurrency  The workspace default; defaults to `currency`. Pass both
 *   when provisioning a secondary currency so the accounts get suffixed codes
 *   rather than colliding with the base chart.
 */
export async function ensureWorkspaceChartOfAccounts(
    tx: Prisma.TransactionClient,
    workspaceId: string,
    currency: string,
    baseCurrency: string = currency,
): Promise<SystemAccountMap> {
    const codeToId = new Map<string, string>();

    // Template order guarantees parents precede children.
    for (const row of CHART_OF_ACCOUNTS) {
        const code = scopedCode(row.code, currency, baseCurrency);
        const parentId = row.parentCode
            ? codeToId.get(scopedCode(row.parentCode, currency, baseCurrency)) ?? null
            : null;

        const account = await tx.ledgerAccount.upsert({
            where: { workspaceId_code: { workspaceId, code } },
            // Never overwrite an accountant's rename; only ensure existence.
            update: {},
            create: {
                workspaceId,
                code,
                name: currency === baseCurrency ? row.name : `${row.name} (${currency})`,
                class: row.class,
                normalBalance: normalBalanceFor(row.class),
                origin: LedgerAccountOrigin.SYSTEM,
                systemKey: row.systemKey ?? null,
                parentId,
                currency,
                isCashEquivalent: row.isCashEquivalent ?? false,
                isPostable: row.isPostable ?? true,
                isProtected: true,
            },
            select: { id: true },
        });

        codeToId.set(code, account.id);
    }

    const systemMap: SystemAccountMap = new Map();
    for (const row of CHART_OF_ACCOUNTS) {
        if (row.systemKey) {
            systemMap.set(row.systemKey, codeToId.get(scopedCode(row.code, currency, baseCurrency))!);
        }
    }

    return systemMap;
}

/**
 * Every currency this workspace actually holds money in.
 *
 * New data is always in the workspace currency — `createAccount` and
 * `createCashbook` both force it — but legacy rows predate that rule, and a
 * journal may never mix currencies.
 */
export async function workspaceCurrencies(
    tx: Prisma.TransactionClient,
    workspaceId: string,
): Promise<{ base: string; all: string[] }> {
    const workspace = await tx.workspace.findUniqueOrThrow({
        where: { id: workspaceId },
        select: { defaultCurrency: true },
    });

    const [cashbooks, accounts] = await Promise.all([
        tx.cashbook.findMany({ where: { workspaceId }, select: { currency: true } }),
        tx.account.findMany({ where: { workspaceId }, select: { currency: true } }),
    ]);

    const all = new Set<string>([workspace.defaultCurrency]);
    for (const c of cashbooks) all.add(c.currency);
    for (const a of accounts) all.add(a.currency);

    return { base: workspace.defaultCurrency, all: [...all].sort() };
}

/** Seed the default wallet types. Without these a new workspace cannot create a wallet. */
export async function ensureDefaultAccountTypes(
    tx: Prisma.TransactionClient,
    workspaceId: string,
): Promise<void> {
    for (const type of DEFAULT_ACCOUNT_TYPES) {
        await tx.accountType.upsert({
            where: { name_workspaceId: { name: type.name, workspaceId } },
            update: {},
            create: {
                workspaceId,
                name: type.name,
                classification: type.classification as AccountClassification,
            },
        });
    }
}

/** Next free numeric suffix under a parent, e.g. 1100-3. */
async function nextChildCode(
    tx: Prisma.TransactionClient,
    workspaceId: string,
    parentCode: string,
): Promise<string> {
    const siblings = await tx.ledgerAccount.findMany({
        where: { workspaceId, code: { startsWith: `${parentCode}-` } },
        select: { code: true },
    });

    const highest = siblings.reduce((max, s) => {
        const n = Number.parseInt(s.code.slice(parentCode.length + 1), 10);
        return Number.isFinite(n) && n > max ? n : max;
    }, 0);

    return `${parentCode}-${highest + 1}`;
}

/**
 * The ledger account backing a wallet. ASSET wallets are cash equivalents and
 * feed the cash flow statement; LIABILITY wallets (credit cards, loans) are not.
 */
export async function ensureWalletLedgerAccount(
    tx: Prisma.TransactionClient,
    account: { id: string; workspaceId: string; name: string; currency: string; ledgerAccountId?: string | null },
    classification: AccountClassification,
): Promise<string> {
    if (account.ledgerAccountId) return account.ledgerAccountId;

    const existing = await tx.account.findUnique({
        where: { id: account.id },
        select: { ledgerAccountId: true },
    });
    if (existing?.ledgerAccountId) return existing.ledgerAccountId;

    const isAsset = classification === AccountClassification.ASSET;
    const parentCode = isAsset ? WALLET_ASSET_PARENT_CODE : WALLET_LIABILITY_PARENT_CODE;

    const parent = await tx.ledgerAccount.findUnique({
        where: { workspaceId_code: { workspaceId: account.workspaceId, code: parentCode } },
        select: { id: true },
    });

    const ledgerAccount = await tx.ledgerAccount.create({
        data: {
            workspaceId: account.workspaceId,
            code: await nextChildCode(tx, account.workspaceId, parentCode),
            name: account.name,
            class: isAsset ? LedgerAccountClass.ASSET : LedgerAccountClass.LIABILITY,
            normalBalance: normalBalanceFor(isAsset ? LedgerAccountClass.ASSET : LedgerAccountClass.LIABILITY),
            origin: LedgerAccountOrigin.WALLET,
            parentId: parent?.id ?? null,
            currency: account.currency,
            isCashEquivalent: isAsset,
            isProtected: true,
        },
        select: { id: true },
    });

    await tx.account.update({
        where: { id: account.id },
        data: { ledgerAccountId: ledgerAccount.id },
    });

    return ledgerAccount.id;
}

/**
 * The ledger account holding a cashbook's unallocated book cash.
 *
 * This is the piece that makes the product's core rule fall out of double-entry:
 * an entry with no wallet routes its cash leg here, an entry with a wallet
 * routes it to the wallet instead. Nothing has to special-case
 * "wallet-linked entries do not move the book balance" — it is simply where the
 * debit went.
 */
export async function ensureCashbookLedgerAccount(
    tx: Prisma.TransactionClient,
    cashbook: { id: string; workspaceId: string; name: string; currency: string; cashLedgerAccountId?: string | null },
): Promise<string> {
    if (cashbook.cashLedgerAccountId) return cashbook.cashLedgerAccountId;

    const existing = await tx.cashbook.findUnique({
        where: { id: cashbook.id },
        select: { cashLedgerAccountId: true },
    });
    if (existing?.cashLedgerAccountId) return existing.cashLedgerAccountId;

    const parent = await tx.ledgerAccount.findUnique({
        where: { workspaceId_code: { workspaceId: cashbook.workspaceId, code: BOOK_CASH_PARENT_CODE } },
        select: { id: true },
    });

    const ledgerAccount = await tx.ledgerAccount.create({
        data: {
            workspaceId: cashbook.workspaceId,
            code: await nextChildCode(tx, cashbook.workspaceId, BOOK_CASH_PARENT_CODE),
            name: `${cashbook.name} — Book Cash`,
            class: LedgerAccountClass.ASSET,
            normalBalance: normalBalanceFor(LedgerAccountClass.ASSET),
            origin: LedgerAccountOrigin.BOOK_CASH,
            parentId: parent?.id ?? null,
            currency: cashbook.currency,
            isCashEquivalent: true,
            isProtected: true,
        },
        select: { id: true },
    });

    await tx.cashbook.update({
        where: { id: cashbook.id },
        data: { cashLedgerAccountId: ledgerAccount.id },
    });

    return ledgerAccount.id;
}

/**
 * Everything a workspace needs before it can post: chart of accounts and the
 * default wallet types.
 */
export async function provisionWorkspaceAccounting(
    tx: Prisma.TransactionClient,
    workspaceId: string,
    currency: string,
): Promise<SystemAccountMap> {
    const systemMap = await ensureWorkspaceChartOfAccounts(tx, workspaceId, currency);
    await ensureDefaultAccountTypes(tx, workspaceId);
    return systemMap;
}

/** @deprecated Use seedDefaultWalletAccounts — kept for older callers; the
 *  seed list is now chosen by currency inside the seeder itself. */
export const DEFAULT_WALLET_ACCOUNTS = walletSeedForCurrency('UGX');

/**
 * The wallets a workspace is born with — chosen by currency, so a Kenyan
 * workspace opens with M-Pesa, a Ugandan one with MTN MoMo and Airtel Money,
 * a USD one with PayPal. Bank and Cash on Hand are universal.
 *
 * Idempotent by name: an account the user (or a previous seed run) already
 * created under the same name is left exactly as it is, including its balance
 * and ledger link. Callers should have provisioned the chart first
 * (provisionWorkspaceAccounting) so wallet ledger accounts land under the
 * right parent.
 */
export async function seedDefaultWalletAccounts(
    tx: Prisma.TransactionClient,
    workspaceId: string,
    currency: string,
    userId: string,
): Promise<void> {
    await seedWallets(tx, workspaceId, currency, userId, walletSeedForCurrency(currency));
}

/** The shared wallet-creation core: create any missing seed wallets, each
 *  with its ledger account, skipping ones that already exist by name. */
export async function seedWallets(
    tx: Prisma.TransactionClient,
    workspaceId: string,
    currency: string,
    userId: string,
    seeds: readonly WalletSeed[],
): Promise<void> {
    await ensureDefaultAccountTypes(tx, workspaceId);

    for (const wallet of seeds) {
        const existing = await tx.account.findFirst({
            where: { workspaceId, name: wallet.name },
            select: { id: true },
        });
        if (existing) continue;

        const accountType = await tx.accountType.findUnique({
            where: { name_workspaceId: { name: wallet.accountTypeName, workspaceId } },
            select: { id: true, name: true },
        });
        if (!accountType) continue;

        const account = await tx.account.create({
            data: {
                workspaceId,
                accountTypeId: accountType.id,
                name: wallet.name,
                currency,
                icon: wallet.icon,
                balance: new Prisma.Decimal(0),
            },
        });

        // Real wallets carry real journal lines; give each its ledger account
        // before the first entry ever touches it.
        await ensureWalletLedgerAccount(
            tx,
            { id: account.id, workspaceId, name: wallet.name, currency },
            AccountClassification.ASSET,
        );

        await tx.auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.ACCOUNT_CREATED,
                resource: 'account',
                resourceId: account.id,
                details: {
                    name: wallet.name,
                    type: accountType.name,
                    currency,
                    seeded: true,
                } as any,
            },
        });
    }
}

/**
 * The one book a workspace is born with: "Cash Journal {current year}", so a
 * new user's first entry has somewhere to live without learning what a
 * cashbook is. Existing workspaces are untouched — this runs only from the
 * workspace-creation paths.
 *
 * Idempotent: a workspace that already has any cashbook (user-created or a
 * previous seed) keeps exactly what it has.
 */
export async function seedDefaultCashbook(
    tx: Prisma.TransactionClient,
    workspaceId: string,
    currency: string,
    userId: string,
): Promise<void> {
    const existing = await tx.cashbook.findFirst({
        where: { workspaceId },
        select: { id: true },
    });
    if (existing) return;

    const year = new Date().getFullYear();
    const cashbook = await tx.cashbook.create({
        data: {
            name: `Cash Journal ${year}`,
            currency,
            workspace: { connect: { id: workspaceId } },
        },
        select: { id: true, name: true, currency: true },
    });

    await ensureCashbookLedgerAccount(tx, {
        id: cashbook.id,
        workspaceId,
        name: cashbook.name,
        currency: cashbook.currency,
    });

    await tx.auditLog.create({
        data: {
            userId,
            workspaceId,
            action: AuditAction.CASHBOOK_CREATED,
            resource: 'cashbook',
            resourceId: cashbook.id,
            details: { name: cashbook.name, currency, seeded: true } as any,
        },
    });
}

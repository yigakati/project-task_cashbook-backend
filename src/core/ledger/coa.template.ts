/**
 * The chart of accounts every workspace is seeded with.
 *
 * Users never see most of this. The Accounts page continues to show only wallet
 * accounts; the full chart is an accountant-only surface. Categories map onto
 * the income/expense accounts optionally — unmapped categories fall back to
 * SALES_REVENUE / GENERAL_EXPENSES, so the entry flow is unchanged.
 */
import { LedgerAccountClass, NormalBalance } from '@prisma/client';
import type { SystemLedgerKey } from './ledger.types';

export interface CoaTemplateRow {
    code: string;
    name: string;
    class: LedgerAccountClass;
    systemKey?: SystemLedgerKey;
    parentCode?: string;
    /** Counts toward the direct-method cash flow statement. */
    isCashEquivalent?: boolean;
    /** Roll-up parents are presentation-only and cannot be posted to. */
    isPostable?: boolean;
}

/** Debit-normal: assets and expenses. Credit-normal: everything else. */
export function normalBalanceFor(klass: LedgerAccountClass): NormalBalance {
    return klass === LedgerAccountClass.ASSET || klass === LedgerAccountClass.EXPENSE
        ? NormalBalance.DEBIT
        : NormalBalance.CREDIT;
}

const { ASSET, LIABILITY, EQUITY, INCOME, EXPENSE } = LedgerAccountClass;

export const CHART_OF_ACCOUNTS: readonly CoaTemplateRow[] = [
    // ─── Assets ───────────────────────────────────────────────
    { code: '1000', name: 'Assets', class: ASSET, isPostable: false },
    // Parent of one child per Cashbook — its unallocated book cash.
    { code: '1010', name: 'Book Cash', class: ASSET, parentCode: '1000', isPostable: false },
    // Parent of one child per ASSET wallet.
    { code: '1100', name: 'Wallets', class: ASSET, parentCode: '1000', isPostable: false },
    { code: '1200', name: 'Accounts Receivable', class: ASSET, parentCode: '1000', systemKey: 'AR' },
    { code: '1300', name: 'Inventory', class: ASSET, parentCode: '1000', systemKey: 'INVENTORY' },
    { code: '1310', name: 'Inventory On Rent', class: ASSET, parentCode: '1000', systemKey: 'INVENTORY_ON_RENT' },
    { code: '1900', name: 'Suspense', class: ASSET, parentCode: '1000', systemKey: 'SUSPENSE' },

    // ─── Liabilities ──────────────────────────────────────────
    { code: '2000', name: 'Liabilities', class: LIABILITY, isPostable: false },
    { code: '2100', name: 'Accounts Payable', class: LIABILITY, parentCode: '2000', systemKey: 'AP' },
    { code: '2200', name: 'Tax Payable', class: LIABILITY, parentCode: '2000', systemKey: 'TAX_PAYABLE' },
    // The cash-basis offsets. A receivable is recognized as an asset against
    // this liability rather than as revenue, so the balance sheet shows AR while
    // the P&L stays strictly cash-basis. Revenue moves out of here when cash lands.
    { code: '2400', name: 'Deferred Revenue (Cash-Basis Offset)', class: LIABILITY, parentCode: '2000', systemKey: 'DEFERRED_REVENUE' },
    { code: '2450', name: 'Deferred Purchases (Cash-Basis Offset)', class: LIABILITY, parentCode: '2000', systemKey: 'DEFERRED_EXPENSE' },
    // Parent of one child per LIABILITY wallet (credit cards, loans).
    { code: '2900', name: 'Wallet Liabilities', class: LIABILITY, parentCode: '2000', isPostable: false },

    // ─── Equity ───────────────────────────────────────────────
    { code: '3000', name: 'Equity', class: EQUITY, isPostable: false },
    { code: '3100', name: 'Opening Balance Equity', class: EQUITY, parentCode: '3000', systemKey: 'OPENING_BALANCE_EQUITY' },
    { code: '3200', name: 'Retained Earnings', class: EQUITY, parentCode: '3000', systemKey: 'RETAINED_EARNINGS' },
    { code: '3900', name: 'Owner Drawings', class: EQUITY, parentCode: '3000', systemKey: 'OWNER_DRAWINGS' },

    // ─── Income ───────────────────────────────────────────────
    { code: '4000', name: 'Income', class: INCOME, isPostable: false },
    { code: '4100', name: 'Sales Revenue', class: INCOME, parentCode: '4000', systemKey: 'SALES_REVENUE' },
    { code: '4200', name: 'Rental Income', class: INCOME, parentCode: '4000', systemKey: 'RENTAL_INCOME' },
    { code: '4900', name: 'Other Income', class: INCOME, parentCode: '4000', systemKey: 'OTHER_INCOME' },

    // ─── Expenses ─────────────────────────────────────────────
    { code: '5000', name: 'Expenses', class: EXPENSE, isPostable: false },
    { code: '5100', name: 'Cost of Goods Sold', class: EXPENSE, parentCode: '5000', systemKey: 'COGS' },
    { code: '5200', name: 'General Expenses', class: EXPENSE, parentCode: '5000', systemKey: 'GENERAL_EXPENSES' },
    // Charges on entries and transfer fees land here.
    { code: '5300', name: 'Transaction Fees', class: EXPENSE, parentCode: '5000', systemKey: 'TRANSACTION_FEES' },
    { code: '5400', name: 'Inventory Adjustments', class: EXPENSE, parentCode: '5000', systemKey: 'INVENTORY_ADJUSTMENT' },
] as const;

/** Parent codes the per-wallet and per-cashbook accounts hang from. */
export const BOOK_CASH_PARENT_CODE = '1010';
export const WALLET_ASSET_PARENT_CODE = '1100';
export const WALLET_LIABILITY_PARENT_CODE = '2900';

/**
 * Default wallet types. AccountType was seeded NOWHERE before this, which meant
 * a brand-new workspace could not create a wallet at all — createAccount
 * requires an accountTypeId and nothing produced one.
 */
export const DEFAULT_ACCOUNT_TYPES = [
    { name: 'Bank', classification: 'ASSET' },
    { name: 'Cash', classification: 'ASSET' },
    { name: 'Mobile Money', classification: 'ASSET' },
    // Online money services (PayPal, Wise, ...) — not a bank, not a carrier
    // float, not cash. USD workspaces are born with one (PayPal).
    { name: 'Digital Wallet', classification: 'ASSET' },
    { name: 'Credit Card', classification: 'LIABILITY' },
    { name: 'Loan', classification: 'LIABILITY' },
] as const;

export interface WalletSeed {
    name: string;
    accountTypeName: string;
    icon: string;
}

const BANK_SEED: WalletSeed = { name: 'Bank', accountTypeName: 'Bank', icon: 'Landmark' };
const CASH_SEED: WalletSeed = { name: 'Cash on Hand', accountTypeName: 'Cash', icon: 'Banknote' };

/**
 * The wallets a workspace is born with, per currency: the ways money is
 * actually held where that currency circulates. Each maps onto its
 * DEFAULT_ACCOUNT_TYPES counterpart, so a user adding another bank account
 * later lands on the same "Bank" type and the taxonomy stays one thing.
 *
 * Mobile money is split per provider — separate floats on separate phones —
 * and every provider stays under the one "Mobile Money" account type, so
 * reports and type filters still see them as one class of wallet.
 *
 * The providers per country (the dominant licensed services):
 *   UGX  Uganda      — MTN MoMo, Airtel Money
 *   KES  Kenya       — M-Pesa (Safaricom), Airtel Money
 *   TZS  Tanzania    — M-Pesa (Vodacom), Tigo Pesa, Airtel Money
 *   RWF  Rwanda      — MTN MoMo, Airtel Money
 *   BIF  Burundi     — Lumicash (Lumitel)
 *   SSP  South Sudan — mGURUSH
 *   ETB  Ethiopia    — Telebirr (Ethio Telecom)
 *   USD  Global      — PayPal (an online wallet, not a carrier float — no
 *                      mobile money)
 * Currencies with no known provider ecosystem fall back to Bank + Cash on
 * Hand, the universal pair.
 *
 * Icons come from the frontend's ACCOUNT_ICONS list — pick values that render
 * there, or the wallet shows the fallback glyph.
 */
export const WALLET_SEEDS_BY_CURRENCY: Record<string, readonly WalletSeed[]> = {
    UGX: [
        { name: 'Airtel Money', accountTypeName: 'Mobile Money', icon: 'HandCoins' },
        { name: 'MTN MoMo', accountTypeName: 'Mobile Money', icon: 'Wallet' },
        BANK_SEED,
        CASH_SEED,
    ],
    KES: [
        { name: 'M-Pesa', accountTypeName: 'Mobile Money', icon: 'Coins' },
        { name: 'Airtel Money', accountTypeName: 'Mobile Money', icon: 'HandCoins' },
        BANK_SEED,
        CASH_SEED,
    ],
    TZS: [
        { name: 'M-Pesa', accountTypeName: 'Mobile Money', icon: 'Coins' },
        { name: 'Tigo Pesa', accountTypeName: 'Mobile Money', icon: 'HandCoins' },
        { name: 'Airtel Money', accountTypeName: 'Mobile Money', icon: 'Wallet' },
        BANK_SEED,
        CASH_SEED,
    ],
    RWF: [
        { name: 'MTN MoMo', accountTypeName: 'Mobile Money', icon: 'Wallet' },
        { name: 'Airtel Money', accountTypeName: 'Mobile Money', icon: 'HandCoins' },
        BANK_SEED,
        CASH_SEED,
    ],
    BIF: [
        { name: 'Lumicash', accountTypeName: 'Mobile Money', icon: 'HandCoins' },
        BANK_SEED,
        CASH_SEED,
    ],
    SSP: [
        { name: 'mGURUSH', accountTypeName: 'Mobile Money', icon: 'HandCoins' },
        BANK_SEED,
        CASH_SEED,
    ],
    ETB: [
        { name: 'Telebirr', accountTypeName: 'Mobile Money', icon: 'Coins' },
        BANK_SEED,
        CASH_SEED,
    ],
    USD: [
        { name: 'PayPal', accountTypeName: 'Digital Wallet', icon: 'CircleDollarSign' },
        BANK_SEED,
        CASH_SEED,
    ],
};

/** The wallet seed list for a currency; unknown currencies get the universal
 *  Bank + Cash on Hand pair. */
export function walletSeedForCurrency(currency: string): readonly WalletSeed[] {
    const normalized = (currency || '').trim().toUpperCase();
    return WALLET_SEEDS_BY_CURRENCY[normalized] ?? [BANK_SEED, CASH_SEED];
}

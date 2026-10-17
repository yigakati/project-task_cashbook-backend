/**
 * What each plan offers, and what it costs.
 *
 * Defined in code, not the database: prices and limits change with the
 * product, and a deploy that ships a new catalogue and a new screen at the
 * same time cannot drift from a row someone edited by hand. A user's chosen
 * plan (and any storage add-on) lives in the database; everything about what
 * that plan *means* is here.
 *
 * All prices are UGX per month, the currency the product bills in. Numbers
 * are integers: mobile-money amounts are whole shillings.
 *
 *   Plan        Workspaces  Storage/workspace  Extra storage (0.5 GB steps)
 *   Free        1           1 GB               —
 *   Starter     5           2.5 GB             +500/GB, up to 10 GB
 *   Growth      15          10 GB              +400/GB, up to 50 GB
 *   Enterprise  custom      custom             —
 *
 * Growth is three times Starter's price for three times the workspaces and
 * four times the storage — a straight ladder rather than a cliff, so moving
 * up never costs more per workspace than staying put. The per-GB add-on gets
 * cheaper as the plan gets bigger, the way storage bundles do everywhere.
 */

export const PLAN_KEYS = ['FREE', 'STARTER', 'GROWTH'] as const;
export type PlanKey = (typeof PLAN_KEYS)[number];
/** What an account can be on: a listed plan, or Enterprise by arrangement. */
export type AccountPlanKey = PlanKey | 'ENTERPRISE';

export interface Plan {
    key: PlanKey;
    name: string;
    /** UGX per month, before any storage add-on. */
    priceUgx: number;
    /** Business workspaces the account may own. The personal one is separate and always allowed. */
    businessWorkspaces: number;
    /** Storage included with every workspace, in GB. */
    includedStorageGb: number;
    /** UGX per extra GB per workspace per month; null when storage can't be added. */
    extraStoragePerGbUgx: number | null;
    /** The most storage one workspace may reach on this plan, in GB. */
    maxStorageGb: number;
    tagline: string;
    features: string[];
}

export const PLANS: Record<PlanKey, Plan> = {
    FREE: {
        key: 'FREE',
        name: 'Free',
        priceUgx: 0,
        businessWorkspaces: 1,
        includedStorageGb: 1,
        extraStoragePerGbUgx: null,
        maxStorageGb: 1,
        tagline: 'Start keeping proper books.',
        features: [
            'Your personal books, always',
            '1 business workspace',
            '1 GB of storage per workspace',
            'Entries, wallets, invoices, reports',
            'Targets and daily goals',
        ],
    },
    STARTER: {
        key: 'STARTER',
        name: 'Starter',
        priceUgx: 5000,
        businessWorkspaces: 5,
        includedStorageGb: 2.5,
        extraStoragePerGbUgx: 500,
        maxStorageGb: 10,
        tagline: 'For a growing shop or a small business.',
        features: [
            'Up to 5 business workspaces',
            '2.5 GB of storage per workspace',
            'Add storage up to 10 GB per workspace',
            'Team members and roles',
            'Everything in Free',
        ],
    },
    GROWTH: {
        key: 'GROWTH',
        name: 'Growth',
        priceUgx: 15000,
        businessWorkspaces: 15,
        includedStorageGb: 10,
        extraStoragePerGbUgx: 400,
        maxStorageGb: 50,
        tagline: 'For several businesses under one account.',
        features: [
            'Up to 15 business workspaces',
            '10 GB of storage per workspace',
            'Add storage up to 50 GB per workspace',
            'Priority support',
            'Everything in Starter',
        ],
    },
};

/** Not sold on the pricing page — by arrangement. */
export const ENTERPRISE = {
    name: 'Enterprise',
    tagline: 'For larger organisations and groups.',
    features: ['Unlimited workspaces', 'Storage to fit', 'Onboarding and training', 'Invoiced billing'],
} as const;

/** Storage is added in half-gigabyte steps, so 2.5 GB can become exactly 5 GB. */
export const STORAGE_STEP_GB = 0.5;

/** Largest add-on one workspace can buy on a plan, in GB (0 when there's none). */
export const maxExtraStorageGb = (plan: Plan) => Math.max(0, plan.maxStorageGb - plan.includedStorageGb);

/** Snap a requested add-on to a whole step within the plan's range. */
export const clampExtraStorage = (plan: Plan, requestedGb: number) => {
    const steps = Math.round(Math.max(0, requestedGb) / STORAGE_STEP_GB);
    return Math.min(steps * STORAGE_STEP_GB, maxExtraStorageGb(plan));
};

/** Storage a workspace gets on a plan, add-on included, in GB. */
export const storageFor = (plan: Plan, extraStorageGb: number) =>
    plan.includedStorageGb + clampExtraStorage(plan, extraStorageGb);

/** A plan, the storage chosen, and what it costs — the one shape the UI and checkout share. */
export interface PlanQuote {
    plan: PlanKey;
    name: string;
    /** Business workspaces allowed. */
    businessWorkspaces: number;
    includedStorageGb: number;
    extraStorageGb: number;
    maxExtraStorageGb: number;
    storageStepGb: number;
    storageGb: number;
    /** UGX per extra GB per month; null when storage can't be added. */
    extraStoragePerGbUgx: number | null;
    basePriceUgx: number;
    storagePriceUgx: number;
    totalUgx: number;
    currency: 'UGX';
    billingPeriod: 'month';
}

export function quote(plan: Plan, requestedExtraGb = 0): PlanQuote {
    const extra = plan.extraStoragePerGbUgx == null ? 0 : clampExtraStorage(plan, requestedExtraGb);
    const storagePriceUgx = Math.round((plan.extraStoragePerGbUgx ?? 0) * extra);
    return {
        plan: plan.key,
        name: plan.name,
        businessWorkspaces: plan.businessWorkspaces,
        includedStorageGb: plan.includedStorageGb,
        extraStorageGb: extra,
        maxExtraStorageGb: maxExtraStorageGb(plan),
        storageStepGb: STORAGE_STEP_GB,
        storageGb: plan.includedStorageGb + extra,
        extraStoragePerGbUgx: plan.extraStoragePerGbUgx,
        basePriceUgx: plan.priceUgx,
        storagePriceUgx,
        totalUgx: plan.priceUgx + storagePriceUgx,
        currency: 'UGX',
        billingPeriod: 'month',
    };
}

/** Everything the pricing page shows, as one document. */
export function catalogue() {
    return {
        currency: 'UGX' as const,
        billingPeriod: 'month' as const,
        plans: PLAN_KEYS.map((key) => {
            const plan = PLANS[key];
            return {
                ...plan,
                maxExtraStorageGb: maxExtraStorageGb(plan),
                quote: quote(plan),
            };
        }),
        enterprise: ENTERPRISE,
    };
}

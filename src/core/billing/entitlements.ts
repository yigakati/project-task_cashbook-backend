import { Prisma, PrismaClient, WorkspaceType } from '@prisma/client';
import { PLANS, storageFor, type AccountPlanKey } from './plans';

type DbClient = PrismaClient | Prisma.TransactionClient;

const GIB = 1024 ** 3;
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Days a paid plan keeps working after its period ends, so a renewal paid a
 * day late doesn't flip a business to Free (and its storage with it) overnight.
 */
export const RENEWAL_GRACE_DAYS = 3;

/**
 * Whether a subscription row still gives its plan. A period with no end is
 * one set by hand (Enterprise, or a plan granted by support) and never lapses.
 */
export function isInForce(
    row: { plan: string; status: string; currentPeriodEnd: Date | null } | null,
    now = new Date(),
): boolean {
    if (!row || row.status !== 'ACTIVE') return false;
    if (!row.currentPeriodEnd) return true;
    return row.currentPeriodEnd.getTime() + RENEWAL_GRACE_DAYS * DAY_MS > now.getTime();
}

/** The plan an account is on; no row, a cancelled row or a lapsed period means Free. */
export async function planOf(db: DbClient, userId: string, now = new Date()): Promise<{ plan: AccountPlanKey; extraStorageGb: number }> {
    const row = await db.userSubscription.findUnique({
        where: { userId },
        select: { plan: true, status: true, extraStorageGb: true, currentPeriodEnd: true },
    });
    if (!row || !isInForce(row, now)) return { plan: 'FREE', extraStorageGb: 0 };
    return { plan: row.plan as AccountPlanKey, extraStorageGb: Number(row.extraStorageGb) };
}

/** Business workspaces the account may own; Infinity for Enterprise. */
export async function businessWorkspaceLimit(db: DbClient, userId: string): Promise<number> {
    const { plan } = await planOf(db, userId);
    return plan === 'ENTERPRISE' ? Infinity : PLANS[plan].businessWorkspaces;
}

export async function ownedBusinessWorkspaces(db: DbClient, userId: string): Promise<number> {
    return db.workspace.count({ where: { ownerId: userId, type: WorkspaceType.BUSINESS, isActive: true } });
}

/**
 * Storage a paid plan gives each of the owner's workspaces, in bytes, add-on
 * included. Null when the plan sets nothing of its own: Free (whose 1 GB is the
 * platform default, which a superadmin may change or grant around) and
 * Enterprise (set per workspace).
 */
export async function planStorageBytes(db: DbClient, ownerId: string): Promise<number | null> {
    const { plan, extraStorageGb } = await planOf(db, ownerId);
    if (plan === 'ENTERPRISE' || plan === 'FREE') return null;
    return Math.round(storageFor(PLANS[plan], extraStorageGb) * GIB);
}

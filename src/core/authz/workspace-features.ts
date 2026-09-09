import { FeatureKey, Prisma, PrismaClient } from '@prisma/client';
import { AppError } from '../errors/AppError';

type DbClient = PrismaClient | Prisma.TransactionClient;

/**
 * Whether a superadmin has unlocked a module for this workspace.
 *
 * Presence of the row is the grant — absence means off, so a feature is never
 * accidentally on because a column defaulted to true somewhere.
 */
export async function isFeatureEnabled(
    db: DbClient,
    workspaceId: string,
    feature: FeatureKey,
): Promise<boolean> {
    const row = await db.workspaceFeature.findUnique({
        where: { workspaceId_feature: { workspaceId, feature } },
        select: { id: true },
    });
    return Boolean(row);
}

/**
 * Refuse an action that needs a granted feature.
 *
 * Checked on the server and not merely hidden in the UI: a hidden button is a
 * courtesy, not a restriction, and these endpoints are reachable directly.
 */
export async function assertFeatureEnabled(
    db: DbClient,
    workspaceId: string,
    feature: FeatureKey,
    message: string,
): Promise<void> {
    if (!(await isFeatureEnabled(db, workspaceId, feature))) {
        throw new AppError(message, 403, 'FEATURE_NOT_ENABLED');
    }
}

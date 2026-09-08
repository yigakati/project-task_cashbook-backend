import { Prisma, PrismaClient } from '@prisma/client';
import { NotFoundError } from '../../core/errors/AppError';

/** Works against the client or inside a transaction — callers need both. */
type DbClient = PrismaClient | Prisma.TransactionClient;

/**
 * Get a workspace's profile, creating it from what is already known if it does
 * not exist yet.
 *
 * The defaults matter more than they look. A workspace already has a name, and
 * its owner already has a verified email on their account — so a profile that
 * would otherwise be blank starts out complete enough to share. That turns the
 * "fill in your details before you can accept" gate from something almost
 * everyone hits into a genuine backstop for the rare workspace that really has
 * nothing usable.
 *
 * The owner's address is a STARTING POINT, not a binding. It is copied once,
 * here, and from then on it is the workspace's own value: changing it later
 * (to billing@, accounts@, whatever the org actually uses) is a plain edit,
 * and it deliberately does not follow the owner's account email around
 * afterwards.
 */
export async function ensureWorkspaceProfile(db: DbClient, workspaceId: string) {
    const existing = await db.workspaceProfile.findUnique({ where: { workspaceId } });
    if (existing) return existing;

    const workspace = await db.workspace.findUnique({
        where: { id: workspaceId },
        select: { id: true, name: true, owner: { select: { email: true } } },
    });
    if (!workspace) throw new NotFoundError('Workspace');

    return db.workspaceProfile.create({
        data: {
            workspaceId,
            displayName: workspace.name,
            email: workspace.owner?.email ?? null,
        },
    });
}

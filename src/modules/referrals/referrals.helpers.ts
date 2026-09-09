import { AuthProvider, Prisma, PrismaClient, ReferralSource, ReferralStatus } from '@prisma/client';
import { randomInt } from 'node:crypto';
import { AuditAction } from '../../core/types';
import { logger } from '../../utils/logger';

type DbClient = PrismaClient | Prisma.TransactionClient;

/**
 * Codes get read aloud, written on paper and retyped from memory, so the
 * alphabet excludes every pair that gets confused doing that: O/0, I/1/L, and
 * lowercase entirely. Eight characters over 32 symbols is ~40 bits, far more
 * than enough to make guessing another agent's code pointless.
 */
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const CODE_LENGTH = 8;

function randomCode(): string {
    let out = '';
    for (let i = 0; i < CODE_LENGTH; i += 1) {
        out += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
    }
    return out;
}

/**
 * A code no agent already holds.
 *
 * Retries rather than trusting the first draw: the unique index is the real
 * guarantee, and a handful of attempts keeps a collision from surfacing as a
 * failed appointment.
 */
export async function generateUniqueReferralCode(db: DbClient): Promise<string> {
    for (let attempt = 0; attempt < 8; attempt += 1) {
        const code = randomCode();
        const taken = await db.referralAgent.findUnique({ where: { code }, select: { id: true } });
        if (!taken) return code;
    }
    throw new Error('Could not generate an unused referral code');
}

/** Codes travel through URLs and handwriting; compare them forgivingly. */
export function normalizeReferralCode(raw: string): string {
    return raw.trim().toUpperCase();
}

/**
 * Credit a new account to the agent whose code it arrived with.
 *
 * Deliberately best-effort: a code that is unknown, revoked, or the user's own
 * must never fail the signup that carries it. Someone mistyping a code is not
 * a reason to refuse them an account, and the alternative — a hard error at
 * the last step of registration — would lose the signup entirely.
 *
 * Attribution is first-touch and written once. The unique index on
 * `referredUserId` is what actually enforces that.
 */
export async function attributeReferral(
    tx: Prisma.TransactionClient,
    params: {
        rawCode: string | undefined | null;
        userId: string;
        signupMethod: AuthProvider;
        source: ReferralSource;
        /**
         * Whether the address is already proven at signup.
         *
         * True for Google/OC, where the provider verified it before we ever
         * saw it — those accounts are created with `emailVerified: true` and
         * never pass through the OTP step, so a referral that waited for
         * `verifyEmail` to promote it would wait forever.
         */
        emailVerified: boolean;
    },
): Promise<void> {
    const { rawCode, userId, signupMethod, source, emailVerified } = params;
    if (!rawCode?.trim()) return;

    const code = normalizeReferralCode(rawCode);

    try {
        const agent = await tx.referralAgent.findUnique({
            where: { code },
            select: { id: true, userId: true, isActive: true },
        });

        if (!agent) {
            logger.info('Referral code did not match any agent', { code });
            return;
        }
        if (!agent.isActive) {
            logger.info('Referral code belongs to a revoked agent', { code });
            return;
        }
        if (agent.userId === userId) {
            // Self-referral. Cheap to attempt and pointless to allow.
            logger.warn('Referral code used on its own owner\'s signup', { code, userId });
            return;
        }

        await tx.referral.create({
            data: {
                agentId: agent.id,
                referredUserId: userId,
                code,
                source,
                signupMethod,
                // Recorded from the account's actual state rather than assumed
                // unverified. A social signup arrives already proven, and has
                // no later step that could ever promote it.
                status: emailVerified ? ReferralStatus.VERIFIED : ReferralStatus.SIGNED_UP,
                verifiedAt: emailVerified ? new Date() : null,
            },
        });

        await tx.auditLog.create({
            data: {
                userId,
                action: AuditAction.REFERRAL_ATTRIBUTED,
                resource: 'referral',
                resourceId: agent.id,
                details: { code, source, signupMethod } as any,
            },
        });
    } catch (error) {
        // Includes the unique-violation case: this account was already
        // attributed, and first touch wins.
        logger.error('Referral attribution skipped', {
            code,
            userId,
            error: error instanceof Error ? error.message : error,
        });
    }
}

/**
 * Promote a referral to VERIFIED once the person proves the address is theirs.
 *
 * Without this every count would include typos and throwaways, which is
 * exactly the number an agent would be paid on.
 */
export async function markReferralVerified(db: DbClient, userId: string): Promise<void> {
    try {
        await db.referral.updateMany({
            where: { referredUserId: userId, status: ReferralStatus.SIGNED_UP },
            data: { status: ReferralStatus.VERIFIED, verifiedAt: new Date() },
        });
    } catch (error) {
        logger.error('Could not mark referral verified', {
            userId,
            error: error instanceof Error ? error.message : error,
        });
    }
}

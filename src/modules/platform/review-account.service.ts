import { injectable, inject } from 'tsyringe';
import { AuthProvider, Prisma, PrismaClient, WorkspaceType } from '@prisma/client';
import bcrypt from 'bcryptjs';
import { config, superAdminEmails } from '../../config';
import { AuditAction } from '../../core/types';
import { currencyForCountry } from '../../core/finance';
import {
    provisionWorkspaceAccounting,
    seedDefaultCashbook,
    seedDefaultWalletAccounts,
} from '../../core/ledger/coa.seed';
import { logger } from '../../utils/logger';

/** Serialises every replica's attempt; held only for the transaction. */
const LOCK_KEY = 'bootstrap:review-account';
const FIRST_NAME = 'App';
const LAST_NAME = 'Reviewer';
/** Uganda: UGX books with the local wallets, like most of the product's users. */
const COUNTRY = 'UG';

export type ReviewAccountStatus = 'disabled' | 'refused' | 'unchanged' | 'created' | 'repaired';

export interface ReviewAccountResult {
    status: ReviewAccountStatus;
    email?: string;
    /** What a repair put right. */
    repaired?: string[];
}

type Credentials = { email: string; password: string };

const ownedPersonal = (userId: string) => ({
    ownerId: userId,
    type: WorkspaceType.PERSONAL,
    isActive: true,
});

/**
 * The account app-store reviewers sign in with.
 *
 * Runs on every boot and is idempotent: a healthy account is left alone
 * without taking a lock or writing a row. Otherwise it creates the account
 * — exactly as a verified sign-up would, personal workspace and all — or
 * repairs whatever drifted: a changed password, lost verification, a
 * deactivation, a missing workspace.
 *
 * Safe with any number of replicas booting at once: the write path runs
 * under a transaction-scoped advisory lock and re-checks inside it, so the
 * first replica does the work and the rest find it done. The unique email
 * is the backstop.
 *
 * Deliberately an ordinary account: never a superadmin, owns nothing but
 * its own personal workspace. If a reviewer deletes it (account deletion
 * is part of what Play reviews), the anonymised tombstone keeps no email,
 * and the next boot creates a fresh one.
 */
@injectable()
export class ReviewAccountService {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    async ensure(credentials: Credentials = {
        email: config.REVIEW_ACCOUNT_EMAIL,
        password: config.REVIEW_ACCOUNT_PASSWORD,
    }): Promise<ReviewAccountResult> {
        const email = credentials.email.trim().toLowerCase();
        const { password } = credentials;
        if (!email || !password) return { status: 'disabled' };

        // A shared, published password must never open the platform console.
        if (superAdminEmails().includes(email)) {
            logger.error('Review account refused: its email is a configured superadmin', { email });
            return { status: 'refused', email };
        }

        // Fast path: nothing to do, no lock, no writes.
        if ((await this.problems(this.prisma, email, password)).length === 0) {
            return { status: 'unchanged', email };
        }

        // Hash before taking the lock — bcrypt is the slow part.
        const passwordHash = await bcrypt.hash(password, config.BCRYPT_SALT_ROUNDS);
        try {
            return await this.writeUnderLock(email, password, passwordHash);
        } catch (error) {
            // Someone registered the address between our read and our insert
            // without going through the lock (the public sign-up form). One
            // more pass finds their row and repairs it.
            if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
                return this.writeUnderLock(email, password, passwordHash);
            }
            throw error;
        }
    }

    /** What's wrong with the account as it stands; empty when it's ready to sign in with. */
    private async problems(db: Prisma.TransactionClient | PrismaClient, email: string, password: string): Promise<string[]> {
        const user = await this.find(db, email);
        if (!user) return ['missing'];
        const out: string[] = [];
        if (!user.isActive) out.push('inactive');
        if (!user.emailVerified) out.push('unverified');
        if (user.isSuperAdmin) out.push('superadmin');
        if (!user.passwordHash || !(await bcrypt.compare(password, user.passwordHash))) out.push('password');
        const workspace = await db.workspace.findFirst({ where: ownedPersonal(user.id), select: { id: true } });
        if (!workspace) out.push('workspace');
        return out;
    }

    private find(db: Prisma.TransactionClient | PrismaClient, email: string) {
        return db.user.findFirst({
            where: { email: { equals: email, mode: 'insensitive' }, deletedAt: null },
        });
    }

    private async writeUnderLock(email: string, password: string, passwordHash: string): Promise<ReviewAccountResult> {
        const result = await this.prisma.$transaction(async (tx) => {
            await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(${LOCK_KEY}, 0))`;

            // Whoever held the lock before us may already have done it all.
            const problems = await this.problems(tx, email, password);
            if (problems.length === 0) return { status: 'unchanged' as const, email };

            const existing = await this.find(tx, email);
            const user = existing
                ? await tx.user.update({
                    where: { id: existing.id },
                    data: {
                        isActive: true,
                        emailVerified: true,
                        isSuperAdmin: false,
                        ...(problems.includes('password') && { passwordHash }),
                    },
                })
                : await tx.user.create({
                    data: {
                        email,
                        passwordHash,
                        firstName: FIRST_NAME,
                        lastName: LAST_NAME,
                        provider: AuthProvider.LOCAL,
                        emailVerified: true,
                    },
                });

            // A reset password ends every session the old one opened, as a
            // normal password reset does.
            if (existing && problems.includes('password')) {
                await tx.refreshToken.updateMany({ where: { userId: user.id, isRevoked: false }, data: { isRevoked: true } });
            }

            if (problems.includes('missing') || problems.includes('workspace')) {
                const currency = currencyForCountry(COUNTRY);
                const workspace = await tx.workspace.create({
                    data: {
                        name: `${FIRST_NAME} ${LAST_NAME}'s Personal`,
                        type: WorkspaceType.PERSONAL,
                        ownerId: user.id,
                        defaultCurrency: currency,
                    },
                });
                await provisionWorkspaceAccounting(tx, workspace.id, currency);
                await seedDefaultWalletAccounts(tx, workspace.id, currency, user.id);
                await seedDefaultCashbook(tx, workspace.id, currency, user.id);
            }

            await tx.auditLog.create({
                data: {
                    userId: user.id,
                    action: existing ? AuditAction.REVIEW_ACCOUNT_REPAIRED : AuditAction.REVIEW_ACCOUNT_CREATED,
                    resource: 'user',
                    resourceId: user.id,
                    details: { source: 'review-account-bootstrap', problems } as Prisma.InputJsonValue,
                },
            });

            return existing
                ? { status: 'repaired' as const, email, repaired: problems }
                : { status: 'created' as const, email };
        }, { timeout: 30_000 });

        if (result.status !== 'unchanged') logger.info('Review account ensured', result);
        return result;
    }
}

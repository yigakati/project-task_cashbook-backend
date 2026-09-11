import { injectable, inject } from 'tsyringe';
import { PrismaClient, Prisma, AuthProvider } from '@prisma/client';

@injectable()
export class AuthRepository {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }
    async findUserByEmail(email: string) {
        return this.prisma.user.findUnique({
            where: { email },
        });
    }

    async findUserById(id: string) {
        return this.prisma.user.findUnique({
            where: { id },
        });
    }

    async createUser(data: Prisma.UserCreateInput) {
        return this.prisma.user.create({
            data,
        });
    }

    async updateUserLastLogin(userId: string) {
        return this.prisma.user.update({
            where: { id: userId },
            data: { lastLoginAt: new Date() },
        });
    }

    async updateUserPassword(userId: string, passwordHash: string) {
        return this.prisma.user.update({
            where: { id: userId },
            data: { passwordHash },
        });
    }

    // ─── Refresh Tokens ────────────────────────────────
    async createRefreshToken(data: {
        userId: string;
        tokenHash: string;
        deviceInfo?: string;
        ipAddress?: string;
        expiresAt: Date;
    }) {
        return this.prisma.refreshToken.create({
            data,
        });
    }

    async findRefreshTokenByHash(tokenHash: string) {
        return this.prisma.refreshToken.findFirst({
            where: {
                tokenHash,
                isRevoked: false,
                expiresAt: { gt: new Date() },
            },
            include: { user: true },
        });
    }

    async revokeRefreshToken(id: string) {
        return this.prisma.refreshToken.update({
            where: { id },
            data: { isRevoked: true },
        });
    }

    /**
     * Spend a refresh token, atomically.
     *
     * Returns false when it was already spent. Two refreshes presenting the
     * same cookie at once — two tabs, or a timer and a 401 in the same tab —
     * both read it as valid a moment earlier; the status filter in the where
     * clause is what lets only one of them win.
     */
    async claimRefreshToken(id: string): Promise<boolean> {
        const { count } = await this.prisma.refreshToken.updateMany({
            where: { id, isRevoked: false },
            data: { isRevoked: true },
        });
        return count === 1;
    }

    async revokeAllUserTokens(userId: string) {
        return this.prisma.refreshToken.updateMany({
            where: { userId, isRevoked: false },
            data: { isRevoked: true },
        });
    }

    async deleteExpiredTokens() {
        return this.prisma.refreshToken.deleteMany({
            where: {
                OR: [
                    { expiresAt: { lt: new Date() } },
                    { isRevoked: true },
                ],
            },
        });
    }

    // ─── Login History ─────────────────────────────────
    async createLoginHistory(data: {
        userId: string;
        ipAddress?: string;
        userAgent?: string;
        status: string;
        reason?: string;
    }) {
        return this.prisma.loginHistory.create({
            data,
        });
    }

    async getLoginHistory(userId: string, limit = 20) {
        return this.prisma.loginHistory.findMany({
            where: { userId },
            orderBy: { createdAt: 'desc' },
            take: limit,
        });
    }

    async getRecentFailedAttempts(userId: string, windowMinutes = 30) {
        const since = new Date(Date.now() - windowMinutes * 60 * 1000);
        return this.prisma.loginHistory.count({
            where: {
                userId,
                status: 'FAILED',
                createdAt: { gte: since },
            },
        });
    }

}

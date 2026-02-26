import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { OAuth2Client } from 'google-auth-library';
import { AuthProvider } from '@prisma/client';
import { config } from '../../config';
import { AuthRepository } from './auth.repository';
import {
    AuthenticationError,
    ConflictError,
    AppError,
} from '../../core/errors/AppError';
import { JwtPayload, AuditAction, WorkspaceType } from '../../core/types';
import {
    RegisterDto, LoginDto, ChangePasswordDto,
    VerifyEmailDto, ForgotPasswordDto, ResetPasswordDto,
    GoogleLoginDto,
} from './auth.dto';
import { logger } from '../../utils/logger';
import { getRedisClient } from '../../config/redis';
import { sendEmail } from '../../config/email';
import { verificationEmailTemplate, passwordResetEmailTemplate } from '../../utils/emailTemplates';
import { InvitesService } from '../invites/invites.service';

const SUSPICIOUS_FAILURE_THRESHOLD = 5;
const OTP_TTL_SECONDS = 15 * 60; // 15 minutes

@injectable()
export class AuthService {
    constructor(
        private authRepository: AuthRepository,
        private invitesService: InvitesService,
        @inject('PrismaClient') private prisma: PrismaClient,
    ) { }

    // ─── Register ──────────────────────────────────────
    async register(dto: RegisterDto, ipAddress?: string, userAgent?: string) {
        const existingUser = await this.authRepository.findUserByEmail(dto.email);
        if (existingUser) {
            throw new ConflictError('A user with this email already exists');
        }

        const passwordHash = await bcrypt.hash(dto.password, config.BCRYPT_SALT_ROUNDS);

        // Create user + personal workspace in a transaction
        const result = await this.prisma.$transaction(async (tx) => {
            const user = await tx.user.create({
                data: {
                    email: dto.email,
                    passwordHash,
                    firstName: dto.firstName,
                    lastName: dto.lastName,
                    isSuperAdmin: dto.email === config.SUPER_ADMIN_EMAIL,
                },
            });

            // Auto-create personal workspace
            await tx.workspace.create({
                data: {
                    name: `${dto.firstName}'s Personal`,
                    type: WorkspaceType.PERSONAL,
                    ownerId: user.id,
                },
            });

            // Audit log
            await tx.auditLog.create({
                data: {
                    userId: user.id,
                    action: AuditAction.USER_REGISTERED,
                    resource: 'user',
                    resourceId: user.id,
                    ipAddress,
                    userAgent,
                },
            });

            return user;
        });

        // Resolve any pending workspace invites for this email
        this.invitesService.resolveInvites(result.id, dto.email)
            .catch((err) => logger.error('Failed to resolve pending invites', { email: dto.email, err }));

        // Generate and store verification OTP
        const otp = this.generateOTP();
        const redis = getRedisClient();
        await redis.set(`verification:${result.id}`, otp, 'EX', OTP_TTL_SECONDS);

        // Send verification email (fire-and-forget, logged on failure)
        sendEmail({
            to: dto.email,
            subject: `Verify your ${config.APP_NAME} account`,
            html: verificationEmailTemplate(dto.firstName, otp),
        }).catch((err) => logger.error('Failed to send verification email', { email: dto.email, err }));

        const { passwordHash: _, ...userWithoutPassword } = result;
        return userWithoutPassword;
    }

    // ─── Login ─────────────────────────────────────────
    async login(dto: LoginDto, ipAddress?: string, userAgent?: string) {
        const user = await this.authRepository.findUserByEmail(dto.email);

        if (!user) {
            throw new AuthenticationError('Invalid email or password');
        }

        if (!user.isActive) {
            throw new AuthenticationError('Account is deactivated');
        }

        if (!user.emailVerified) {
            throw new AuthenticationError('Please verify your email before logging in');
        }

        // Check for suspicious activity
        const recentFailures = await this.authRepository.getRecentFailedAttempts(user.id);
        if (recentFailures >= SUSPICIOUS_FAILURE_THRESHOLD) {
            await this.authRepository.createLoginHistory({
                userId: user.id,
                ipAddress,
                userAgent,
                status: 'SUSPICIOUS',
                reason: `${recentFailures} failed attempts in last 30 minutes`,
            });

            await this.prisma.auditLog.create({
                data: {
                    userId: user.id,
                    action: AuditAction.SUSPICIOUS_LOGIN,
                    resource: 'auth',
                    details: { recentFailures, ipAddress } as any,
                    ipAddress,
                    userAgent,
                },
            });

            throw new AuthenticationError(
                'Account temporarily locked due to too many failed attempts. Please try again later.'
            );
        }

        const isPasswordValid = user.passwordHash
            ? await bcrypt.compare(dto.password, user.passwordHash)
            : false;
        if (!isPasswordValid) {
            await this.authRepository.createLoginHistory({
                userId: user.id,
                ipAddress,
                userAgent,
                status: 'FAILED',
                reason: 'Invalid password',
            });
            throw new AuthenticationError('Invalid email or password');
        }

        // Generate tokens
        const accessToken = this.generateAccessToken(user);
        const { token: refreshToken, hash: refreshTokenHash } = this.generateRefreshToken();

        // Parse refresh expiry for DB
        const refreshExpiresAt = this.parseExpiryToDate(config.JWT_REFRESH_EXPIRY);

        // Store refresh token
        await this.authRepository.createRefreshToken({
            userId: user.id,
            tokenHash: refreshTokenHash,
            deviceInfo: userAgent,
            ipAddress,
            expiresAt: refreshExpiresAt,
        });

        // Update last login + create history
        await this.authRepository.updateUserLastLogin(user.id);
        await this.authRepository.createLoginHistory({
            userId: user.id,
            ipAddress,
            userAgent,
            status: 'SUCCESS',
        });

        // Audit log
        await this.prisma.auditLog.create({
            data: {
                userId: user.id,
                action: AuditAction.USER_LOGGED_IN,
                resource: 'auth',
                ipAddress,
                userAgent,
            },
        });

        const { passwordHash: _, ...userWithoutPassword } = user;
        return {
            user: userWithoutPassword,
            accessToken,
            refreshToken,
        };
    }

    // ─── Refresh Token ────────────────────────────────
    async refreshTokens(oldRefreshToken: string, ipAddress?: string, userAgent?: string) {
        const tokenHash = this.hashToken(oldRefreshToken);
        const storedToken = await this.authRepository.findRefreshTokenByHash(tokenHash);

        if (!storedToken) {
            throw new AuthenticationError('Invalid or expired refresh token');
        }

        if (!storedToken.user.isActive) {
            throw new AuthenticationError('Account is deactivated');
        }

        // Revoke old token (rotation)
        await this.authRepository.revokeRefreshToken(storedToken.id);

        // Generate new tokens
        const accessToken = this.generateAccessToken(storedToken.user);
        const { token: newRefreshToken, hash: newRefreshTokenHash } = this.generateRefreshToken();

        const refreshExpiresAt = this.parseExpiryToDate(config.JWT_REFRESH_EXPIRY);

        await this.authRepository.createRefreshToken({
            userId: storedToken.userId,
            tokenHash: newRefreshTokenHash,
            deviceInfo: userAgent,
            ipAddress,
            expiresAt: refreshExpiresAt,
        });

        await this.prisma.auditLog.create({
            data: {
                userId: storedToken.userId,
                action: AuditAction.TOKEN_REFRESHED,
                resource: 'auth',
                ipAddress,
                userAgent,
            },
        });

        return {
            accessToken,
            refreshToken: newRefreshToken,
        };
    }

    // ─── Logout ────────────────────────────────────────
    async logout(refreshToken: string, userId: string, jti?: string, ipAddress?: string, userAgent?: string) {
        if (refreshToken) {
            const tokenHash = this.hashToken(refreshToken);
            const storedToken = await this.authRepository.findRefreshTokenByHash(tokenHash);
            if (storedToken) {
                await this.authRepository.revokeRefreshToken(storedToken.id);
            }
        }

        // Denylist the current access token by jti
        if (jti) {
            await this.denylistToken(jti);
        }

        await this.prisma.auditLog.create({
            data: {
                userId,
                action: AuditAction.USER_LOGGED_OUT,
                resource: 'auth',
                ipAddress,
                userAgent,
            },
        });
    }

    // ─── Logout All ────────────────────────────────────
    async logoutAll(userId: string, ipAddress?: string, userAgent?: string) {
        await this.authRepository.revokeAllUserTokens(userId);

        await this.prisma.auditLog.create({
            data: {
                userId,
                action: AuditAction.ALL_SESSIONS_REVOKED,
                resource: 'auth',
                ipAddress,
                userAgent,
            },
        });
    }

    // ─── Change Password ──────────────────────────────
    async changePassword(userId: string, dto: ChangePasswordDto) {
        const user = await this.authRepository.findUserById(userId);
        if (!user) {
            throw new AuthenticationError('User not found');
        }

        if (!user.passwordHash) {
            throw new AppError('Password change is not available for Google-authenticated accounts', 400, 'NO_PASSWORD');
        }

        const isValid = await bcrypt.compare(dto.currentPassword, user.passwordHash);
        if (!isValid) {
            throw new AuthenticationError('Current password is incorrect');
        }

        const newHash = await bcrypt.hash(dto.newPassword, config.BCRYPT_SALT_ROUNDS);
        await this.authRepository.updateUserPassword(userId, newHash);

        // Revoke all refresh tokens for security
        await this.authRepository.revokeAllUserTokens(userId);
    }

    // ─── Login History ─────────────────────────────────
    async getLoginHistory(userId: string) {
        return this.authRepository.getLoginHistory(userId);
    }

    // ─── Email Verification ───────────────────────────
    async verifyEmail(dto: VerifyEmailDto) {
        const user = await this.authRepository.findUserByEmail(dto.email);
        if (!user) {
            throw new AuthenticationError('Invalid email or verification code');
        }

        if (user.emailVerified) {
            return; // Already verified, idempotent
        }

        const redis = getRedisClient();
        const storedOtp = await redis.get(`verification:${user.id}`);

        if (!storedOtp || !this.safeCompare(storedOtp, dto.otp)) {
            throw new AuthenticationError('Invalid or expired verification code');
        }

        await this.prisma.user.update({
            where: { id: user.id },
            data: { emailVerified: true },
        });

        await redis.del(`verification:${user.id}`);

        await this.prisma.auditLog.create({
            data: {
                userId: user.id,
                action: AuditAction.EMAIL_VERIFIED,
                resource: 'user',
                resourceId: user.id,
            },
        });
    }

    async resendVerification(email: string) {
        const user = await this.authRepository.findUserByEmail(email);

        // Anti-enumeration: always return success
        if (!user || user.emailVerified) return;

        const otp = this.generateOTP();
        const redis = getRedisClient();
        await redis.set(`verification:${user.id}`, otp, 'EX', OTP_TTL_SECONDS);

        sendEmail({
            to: email,
            subject: `Verify your ${config.APP_NAME} account`,
            html: verificationEmailTemplate(user.firstName, otp),
        }).catch((err) => logger.error('Failed to send verification email', { email, err }));
    }

    // ─── Forgot / Reset Password ──────────────────────
    async forgotPassword(email: string) {
        const user = await this.authRepository.findUserByEmail(email);

        // Anti-enumeration: always return success
        if (!user || !user.isActive) return;

        const otp = this.generateOTP();
        const redis = getRedisClient();
        await redis.set(`reset:${user.id}`, otp, 'EX', OTP_TTL_SECONDS);

        await this.prisma.auditLog.create({
            data: {
                userId: user.id,
                action: AuditAction.PASSWORD_RESET_REQUESTED,
                resource: 'auth',
            },
        });

        sendEmail({
            to: email,
            subject: `Reset your ${config.APP_NAME} password`,
            html: passwordResetEmailTemplate(user.firstName, otp),
        }).catch((err) => logger.error('Failed to send reset email', { email, err }));
    }

    async resetPassword(dto: ResetPasswordDto) {
        const user = await this.authRepository.findUserByEmail(dto.email);
        if (!user) {
            throw new AuthenticationError('Invalid email or reset code');
        }

        const redis = getRedisClient();
        const storedOtp = await redis.get(`reset:${user.id}`);

        if (!storedOtp || !this.safeCompare(storedOtp, dto.otp)) {
            throw new AuthenticationError('Invalid or expired reset code');
        }

        const newHash = await bcrypt.hash(dto.newPassword, config.BCRYPT_SALT_ROUNDS);
        await this.authRepository.updateUserPassword(user.id, newHash);

        // Revoke all sessions for security
        await this.authRepository.revokeAllUserTokens(user.id);

        await redis.del(`reset:${user.id}`);

        await this.prisma.auditLog.create({
            data: {
                userId: user.id,
                action: AuditAction.PASSWORD_RESET_COMPLETED,
                resource: 'auth',
            },
        });
    }

    // ─── Token Helpers ─────────────────────────────────
    private generateAccessToken(user: { id: string; email: string; isSuperAdmin: boolean }): string {
        const jti = crypto.randomUUID();
        const payload: JwtPayload = {
            userId: user.id,
            email: user.email,
            isSuperAdmin: user.isSuperAdmin,
            jti,
        };

        return jwt.sign(payload, config.JWT_ACCESS_SECRET, {
            expiresIn: config.JWT_ACCESS_EXPIRY as any,
        });
    }

    private generateRefreshToken(): { token: string; hash: string } {
        const token = crypto.randomBytes(40).toString('hex');
        const hash = this.hashToken(token);
        return { token, hash };
    }

    private hashToken(token: string): string {
        return crypto.createHash('sha256').update(token).digest('hex');
    }

    /**
     * Add a JWT jti to the Redis denylist so the token is rejected
     * even before it expires naturally.
     */
    private async denylistToken(jti: string): Promise<void> {
        try {
            const redis = getRedisClient();
            // TTL = access-token lifetime so entries auto-expire
            const ttlSeconds = this.parseExpiryToSeconds(config.JWT_ACCESS_EXPIRY);
            await redis.set(`deny:${jti}`, '1', 'EX', ttlSeconds);
        } catch (error) {
            logger.error('Failed to denylist token', { jti, error });
        }
    }

    /** Check if a jti has been denylisted */
    static async isTokenDenylisted(jti: string): Promise<boolean> {
        try {
            const redis = getRedisClient();
            const result = await redis.get(`deny:${jti}`);
            return result !== null;
        } catch (error) {
            logger.error('Failed to check denylist', { jti, error });
            return false; // fail-open to avoid locking out users on Redis failure
        }
    }

    private parseExpiryToDate(expiry: string): Date {
        const seconds = this.parseExpiryToSeconds(expiry);
        return new Date(Date.now() + seconds * 1000);
    }

    private parseExpiryToSeconds(expiry: string): number {
        const match = expiry.match(/^(\d+)([smhd])$/);
        if (!match) {
            return 7 * 24 * 60 * 60; // default 7 days in seconds
        }

        const value = parseInt(match[1]);
        const unit = match[2];

        const multipliers: Record<string, number> = {
            s: 1,
            m: 60,
            h: 60 * 60,
            d: 24 * 60 * 60,
        };

        return value * multipliers[unit];
    }

    // ─── OTP Helpers ──────────────────────────────────
    private generateOTP(): string {
        return crypto.randomInt(100000, 999999).toString();
    }

    private safeCompare(a: string, b: string): boolean {
        if (a.length !== b.length) return false;
        return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    }

    // ─── Google OAuth ────────────────────────────────────────
    async googleLogin(dto: GoogleLoginDto, ipAddress?: string, userAgent?: string) {
        const client = new OAuth2Client(config.GOOGLE_CLIENT_ID);

        let payload;
        try {
            const ticket = await client.verifyIdToken({
                idToken: dto.idToken,
                audience: config.GOOGLE_CLIENT_ID,
            });
            payload = ticket.getPayload();
        } catch (error) {
            await this.prisma.auditLog.create({
                data: {
                    action: AuditAction.GOOGLE_LOGIN_FAILED,
                    resource: 'auth',
                    details: { reason: 'Invalid Google ID token' } as any,
                    ipAddress,
                    userAgent,
                },
            });
            throw new AuthenticationError('Invalid Google ID token');
        }

        if (!payload || !payload.sub || !payload.email) {
            throw new AuthenticationError('Invalid Google token payload');
        }

        if (!payload.email_verified) {
            await this.prisma.auditLog.create({
                data: {
                    action: AuditAction.GOOGLE_LOGIN_FAILED,
                    resource: 'auth',
                    details: { reason: 'Google email not verified', email: payload.email } as any,
                    ipAddress,
                    userAgent,
                },
            });
            throw new AuthenticationError('Your Google email is not verified');
        }

        const googleSub = payload.sub;
        const email = payload.email;
        const firstName = payload.given_name || payload.name?.split(' ')[0] || 'User';
        const lastName = payload.family_name || payload.name?.split(' ').slice(1).join(' ') || '';

        // Resolve user inside a transaction
        const user = await this.prisma.$transaction(async (tx) => {
            // Case A: Existing Google user
            const existingGoogleUser = await tx.user.findUnique({
                where: {
                    provider_providerId: {
                        provider: AuthProvider.GOOGLE,
                        providerId: googleSub,
                    },
                },
            });

            if (existingGoogleUser) {
                if (!existingGoogleUser.isActive) {
                    throw new AuthenticationError('Account is deactivated');
                }
                return existingGoogleUser;
            }

            // Case B: Existing LOCAL user with same email
            const existingLocalUser = await tx.user.findUnique({
                where: { email },
            });

            if (existingLocalUser) {
                if (!existingLocalUser.isActive) {
                    throw new AuthenticationError('Account is deactivated');
                }

                if (!existingLocalUser.emailVerified) {
                    throw new AppError(
                        'A local account with this email exists but is not verified. Please verify your email first.',
                        403,
                        'EMAIL_NOT_VERIFIED'
                    );
                }

                // Link Google to existing verified LOCAL account
                const linked = await tx.user.update({
                    where: { id: existingLocalUser.id },
                    data: {
                        provider: AuthProvider.GOOGLE,
                        providerId: googleSub,
                    },
                });

                await tx.auditLog.create({
                    data: {
                        userId: linked.id,
                        action: AuditAction.GOOGLE_ACCOUNT_LINKED,
                        resource: 'user',
                        resourceId: linked.id,
                        details: { googleSub } as any,
                        ipAddress,
                        userAgent,
                    },
                });

                return linked;
            }

            // Case C: Brand new Google user
            const newUser = await tx.user.create({
                data: {
                    email,
                    firstName,
                    lastName,
                    provider: AuthProvider.GOOGLE,
                    providerId: googleSub,
                    emailVerified: true,
                    isSuperAdmin: email === config.SUPER_ADMIN_EMAIL,
                },
            });

            // Auto-create personal workspace
            await tx.workspace.create({
                data: {
                    name: `${firstName}'s Personal`,
                    type: WorkspaceType.PERSONAL,
                    ownerId: newUser.id,
                },
            });

            await tx.auditLog.create({
                data: {
                    userId: newUser.id,
                    action: AuditAction.GOOGLE_ACCOUNT_CREATED,
                    resource: 'user',
                    resourceId: newUser.id,
                    details: { googleSub, email } as any,
                    ipAddress,
                    userAgent,
                },
            });

            return newUser;
        });

        // Resolve pending invites (fire-and-forget)
        this.invitesService.resolveInvites(user.id, user.email)
            .catch((err) => logger.error('Failed to resolve pending invites', { email: user.email, err }));

        // Generate tokens (using existing token system)
        const accessToken = this.generateAccessToken(user);
        const { token: refreshToken, hash: refreshTokenHash } = this.generateRefreshToken();
        const refreshExpiresAt = this.parseExpiryToDate(config.JWT_REFRESH_EXPIRY);

        await this.authRepository.createRefreshToken({
            userId: user.id,
            tokenHash: refreshTokenHash,
            deviceInfo: userAgent,
            ipAddress,
            expiresAt: refreshExpiresAt,
        });

        await this.authRepository.updateUserLastLogin(user.id);
        await this.authRepository.createLoginHistory({
            userId: user.id,
            ipAddress,
            userAgent,
            status: 'SUCCESS',
        });

        await this.prisma.auditLog.create({
            data: {
                userId: user.id,
                action: AuditAction.GOOGLE_LOGIN_SUCCESS,
                resource: 'auth',
                ipAddress,
                userAgent,
            },
        });

        const { passwordHash: _, ...userWithoutPassword } = user;
        return {
            user: userWithoutPassword,
            accessToken,
            refreshToken,
        };
    }
}

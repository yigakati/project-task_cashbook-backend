import { injectable, inject } from 'tsyringe';
import { PrismaClient, Prisma } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { OAuth2Client } from 'google-auth-library';
import { AuthProvider } from '@prisma/client';
import { config, superAdminEmails } from '../../config';
import { AuthRepository } from './auth.repository';
import {
    AuthenticationError,
    ConflictError,
    AppError,
    EmailNotVerifiedError,
} from '../../core/errors/AppError';
import { JwtPayload, AuditAction, WorkspaceType } from '../../core/types';
import {
    RegisterDto, LoginDto, ChangePasswordDto, SetupPasswordDto,
    VerifyEmailDto, ForgotPasswordDto, ResetPasswordDto,
    GoogleLoginDto,
    OcLoginDto,
} from './auth.dto';
import { logger } from '../../utils/logger';
import { getRedisClient } from '../../config/redis';
import { sendEmail } from '../../config/email';
import { verificationEmailTemplate, passwordResetEmailTemplate, welcomeEmailTemplate } from '../../utils/emailTemplates';
import {
    provisionWorkspaceAccounting,
    seedDefaultWalletAccounts,
    seedDefaultCashbook,
} from '../../core/ledger/coa.seed';
import { currencyForCountry } from '../../core/finance';

const SUSPICIOUS_FAILURE_THRESHOLD = 5;
const OTP_TTL_SECONDS = 15 * 60; // 15 minutes
/** A hung OC server must not hang our request thread indefinitely. */
const OC_REQUEST_TIMEOUT_MS = 10_000;

@injectable()
export class AuthService {
    constructor(
        private authRepository: AuthRepository,
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
                    isSuperAdmin: superAdminEmails().includes(dto.email.toLowerCase()),
                },
            });

            // Auto-create personal workspace, born ready to book: chart of
            // accounts, default wallet types, the country's obvious wallets,
            // and its first cashbook — the same head start a business
            // workspace gets. The country decides the currency (and with it,
            // which wallets arrive: M-Pesa in Kenya, MTN MoMo in Uganda,
            // PayPal for USD, ...).
            const baseCurrency = currencyForCountry(dto.country);
            const personalWorkspace = await tx.workspace.create({
                data: {
                    name: `${dto.firstName}'s Personal`,
                    type: WorkspaceType.PERSONAL,
                    ownerId: user.id,
                    defaultCurrency: baseCurrency,
                },
            });
            await provisionWorkspaceAccounting(tx, personalWorkspace.id, baseCurrency);
            await seedDefaultWalletAccounts(tx, personalWorkspace.id, baseCurrency, user.id);
            await seedDefaultCashbook(tx, personalWorkspace.id, baseCurrency, user.id);

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

    /**
     * Reconcile one user's superadmin flag against the configured allow-list.
     *
     * Cheaper than a full reconcile on every login, and enough to make the env
     * var authoritative from the user's point of view. The full sweep runs on
     * boot and on demand from the platform page.
     */
    private async syncSuperAdminFlag(
        userId: string,
        email: string,
        current: boolean,
    ): Promise<boolean> {
        const shouldBe = superAdminEmails().includes(email.toLowerCase());
        if (shouldBe === current) return current;

        await this.prisma.user.update({
            where: { id: userId },
            data: { isSuperAdmin: shouldBe },
        });
        logger.info('Superadmin status synced from configuration', { email, isSuperAdmin: shouldBe });
        return shouldBe;
    }

    async login(dto: LoginDto, ipAddress?: string, userAgent?: string) {
        const user = await this.authRepository.findUserByEmail(dto.email);

        if (!user) {
            throw new AuthenticationError('Invalid email or password');
        }

        if (!user.isActive) {
            throw new AuthenticationError('Account is deactivated');
        }

        if (!user.emailVerified) {
            // Trigger a fresh code so the user can verify immediately after redirect.
            // Fire-and-forget: we never tell the client whether the resend succeeded
            // to avoid leaking account-existence information via timing.
            void this.resendVerification(user.email);
            throw new EmailNotVerifiedError(user.email);
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

        // Bring superadmin status in line with SUPER_ADMIN_EMAILS before minting
        // the token, so adding or removing an address takes effect on next login
        // rather than only for accounts created after the change.
        const isSuperAdmin = await this.syncSuperAdminFlag(user.id, user.email, user.isSuperAdmin);

        // Generate tokens
        const accessToken = this.generateAccessToken({ ...user, isSuperAdmin });
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

    // ─── OC OAuth ────────────────────────────────────────────
    /**
     * Authorization-code exchange, unlike `googleLogin`.
     *
     * Google hands us a signed ID token the frontend already obtained; verifying
     * it is a local signature check against Google's public keys, via a hardened
     * SDK, and needs no outbound call of our own at request time. OC gives us
     * only a one-time code, so THIS server has to make two outbound HTTP calls
     * to a third party to turn it into a user — a different, larger trust
     * surface than Google's flow, and the reason this method is more defensive
     * than its sibling: a request timeout on both calls (a hung upstream must
     * not hang ours), and an audit row on every distinct failure mode, not just
     * the first one.
     *
     * `redirectUri` is not accepted from the caller at all. OC's OAuth app
     * registration takes redirect URIs as a fixed list at app-creation time —
     * `config.OC_REDIRECT_URI` is the one value that will ever be valid for
     * this app — so there is nothing to validate: the server always sends its
     * own known-correct value rather than trusting client input.
     */
    /**
     * Shared by `googleLogin` and `ocLogin` — resolving "which user does this
     * OAuth identity belong to" is identical for both providers, and used to
     * be duplicated per-provider logic that mutated `User.provider`/
     * `providerId` directly. That single-slot design meant linking a second
     * provider silently overwrote the first: a user who signed up with
     * Google, then signed in with OC using the same email, would have their
     * `provider` column flipped to `OC` — and a subsequent Google sign-in
     * would no longer find them by `(GOOGLE, googleSub)`, re-triggering the
     * "existing account" match by email and flipping it right back. Only
     * whichever provider was used most recently actually worked.
     *
     * `LinkedIdentity` fixes this by giving every provider its own row, so a
     * user can have both linked simultaneously. `User.provider`/`providerId`
     * are left untouched here — they stay whatever they were at original
     * signup, an immutable record for display/audit, not a login path.
     */
    private async resolveOAuthUser(
        tx: Prisma.TransactionClient,
        params: {
            provider: AuthProvider;
            providerId: string;
            email: string;
            firstName: string;
            lastName: string;
            linkedAction: AuditAction;
            createdAction: AuditAction;
            ipAddress?: string;
            userAgent?: string;
        },
    ) {
        const { provider, providerId, email, firstName, lastName, linkedAction, createdAction, ipAddress, userAgent } = params;

        // Case A: this exact provider identity is already linked to someone.
        const existingIdentity = await tx.linkedIdentity.findUnique({
            where: { provider_providerId: { provider, providerId } },
            include: { user: true },
        });

        if (existingIdentity) {
            if (!existingIdentity.user.isActive) {
                throw new AuthenticationError('Account is deactivated');
            }
            return { user: existingIdentity.user, isNewUser: false };
        }

        // Case B: no link yet, but a user already exists with this email —
        // via local signup or a different provider. Link this identity to
        // them rather than creating a second account or overwriting theirs.
        const existingUser = await tx.user.findUnique({ where: { email } });

        if (existingUser) {
            if (!existingUser.isActive) {
                throw new AuthenticationError('Account is deactivated');
            }

            if (!existingUser.emailVerified) {
                throw new AppError(
                    'An account with this email exists but is not verified. Please verify your email first.',
                    403,
                    'EMAIL_NOT_VERIFIED',
                );
            }

            await tx.linkedIdentity.create({
                data: { userId: existingUser.id, provider, providerId, email },
            });

            await tx.auditLog.create({
                data: {
                    userId: existingUser.id,
                    action: linkedAction,
                    resource: 'user',
                    resourceId: existingUser.id,
                    details: { providerId } as any,
                    ipAddress,
                    userAgent,
                },
            });

            return { user: existingUser, isNewUser: false };
        }

        // Case C: brand new user.
        const newUser = await tx.user.create({
            data: {
                email,
                firstName,
                lastName,
                provider,
                providerId,
                emailVerified: true,
                isSuperAdmin: superAdminEmails().includes(email.toLowerCase()),
            },
        });

        await tx.linkedIdentity.create({
            data: { userId: newUser.id, provider, providerId, email },
        });

        const personalWorkspace = await tx.workspace.create({
            data: {
                name: `${firstName}'s Personal`,
                type: WorkspaceType.PERSONAL,
                ownerId: newUser.id,
            },
        });
        await provisionWorkspaceAccounting(tx, personalWorkspace.id, personalWorkspace.defaultCurrency);
        await seedDefaultWalletAccounts(tx, personalWorkspace.id, personalWorkspace.defaultCurrency, newUser.id);
        await seedDefaultCashbook(tx, personalWorkspace.id, personalWorkspace.defaultCurrency, newUser.id);

        await tx.auditLog.create({
            data: {
                userId: newUser.id,
                action: createdAction,
                resource: 'user',
                resourceId: newUser.id,
                details: { providerId, email } as any,
                ipAddress,
                userAgent,
            },
        });

        return { user: newUser, isNewUser: true };
    }

    async ocLogin(dto: OcLoginDto, ipAddress?: string, userAgent?: string) {
        if (!config.Client_ID || !config.Client_Secret) {
            throw new AppError(
                'OC sign-in is not configured on this server',
                503,
                'OC_AUTH_NOT_CONFIGURED',
            );
        }

        let tokens: any;
        try {
            const tokenRes = await fetch(`${config.OC_BASE_URL}/api/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    grant_type: 'authorization_code',
                    client_id: config.Client_ID,
                    client_secret: config.Client_Secret,
                    code: dto.code,
                    // Not client input. OC's OAuth app registration takes
                    // redirect URIs as a fixed list at creation time — there is
                    // exactly one value that was ever going to be valid, so the
                    // server supplies it rather than trusting a caller to send
                    // back the same one it was handed. This also means the
                    // token exchange can never be pointed at a URI the app was
                    // not actually registered with, regardless of what any
                    // caller of this endpoint sends.
                    redirect_uri: config.OC_REDIRECT_URI,
                }),
                signal: AbortSignal.timeout(OC_REQUEST_TIMEOUT_MS),
            });

            if (!tokenRes.ok) {
                const body = await tokenRes.text().catch(() => '');
                logger.error('OC token exchange rejected', { status: tokenRes.status, body });
                throw new Error(`OC token endpoint returned ${tokenRes.status}`);
            }
            tokens = await tokenRes.json();
        } catch (error) {
            logger.error('OC token exchange failed', {
                error: error instanceof Error ? error.message : error,
            });
            await this.prisma.auditLog.create({
                data: {
                    action: AuditAction.OC_LOGIN_FAILED,
                    resource: 'auth',
                    details: { reason: 'Invalid OC authorization code' } as any,
                    ipAddress,
                    userAgent,
                },
            });
            throw new AuthenticationError('Invalid OC authorization code');
        }

        if (!tokens.access_token) {
            await this.prisma.auditLog.create({
                data: {
                    action: AuditAction.OC_LOGIN_FAILED,
                    resource: 'auth',
                    details: { reason: 'OC token response carried no access_token' } as any,
                    ipAddress,
                    userAgent,
                },
            });
            throw new AuthenticationError('Invalid OC authorization response');
        }

        let payload: any;
        try {
            const userRes = await fetch(`${config.OC_BASE_URL}/api/oauth/userinfo`, {
                headers: { Authorization: `Bearer ${tokens.access_token}` },
                signal: AbortSignal.timeout(OC_REQUEST_TIMEOUT_MS),
            });
            if (!userRes.ok) {
                const body = await userRes.text().catch(() => '');
                logger.error('OC userinfo request rejected', { status: userRes.status, body });
                throw new Error(`OC userinfo endpoint returned ${userRes.status}`);
            }
            payload = await userRes.json();
        } catch (error) {
            logger.error('OC userinfo fetch failed', {
                error: error instanceof Error ? error.message : error,
            });
            await this.prisma.auditLog.create({
                data: {
                    action: AuditAction.OC_LOGIN_FAILED,
                    resource: 'auth',
                    details: { reason: 'Failed to fetch OC user info' } as any,
                    ipAddress,
                    userAgent,
                },
            });
            throw new AuthenticationError('Failed to fetch OC user info');
        }

        // The docs describe the identity field only as "ID"; `sub` is the
        // OIDC-standard name for it (the requested scope includes `openid`),
        // but `id` is accepted too rather than trusting OC's userinfo response
        // to be byte-for-byte spec-compliant on a field we never got a schema
        // for.
        const ocSub = payload?.sub ?? payload?.id;
        if (!payload || !ocSub || !payload.email) {
            await this.prisma.auditLog.create({
                data: {
                    action: AuditAction.OC_LOGIN_FAILED,
                    resource: 'auth',
                    details: { reason: 'Invalid OC user payload' } as any,
                    ipAddress,
                    userAgent,
                },
            });
            throw new AuthenticationError('Invalid OC user payload');
        }

        const email = payload.email;
        const firstName = payload.given_name || payload.name?.split(' ')[0] || 'User';
        const lastName = payload.family_name || payload.name?.split(' ').slice(1).join(' ') || '';
        const isEmailVerified = payload.email_verified !== false; // Assuming verified unless explicitly false

        if (!isEmailVerified) {
            await this.prisma.auditLog.create({
                data: {
                    action: AuditAction.OC_LOGIN_FAILED,
                    resource: 'auth',
                    details: { reason: 'OC email not verified', email } as any,
                    ipAddress,
                    userAgent,
                },
            });
            throw new AuthenticationError('Your OC email is not verified');
        }

        // Resolve user inside a transaction
        const { user, isNewUser } = await this.prisma.$transaction((tx) =>
            this.resolveOAuthUser(tx, {
                provider: AuthProvider.OC,
                providerId: ocSub,
                email,
                firstName,
                lastName,
                linkedAction: AuditAction.OC_ACCOUNT_LINKED,
                createdAction: AuditAction.OC_ACCOUNT_CREATED,
                ipAddress,
                userAgent,
            }),
        );

        if (isNewUser) {
            sendEmail({
                to: user.email,
                subject: `Welcome to ${config.APP_NAME}!`,
                html: welcomeEmailTemplate(user.firstName),
            }).catch((err) => logger.error('Failed to send onboarding email', { email: user.email, err }));
        }

        // Generate tokens
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

        // Log activity outside transaction
        await this.prisma.auditLog.create({
            data: {
                userId: user.id,
                action: AuditAction.OC_LOGIN_SUCCESS,
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
            throw new AppError(
                'This account has no password yet — set one up first, then you can change it.',
                400,
                'NO_PASSWORD',
            );
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

    /**
     * For accounts that reached this app entirely through Google/OC and have
     * no password at all — distinct from `changePassword` because there is no
     * "current password" to verify. Once a password exists, this account
     * uses `changePassword` instead; this method refuses to overwrite an
     * existing hash so it can never be used to bypass that check.
     */
    async setupPassword(userId: string, dto: SetupPasswordDto) {
        const user = await this.authRepository.findUserById(userId);
        if (!user) {
            throw new AuthenticationError('User not found');
        }

        if (user.passwordHash) {
            throw new AppError(
                'This account already has a password — use change password instead.',
                400,
                'PASSWORD_ALREADY_SET',
            );
        }

        const newHash = await bcrypt.hash(dto.newPassword, config.BCRYPT_SALT_ROUNDS);
        await this.authRepository.updateUserPassword(userId, newHash);

        await this.prisma.auditLog.create({
            data: {
                userId,
                action: AuditAction.PASSWORD_SETUP_COMPLETED,
                resource: 'auth',
            },
        });
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

        // Send onboarding welcome email after successful verification
        sendEmail({
            to: user.email,
            subject: `Welcome to ${config.APP_NAME}!`,
            html: welcomeEmailTemplate(user.firstName),
        }).catch((err) => logger.error('Failed to send onboarding email', { email: user.email, err }));

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
        const { user, isNewUser } = await this.prisma.$transaction((tx) =>
            this.resolveOAuthUser(tx, {
                provider: AuthProvider.GOOGLE,
                providerId: googleSub,
                email,
                firstName,
                lastName,
                linkedAction: AuditAction.GOOGLE_ACCOUNT_LINKED,
                createdAction: AuditAction.GOOGLE_ACCOUNT_CREATED,
                ipAddress,
                userAgent,
            }),
        );

        if (isNewUser) {
            sendEmail({
                to: user.email,
                subject: `Welcome to ${config.APP_NAME}!`,
                html: welcomeEmailTemplate(user.firstName),
            }).catch((err) => logger.error('Failed to send onboarding email', { email: user.email, err }));
        }

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
    // ─── OAuth Connection ──────────────────────────────────────
    async connectGoogle(userId: string, dto: GoogleLoginDto, ipAddress?: string, userAgent?: string) {
        const googleClient = new OAuth2Client();
        let payload;
        try {
            const ticket = await googleClient.verifyIdToken({
                idToken: dto.idToken,
                audience: config.GOOGLE_CLIENT_ID,
            });
            payload = ticket.getPayload();
        } catch (error) {
            throw new AuthenticationError('Invalid Google token');
        }

        const googleSub = payload?.sub;
        if (!payload || !googleSub || !payload.email) {
            throw new AuthenticationError('Invalid Google user payload');
        }

        const existingLink = await this.prisma.linkedIdentity.findUnique({
            where: { provider_providerId: { provider: AuthProvider.GOOGLE, providerId: googleSub } },
        });

        if (existingLink && existingLink.userId !== userId) {
            throw new ConflictError('This Google account is already connected to another user');
        }

        if (!existingLink) {
            await this.prisma.linkedIdentity.create({
                data: {
                    userId,
                    provider: AuthProvider.GOOGLE,
                    providerId: googleSub,
                    email: payload.email,
                },
            });
        }

        await this.prisma.auditLog.create({
            data: {
                userId,
                action: AuditAction.GOOGLE_ACCOUNT_LINKED,
                resource: 'user',
                resourceId: userId,
                details: { connected: 'GOOGLE' } as any,
                ipAddress,
                userAgent,
            },
        });

        const user = await this.prisma.user.findUnique({ where: { id: userId } });
        const { passwordHash: _, ...userWithoutPassword } = user!;
        return userWithoutPassword;
    }

    async connectOc(userId: string, dto: OcLoginDto, ipAddress?: string, userAgent?: string) {
        const OC_BASE = 'https://oc.odixtec.net';
        
        let tokenData: any;
        try {
            const tokenRes = await fetch(`${OC_BASE}/api/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    grant_type: 'authorization_code',
                    client_id: config.Client_ID,
                    client_secret: config.Client_Secret,
                    redirect_uri: config.OC_REDIRECT_URI,
                    code: dto.code,
                }),
                signal: AbortSignal.timeout(OC_REQUEST_TIMEOUT_MS),
            });
            if (!tokenRes.ok) {
                throw new Error('OC token exchange failed');
            }
            tokenData = await tokenRes.json();
        } catch (error) {
            throw new AuthenticationError('Failed to exchange OC code');
        }

        let payload: any;
        try {
            const userRes = await fetch(`${OC_BASE}/api/oauth/userinfo`, {
                headers: { Authorization: `Bearer ${tokenData.access_token}` },
                signal: AbortSignal.timeout(OC_REQUEST_TIMEOUT_MS),
            });
            if (!userRes.ok) {
                throw new Error('OC userinfo failed');
            }
            payload = await userRes.json();
        } catch (error) {
            throw new AuthenticationError('Failed to fetch OC user info');
        }

        const ocSub = payload?.sub ?? payload?.id;
        if (!payload || !ocSub || !payload.email) {
            throw new AuthenticationError('Invalid OC user payload');
        }

        const existingLink = await this.prisma.linkedIdentity.findUnique({
            where: { provider_providerId: { provider: AuthProvider.OC, providerId: ocSub.toString() } },
        });

        if (existingLink && existingLink.userId !== userId) {
            throw new ConflictError('This OC account is already connected to another user');
        }

        if (!existingLink) {
            await this.prisma.linkedIdentity.create({
                data: {
                    userId,
                    provider: AuthProvider.OC,
                    providerId: ocSub.toString(),
                    email: payload.email,
                },
            });
        }

        await this.prisma.auditLog.create({
            data: {
                userId,
                action: AuditAction.OC_ACCOUNT_LINKED,
                resource: 'user',
                resourceId: userId,
                details: { connected: 'OC' } as any,
                ipAddress,
                userAgent,
            },
        });

        const user = await this.prisma.user.findUnique({ where: { id: userId } });
        const { passwordHash: _, ...userWithoutPassword } = user!;
        return userWithoutPassword;
    }
}

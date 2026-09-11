import { injectable } from 'tsyringe';
import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { AuthService } from './auth.service';
import { AuthenticatedRequest, ApiResponse } from '../../core/types';
import { config } from '../../config';
import { accessTokenTtlMs, refreshTokenTtlMs } from '../../core/auth/token-lifetimes';

@injectable()
export class AuthController {
    constructor(private authService: AuthService) { }

    async register(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const user = await this.authService.register(
                req.body,
                req.ip,
                req.get('user-agent')
            );

            const response: ApiResponse = {
                success: true,
                message: 'Registration successful. Please check your email for a verification code.',
                data: user,
            };

            res.status(StatusCodes.CREATED).json(response);
        } catch (error) {
            next(error);
        }
    }

    async login(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.authService.login(
                req.body,
                req.ip,
                req.get('user-agent')
            );

            // Set cookies
            setAuthCookies(res, result.accessToken, result.refreshToken);

            const response: ApiResponse = {
                success: true,
                message: 'Login successful',
                data: { user: result.user },
            };

            res.status(StatusCodes.OK).json(response);
        } catch (error) {
            next(error);
        }
    }

    async refresh(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const refreshToken = req.cookies?.refreshToken;
            if (!refreshToken) {
                res.status(StatusCodes.UNAUTHORIZED).json({
                    success: false,
                    message: 'Refresh token is required',
                });
                return;
            }

            const result = await this.authService.refreshTokens(
                refreshToken,
                req.ip,
                req.get('user-agent')
            );

            setAuthCookies(res, result.accessToken, result.refreshToken);

            const response: ApiResponse = {
                success: true,
                message: 'Tokens refreshed successfully',
            };

            res.status(StatusCodes.OK).json(response);
        } catch (error) {
            next(error);
        }
    }

    async logout(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const refreshToken = req.cookies?.refreshToken;

            await this.authService.logout(
                refreshToken,
                req.user.userId,
                req.user.jti,
                req.ip,
                req.get('user-agent')
            );

            clearAuthCookies(res);

            const response: ApiResponse = {
                success: true,
                message: 'Logged out successfully',
            };

            res.status(StatusCodes.OK).json(response);
        } catch (error) {
            next(error);
        }
    }

    async logoutAll(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.authService.logoutAll(
                req.user.userId,
                req.ip,
                req.get('user-agent')
            );

            clearAuthCookies(res);

            const response: ApiResponse = {
                success: true,
                message: 'Logged out from all devices',
            };

            res.status(StatusCodes.OK).json(response);
        } catch (error) {
            next(error);
        }
    }

    async changePassword(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.authService.changePassword(req.user.userId, req.body);

            clearAuthCookies(res);

            const response: ApiResponse = {
                success: true,
                message: 'Password changed successfully. Please log in again.',
            };

            res.status(StatusCodes.OK).json(response);
        } catch (error) {
            next(error);
        }
    }

    async setupPassword(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.authService.setupPassword(req.user.userId, req.body);

            // Unlike changePassword, nothing here needs to force re-login —
            // there was no prior password whose compromise this closes off,
            // and the current session's credentials are unaffected.
            const response: ApiResponse = {
                success: true,
                message: 'Password set up successfully.',
            };

            res.status(StatusCodes.OK).json(response);
        } catch (error) {
            next(error);
        }
    }

    async getLoginHistory(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const history = await this.authService.getLoginHistory(req.user.userId);

            const response: ApiResponse = {
                success: true,
                message: 'Login history retrieved',
                data: history,
            };

            res.status(StatusCodes.OK).json(response);
        } catch (error) {
            next(error);
        }
    }

    // ─── Email Verification ────────────────────────────
    async verifyEmail(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.authService.verifyEmail(req.body);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Email verified successfully',
            });
        } catch (error) {
            next(error);
        }
    }

    async resendVerification(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.authService.resendVerification(req.body.email);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'If that email exists and is unverified, a verification code has been sent',
            });
        } catch (error) {
            next(error);
        }
    }

    // ─── Forgot / Reset Password ───────────────────────
    async forgotPassword(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.authService.forgotPassword(req.body.email);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'If that email exists, a password reset code has been sent',
            });
        } catch (error) {
            next(error);
        }
    }

    async resetPassword(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.authService.resetPassword(req.body);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Password reset successfully. Please log in with your new password.',
            });
        } catch (error) {
            next(error);
        }
    }

    // ─── Google OAuth ───────────────────────────────────
    async googleLogin(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.authService.googleLogin(
                req.body,
                req.ip,
                req.get('user-agent')
            );

            setAuthCookies(res, result.accessToken, result.refreshToken);

            const response: ApiResponse = {
                success: true,
                message: 'Google login successful',
                data: { user: result.user },
            };

            res.status(StatusCodes.OK).json(response);
        } catch (error) {
            next(error);
        }
    }

    // ─── OC OAuth ───────────────────────────────────────
    async ocLogin(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.authService.ocLogin(
                req.body,
                req.ip,
                req.get('user-agent')
            );

            setAuthCookies(res, result.accessToken, result.refreshToken);

            const response: ApiResponse = {
                success: true,
                message: 'OC login successful',
                data: { user: result.user },
            };

            res.status(StatusCodes.OK).json(response);
        } catch (error) {
            next(error);
        }
    }

    async connectGoogle(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const user = await this.authService.connectGoogle(
                req.user.userId,
                req.body,
                req.ip,
                req.get('user-agent')
            );
            res.status(StatusCodes.OK).json({ success: true, message: 'Google account connected', data: { user } });
        } catch (error) {
            next(error);
        }
    }

    async connectOc(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const user = await this.authService.connectOc(
                req.user.userId,
                req.body,
                req.ip,
                req.get('user-agent')
            );
            res.status(StatusCodes.OK).json({ success: true, message: 'OC account connected', data: { user } });
        } catch (error) {
            next(error);
        }
    }
}

// ─── Cookie Helpers ────────────────────────────────────

/**
 * A readable companion to the httpOnly access cookie, carrying only its expiry
 * time (epoch ms).
 *
 * The client cannot read the access cookie — that is the point of httpOnly —
 * so until now the only way it learned the token had lapsed was a request
 * bouncing with a 401, then a refresh, then a replay. Every poller did that
 * once per expiry window: a 401 in the browser while the server logs a 200 or
 * 304, because what the server sees last is the successful replay. Knowing
 * the expiry lets the client refresh just before it, so no request goes out
 * with a token already known to be dead.
 *
 * A timestamp is not a credential. It outlives the access cookie on purpose
 * (refresh-token lifetime), so an expired session reads as "expired at X"
 * rather than as "never logged in".
 */
const ACCESS_EXPIRY_COOKIE = 'accessTokenExpiresAt';

function baseCookieOptions() {
    return {
        secure: config.COOKIE_SECURE,
        sameSite: config.COOKIE_SAME_SITE as 'lax' | 'strict' | 'none',
        domain: config.COOKIE_DOMAIN,
    };
}

function setAuthCookies(res: Response, accessToken: string, refreshToken: string): void {
    const base = baseCookieOptions();
    // Both lifetimes come from the same config the tokens are signed with, so
    // a cookie can never outlive — or die before — the token it carries.
    const accessTtl = accessTokenTtlMs();
    const refreshTtl = refreshTokenTtlMs();

    res.cookie('accessToken', accessToken, { ...base, httpOnly: true, maxAge: accessTtl });

    res.cookie('refreshToken', refreshToken, {
        ...base,
        httpOnly: true,
        maxAge: refreshTtl,
        path: '/api/v1/auth', // Only sent to auth routes
    });

    res.cookie(ACCESS_EXPIRY_COOKIE, String(Date.now() + accessTtl), {
        ...base,
        httpOnly: false,
        maxAge: refreshTtl,
        path: '/',
    });
}

function clearAuthCookies(res: Response): void {
    const base = baseCookieOptions();
    res.clearCookie('accessToken', { ...base, httpOnly: true });
    res.clearCookie('refreshToken', { ...base, httpOnly: true, path: '/api/v1/auth' });
    res.clearCookie(ACCESS_EXPIRY_COOKIE, { ...base, path: '/' });
}

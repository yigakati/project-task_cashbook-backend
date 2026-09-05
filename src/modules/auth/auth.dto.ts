import { z } from 'zod';

export const registerSchema = z.object({
    email: z.string().email('Invalid email address'),
    password: z
        .string()
        .min(8, 'Password must be at least 8 characters')
        .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
        .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
        .regex(/[0-9]/, 'Password must contain at least one number')
        .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
    firstName: z.string().min(1, 'First name is required').max(100),
    lastName: z.string().min(1, 'Last name is required').max(100),
    /** ISO 3166-1 alpha-2 (e.g. UG, KE, US) — decides the currency the
     *  personal workspace (and its seeded wallets) is born in. */
    country: z.string().trim().length(2, 'Use the 2-letter country code').optional(),
});

export const loginSchema = z.object({
    email: z.string().email('Invalid email address'),
    password: z.string().min(1, 'Password is required'),
});

export const refreshTokenSchema = z.object({
    // Refresh token comes from cookies, no body required
});

export const changePasswordSchema = z.object({
    currentPassword: z.string().min(1, 'Current password is required'),
    newPassword: z
        .string()
        .min(8, 'Password must be at least 8 characters')
        .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
        .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
        .regex(/[0-9]/, 'Password must contain at least one number')
        .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
});

/**
 * For accounts with no password yet (Google/OC-only signups). No
 * `currentPassword` field — that's what distinguishes it from
 * `changePasswordSchema`, and auth.service.ts#setupPassword refuses to run at
 * all once a password already exists, so this can't be used to bypass that
 * check even if a client sent it anyway.
 */
export const setupPasswordSchema = z.object({
    newPassword: z
        .string()
        .min(8, 'Password must be at least 8 characters')
        .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
        .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
        .regex(/[0-9]/, 'Password must contain at least one number')
        .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
});

export const verifyEmailSchema = z.object({
    email: z.string().email('Invalid email address'),
    otp: z.string().length(6, 'OTP must be 6 digits'),
});

export const resendVerificationSchema = z.object({
    email: z.string().email('Invalid email address'),
});

export const forgotPasswordSchema = z.object({
    email: z.string().email('Invalid email address'),
});

export const resetPasswordSchema = z.object({
    email: z.string().email('Invalid email address'),
    otp: z.string().length(6, 'OTP must be 6 digits'),
    newPassword: z
        .string()
        .min(8, 'Password must be at least 8 characters')
        .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
        .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
        .regex(/[0-9]/, 'Password must contain at least one number')
        .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
});

export const googleLoginSchema = z.object({
    idToken: z.string().min(1, 'Google ID token is required'),
});

/**
 * `redirectUri` is deliberately not accepted here. OC's OAuth app registration
 * takes redirect URIs as a fixed list at app-creation time — there is exactly
 * one value that will ever be valid for this app (`config.OC_REDIRECT_URI`),
 * so the server supplies it itself when exchanging the code rather than
 * trusting whatever a client sends. See auth.service.ts#ocLogin.
 */
export const ocLoginSchema = z.object({
    code: z.string().min(1, 'Authorization code is required'),
});

export type RegisterDto = z.infer<typeof registerSchema>;
export type LoginDto = z.infer<typeof loginSchema>;
export type ChangePasswordDto = z.infer<typeof changePasswordSchema>;
export type SetupPasswordDto = z.infer<typeof setupPasswordSchema>;
export type VerifyEmailDto = z.infer<typeof verifyEmailSchema>;
export type ResendVerificationDto = z.infer<typeof resendVerificationSchema>;
export type ForgotPasswordDto = z.infer<typeof forgotPasswordSchema>;
export type ResetPasswordDto = z.infer<typeof resetPasswordSchema>;
export type GoogleLoginDto = z.infer<typeof googleLoginSchema>;
export type OcLoginDto = z.infer<typeof ocLoginSchema>;

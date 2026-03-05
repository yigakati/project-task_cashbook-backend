import { config } from '../config';

/**
 * Branded email template for email verification OTP.
 */
export function verificationEmailTemplate(firstName: string, otp: string): string {
    return `
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 520px; margin: 0 auto; padding: 32px; background: #ffffff; border-radius: 12px; border: 1px solid #e5e7eb;">
        <h2 style="color: #111827; margin-bottom: 8px;">Verify your email</h2>
        <p style="color: #6b7280; font-size: 15px; line-height: 1.6;">
            Hi ${firstName}, welcome to <strong>${config.APP_NAME}</strong>! Use the code below to verify your email address.
        </p>
        <div style="text-align: center; margin: 28px 0;">
            <span style="display: inline-block; font-size: 32px; font-weight: 700; letter-spacing: 6px; color: #111827; background: #f3f4f6; padding: 14px 28px; border-radius: 8px;">${otp}</span>
        </div>
        <p style="color: #9ca3af; font-size: 13px;">
            This code expires in <strong>15 minutes</strong>. If you didn't create an account, you can safely ignore this email.
        </p>
    </div>`;
}

/**
 * Branded email template for password-reset OTP.
 */
export function passwordResetEmailTemplate(firstName: string, otp: string): string {
    return `
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 520px; margin: 0 auto; padding: 32px; background: #ffffff; border-radius: 12px; border: 1px solid #e5e7eb;">
        <h2 style="color: #111827; margin-bottom: 8px;">Reset your password</h2>
        <p style="color: #6b7280; font-size: 15px; line-height: 1.6;">
            Hi ${firstName}, we received a request to reset your <strong>${config.APP_NAME}</strong> password. Use the code below to proceed.
        </p>
        <div style="text-align: center; margin: 28px 0;">
            <span style="display: inline-block; font-size: 32px; font-weight: 700; letter-spacing: 6px; color: #111827; background: #f3f4f6; padding: 14px 28px; border-radius: 8px;">${otp}</span>
        </div>
        <p style="color: #9ca3af; font-size: 13px;">
            This code expires in <strong>15 minutes</strong>. If you didn't request a password reset, you can safely ignore this email.
        </p>
    </div>`;
}

/**
 * Invitation email for users who already have an account.
 * Tells them they've been added and should log in.
 */
export function workspaceInviteEmailTemplate(
    recipientName: string,
    workspaceName: string,
    inviterName: string,
    role: string,
): string {
    return `
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 520px; margin: 0 auto; padding: 32px; background: #ffffff; border-radius: 12px; border: 1px solid #e5e7eb;">
        <h2 style="color: #111827; margin-bottom: 8px;">You've been added to a workspace</h2>
        <p style="color: #6b7280; font-size: 15px; line-height: 1.6;">
            Hi ${recipientName}, <strong>${inviterName}</strong> has added you to the
            <strong>${workspaceName}</strong> workspace on <strong>${config.APP_NAME}</strong>
            as a <strong>${role}</strong>.
        </p>
        <div style="text-align: center; margin: 28px 0;">
            <a href="${config.CORS_ORIGINS}" style="display: inline-block; padding: 12px 32px; background: #111827; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px;">Log in to get started</a>
        </div>
        <p style="color: #9ca3af; font-size: 13px;">
            You can access this workspace immediately after logging in.
        </p>
    </div>`;
}

/**
 * Invitation email for users who don't have an account yet.
 * Prompts them to sign up to join the workspace.
 */
export function workspaceInviteSignupEmailTemplate(
    email: string,
    workspaceName: string,
    inviterName: string,
    role: string,
): string {
    return `
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 520px; margin: 0 auto; padding: 32px; background: #ffffff; border-radius: 12px; border: 1px solid #e5e7eb;">
        <h2 style="color: #111827; margin-bottom: 8px;">You've been invited to join ${config.APP_NAME}</h2>
        <p style="color: #6b7280; font-size: 15px; line-height: 1.6;">
            Hi there! <strong>${inviterName}</strong> has invited you to join the
            <strong>${workspaceName}</strong> workspace on <strong>${config.APP_NAME}</strong>
            as a <strong>${role}</strong>.
        </p>
        <div style="text-align: center; margin: 28px 0;">
            <a href="${config.CORS_ORIGINS}" style="display: inline-block; padding: 12px 32px; background: #111827; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px;">Sign up to join</a>
        </div>
        <p style="color: #9ca3af; font-size: 13px;">
            Create your account using <strong>${email}</strong> and you'll automatically be added to the workspace. This invitation expires in <strong>7 days</strong>.
        </p>
    </div>`;
}

/**
 * Onboarding welcome email template for newly verified/created users.
 */
export function welcomeEmailTemplate(firstName: string): string {
    return `
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 520px; margin: 0 auto; padding: 32px; background: #ffffff; border-radius: 12px; border: 1px solid #e5e7eb;">
        <h2 style="color: #111827; margin-bottom: 8px;">Welcome to ${config.APP_NAME}!</h2>
        <p style="color: #6b7280; font-size: 15px; line-height: 1.6;">
            Hi ${firstName}, we're absolutely thrilled to have you here! Our platform is designed to give you the best features to manage your accounts seamlessly and track your cash flows with unparalleled precision.
        </p>
        <div style="text-align: center; margin: 28px 0;">
            <a href="${config.CORS_ORIGINS}" style="display: inline-block; padding: 12px 32px; background: #111827; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px;">Get Started Now</a>
        </div>
        <p style="color: #6b7280; font-size: 15px; line-height: 1.6;">
            If you ever need any assistance, feel free to reach out. We are always here to help you succeed!
        </p>
        <p style="color: #9ca3af; font-size: 13px; margin-top: 32px;">
            The ${config.APP_NAME} Team
        </p>
    </div>`;
}

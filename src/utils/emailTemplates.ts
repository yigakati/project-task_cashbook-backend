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
        <h2 style="color: #111827; margin-bottom: 8px;">You've been invited to a workspace</h2>
        <p style="color: #6b7280; font-size: 15px; line-height: 1.6;">
            Hi ${recipientName}, <strong>${inviterName}</strong> has invited you to join the
            <strong>${workspaceName}</strong> workspace on <strong>${config.APP_NAME}</strong>
            as a <strong>${role}</strong>.
        </p>
        <div style="text-align: center; margin: 28px 0;">
            <a href="${config.CORS_ORIGINS}" style="display: inline-block; padding: 12px 32px; background: #111827; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px;">Log in to review your invitations</a>
        </div>
        <p style="color: #9ca3af; font-size: 13px;">
            You can accept or decline this invitation from your pending invitations dashboard.
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

/**
 * Professional invoice delivery email.
 * Sent to the customer when an invoice is marked as SENT.
 *
 * @param customerName   Full name of the customer / contact
 * @param businessName   Display name of the sending workspace / business
 * @param invoiceNumber  e.g. "INV-0042"
 * @param currency       e.g. "UGX"
 * @param totalAmount    Formatted total string  e.g. "1,200,000.00"
 * @param dueDate        Formatted due-date string e.g. "30 Apr 2025"
 * @param itemsSummary   Short plaintext summary of line items (max 5)
 * @param notes          Optional notes from the invoice
 * @param logoUrl        Optional logo URL — falls back to platform logo
 */
export function invoiceEmailTemplate(params: {
    customerName: string;
    businessName: string;
    invoiceNumber: string;
    currency: string;
    totalAmount: string;
    dueDate: string;
    itemsSummary: Array<{ name: string; quantity: string; total: string }>;
    notes?: string | null;
    logoUrl?: string | null;
}): string {
    const {
        customerName,
        businessName,
        invoiceNumber,
        currency,
        totalAmount,
        dueDate,
        itemsSummary,
        notes,
        logoUrl,
    } = params;

    const FALLBACK_LOGO = 'https://inchange.odixtec.net/reportlogo.svg';
    const logo = logoUrl || FALLBACK_LOGO;

    const itemRows = itemsSummary
        .slice(0, 5)
        .map(
            (i) => `
            <tr>
                <td style="padding: 10px 0; border-bottom: 1px solid #f3f4f6; color: #374151; font-size: 14px;">${i.name}</td>
                <td style="padding: 10px 0; border-bottom: 1px solid #f3f4f6; color: #6b7280; font-size: 14px; text-align: center;">${i.quantity}</td>
                <td style="padding: 10px 0; border-bottom: 1px solid #f3f4f6; color: #111827; font-size: 14px; text-align: right; font-weight: 600;">${currency} ${i.total}</td>
            </tr>`
        )
        .join('');

    const moreItems = itemsSummary.length > 5
        ? `<tr><td colspan="3" style="padding: 8px 0; color: #9ca3af; font-size: 13px;">+ ${itemsSummary.length - 5} more item(s) — see attached PDF</td></tr>`
        : '';

    const notesBlock = notes
        ? `<div style="margin-top: 20px; padding: 14px 16px; background: #f9fafb; border-left: 3px solid #e5e7eb; border-radius: 4px;">
               <p style="margin: 0; color: #6b7280; font-size: 13px; line-height: 1.6;">${notes}</p>
           </div>`
        : '';

    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Invoice ${invoiceNumber}</title>
    </head>
    <body style="margin: 0; padding: 0; background: #f3f4f6; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">

        <!-- Wrapper -->
        <table width="100%" cellpadding="0" cellspacing="0" style="background: #f3f4f6; padding: 32px 0;">
        <tr><td align="center">

        <!-- Card -->
        <table width="580" cellpadding="0" cellspacing="0" style="background: #ffffff; border-radius: 12px; overflow: hidden; border: 1px solid #e5e7eb; max-width: 580px;">

            <!-- Header band -->
            <tr>
                <td style="background: #111827; padding: 28px 36px 24px;">
                    <table width="100%" cellpadding="0" cellspacing="0">
                        <tr>
                            <td>
                                <img src="${logo}" alt="${businessName}" height="36"
                                     style="display: block; height: 36px; max-width: 150px; object-fit: contain;"
                                     onerror="this.style.display='none'" />
                                <p style="margin: 8px 0 0; color: #ffffff; font-size: 16px; font-weight: 700;">${businessName}</p>
                            </td>
                            <td align="right" style="vertical-align: top;">
                                <p style="margin: 0; color: #9ca3af; font-size: 11px; font-weight: 600; letter-spacing: 1px;">INVOICE</p>
                                <p style="margin: 4px 0 0; color: #ffffff; font-size: 20px; font-weight: 700;">${invoiceNumber}</p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>

            <!-- Body -->
            <tr>
                <td style="padding: 32px 36px 0;">

                    <!-- Greeting -->
                    <p style="margin: 0 0 20px; color: #374151; font-size: 15px; line-height: 1.6;">
                        Dear <strong>${customerName}</strong>,
                    </p>
                    <p style="margin: 0 0 28px; color: #6b7280; font-size: 14px; line-height: 1.7;">
                        Please find your invoice attached to this email as a PDF. A summary of your charges is below.
                    </p>

                    <!-- Amount due highlight -->
                    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 28px;">
                        <tr>
                            <td style="background: #f9fafb; border-radius: 8px; padding: 18px 22px;">
                                <table width="100%" cellpadding="0" cellspacing="0">
                                    <tr>
                                        <td>
                                            <p style="margin: 0; color: #6b7280; font-size: 12px; font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase;">Amount Due</p>
                                            <p style="margin: 4px 0 0; color: #111827; font-size: 26px; font-weight: 700;">${currency} ${totalAmount}</p>
                                        </td>
                                        <td align="right">
                                            <p style="margin: 0; color: #6b7280; font-size: 12px; font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase;">Due Date</p>
                                            <p style="margin: 4px 0 0; color: #DC2626; font-size: 15px; font-weight: 700;">${dueDate}</p>
                                        </td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                    </table>

                    <!-- Items summary table -->
                    <p style="margin: 0 0 10px; color: #374151; font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;">Invoice Summary</p>
                    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 8px;">
                        <thead>
                            <tr style="background: #f9fafb;">
                                <th style="padding: 8px 0; text-align: left; color: #9ca3af; font-size: 11px; font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase;">Item</th>
                                <th style="padding: 8px 0; text-align: center; color: #9ca3af; font-size: 11px; font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase;">Qty</th>
                                <th style="padding: 8px 0; text-align: right; color: #9ca3af; font-size: 11px; font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase;">Total</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${itemRows}
                            ${moreItems}
                        </tbody>
                    </table>

                    ${notesBlock}

                    <!-- CTA note -->
                    <p style="margin: 28px 0 0; color: #6b7280; font-size: 13px; line-height: 1.6;">
                        The full invoice with a breakdown of all charges is attached as a PDF. Please arrange payment by the due date.
                    </p>

                </td>
            </tr>

            <!-- Footer -->
            <tr>
                <td style="padding: 28px 36px 32px; border-top: 1px solid #f3f4f6; margin-top: 28px;">
                    <p style="margin: 0; color: #9ca3af; font-size: 12px; line-height: 1.6;">
                        This invoice was generated by <strong>${config.APP_NAME}</strong>. If you have questions about this invoice, please contact <strong>${businessName}</strong> directly.
                    </p>
                    <p style="margin: 12px 0 0; color: #d1d5db; font-size: 11px;">
                        © ${new Date().getFullYear()} ${config.APP_NAME}. All rights reserved.
                    </p>
                </td>
            </tr>

        </table>
        <!-- /Card -->

        </td></tr>
        </table>
        <!-- /Wrapper -->

    </body>
    </html>`;
}

/**
 * Professional payment receipt email.
 * Sent to the customer when a payment is recorded against an obligation.
 *
 * @param customerName   Full name of the customer
 * @param businessName   Display name of the sending workspace / business
 * @param receiptNumber  e.g. "RC-ABC1234"
 * @param obligationName e.g. "Invoice INV-0042"
 * @param currency       e.g. "UGX"
 * @param amountPaid     Formatted payment amount string e.g. "500,000.00"
 * @param paymentDate    Formatted payment date e.g. "25 Mar 2025"
 * @param remainingBal   Remaining obligation balance e.g. "700,000.00"
 * @param logoUrl        Optional logo URL — falls back to platform logo
 */
export function receiptEmailTemplate(params: {
    customerName: string;
    businessName: string;
    receiptNumber: string;
    obligationName: string;
    currency: string;
    amountPaid: string;
    paymentDate: string;
    remainingBal: string;
    logoUrl?: string | null;
}): string {
    const {
        customerName,
        businessName,
        receiptNumber,
        obligationName,
        currency,
        amountPaid,
        paymentDate,
        remainingBal,
        logoUrl
    } = params;
    
    // Use fallback logo if none provided
    const _logoUrl = logoUrl || 'https://inchange.odixtec.net/reportlogo.svg';

    return `<!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Payment Receipt from ${businessName}</title>
    </head>
    <body style="margin: 0; padding: 24px 0; background-color: #f3f4f6; -webkit-font-smoothing: antialiased; word-break: break-word;">

        <table width="100%" cellpadding="0" cellspacing="0" border="0">
        <tr><td align="center">

        <table width="600" cellpadding="0" cellspacing="0" border="0" style="max-width: 600px; width: 100%; border-radius: 12px; overflow: hidden; font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
            
            <!-- Header Band (Dark) -->
            <tr>
                <td style="background-color: #111827; padding: 32px 40px; text-align: center;">
                    <img src="${_logoUrl}" alt="${businessName} Logo" style="max-height: 44px; max-width: 180px; display: block; margin: 0 auto 24px; object-fit: contain;">
                    <p style="margin: 0 0 8px; color: #9ca3af; font-size: 13px; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 600;">
                        Payment Receipt
                    </p>
                    <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 700;">
                        Receipt #${receiptNumber}
                    </h1>
                </td>
            </tr>

            <!-- Content Area (White) -->
            <tr>
                <td style="background-color: #ffffff; padding: 40px;">
                    <p style="margin: 0 0 16px; font-size: 16px; color: #374151;">
                        Hello <strong>${customerName}</strong>,
                    </p>
                    <p style="margin: 0 0 32px; font-size: 16px; color: #4b5563; line-height: 1.6;">
                        Thank you for your business. We have successfully received a payment of <strong>${currency} ${amountPaid}</strong> from you on <strong>${paymentDate}</strong>.
                    </p>

                    <!-- Amount Box -->
                    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 32px;">
                        <tr>
                            <td style="padding: 24px; text-align: center;">
                                <p style="margin: 0 0 8px; font-size: 13px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600;">
                                    Payment Applied To
                                </p>
                                <p style="margin: 0 0 20px; font-size: 22px; color: #0f172a; font-weight: 700;">
                                    ${obligationName}
                                </p>

                                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top: 16px;">
                                    <tr>
                                        <td style="padding: 12px 0; border-top: 1px solid #e2e8f0; border-bottom: 1px solid #e2e8f0; text-align: left; color: #64748b; font-size: 15px;">
                                            Amount Paid
                                        </td>
                                        <td style="padding: 12px 0; border-top: 1px solid #e2e8f0; border-bottom: 1px solid #e2e8f0; text-align: right; color: #16a34a; font-size: 15px; font-weight: 600;">
                                            ${currency} ${amountPaid}
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 12px 0; text-align: left; color: #64748b; font-size: 15px;">
                                            Remaining Balance
                                        </td>
                                        <td style="padding: 12px 0; text-align: right; color: #0f172a; font-size: 15px; font-weight: 600;">
                                            ${currency} ${remainingBal}
                                        </td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                    </table>

                    <p style="margin: 0 0 32px; font-size: 15px; color: #4b5563; line-height: 1.6;">
                        A detailed PDF receipt is attached to this email for your records. Please keep it for your financial tracking.
                    </p>

                    <!-- Sign-off -->
                    <p style="margin: 0 0 8px; font-size: 16px; color: #374151;">Best regards,</p>
                    <p style="margin: 0; font-size: 16px; color: #111827; font-weight: 600;">${businessName}</p>
                </td>
            </tr>

            <!-- Footer Area (Dark) -->
            <tr>
                <td style="background-color: #1f2937; padding: 22px 36px; text-align: center;">
                    <img src="https://inchange.odixtec.net/reportlogo.svg" alt="Odixtec Logo" style="height: 20px; opacity: 0.7; margin-bottom: 12px;">
                    <p style="margin: 0; color: #9ca3af; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em;">
                        Powered by ${config.APP_NAME}
                    </p>
                    <p style="margin: 12px 0 0; color: #d1d5db; font-size: 11px;">
                        © ${new Date().getFullYear()}  ${config.APP_NAME}. All rights reserved.
                    </p>
                </td>
            </tr>

        </table>
        <!-- /Card -->

        </td></tr>
        </table>
        <!-- /Wrapper -->

    </body>
    </html>`;
}


/**
 * Inviting someone who has no account yet to become a contact.
 *
 * Unlike the in-app request, this is the entire delivery mechanism — there is
 * no inbox to land in — so it has to carry enough context for a cold recipient
 * to know who is asking and why, and it links to signup rather than login.
 */
export function contactInviteSignupEmailTemplate(params: {
    senderName: string;
    message: string | null;
    signupUrl: string;
}): string {
    const { senderName, message, signupUrl } = params;
    return `
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 520px; margin: 0 auto; padding: 32px; background: #ffffff; border-radius: 12px; border: 1px solid #e5e7eb;">
        <h2 style="color: #111827; margin-bottom: 8px;">${senderName} wants to add you as a contact</h2>
        <p style="color: #6b7280; font-size: 15px; line-height: 1.6;">
            <strong>${senderName}</strong> uses <strong>${config.APP_NAME}</strong> to keep
            track of who they do business with, and would like to record you as a contact.
        </p>
        ${message ? `<blockquote style="margin: 20px 0; padding: 12px 16px; border-left: 3px solid #e5e7eb; color: #4b5563; font-size: 14px; font-style: italic;">${message}</blockquote>` : ''}
        <p style="color: #6b7280; font-size: 15px; line-height: 1.6;">
            Create a free account and the request will be waiting for you. You choose
            which of your businesses to share, what to share, and you can decline.
        </p>
        <div style="text-align: center; margin: 28px 0;">
            <a href="${signupUrl}" style="display: inline-block; padding: 12px 32px; background: #111827; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px;">Create an account</a>
        </div>
        <p style="color: #9ca3af; font-size: 13px;">
            If you do not know ${senderName}, you can ignore this email — nothing is shared
            unless you accept.
        </p>
    </div>`;
}

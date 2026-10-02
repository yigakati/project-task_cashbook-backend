import nodemailer, { Transporter } from 'nodemailer';
import { config } from './index';
import { logger } from '../utils/logger';
import { emailQueue } from './queues';

let transporter: Transporter | null = null;

/**
 * Whether SMTP is actually configured.
 *
 * SMTP_USER and SMTP_PASS default to empty strings so the app can boot without
 * mail credentials. That is convenient in development and a trap in
 * production: without this check every queued email opens a connection with
 * blank credentials, fails authentication, and is retried three times with
 * backoff — which is what a queue full of "errors on startup" actually is.
 */
export function isEmailConfigured(): boolean {
    return Boolean(config.SMTP_HOST && config.SMTP_USER && config.SMTP_PASS);
}

export function getEmailTransporter(): Transporter {
    if (!transporter) {
        transporter = nodemailer.createTransport({
            host: config.SMTP_HOST,
            port: config.SMTP_PORT,
            secure: config.SMTP_SECURE,
            auth: {
                user: config.SMTP_USER,
                pass: config.SMTP_PASS,
            },
            // Without these a dead or wrong host hangs the worker slot until the
            // OS gives up, which is minutes rather than seconds.
            connectionTimeout: 10_000,
            greetingTimeout: 10_000,
            socketTimeout: 20_000,
        });
    }
    return transporter;
}

/**
 * Check the credentials once, at boot, and say so plainly.
 *
 * Better to learn that mail is misconfigured from one startup line than from a
 * user reporting that their invite never arrived.
 */
export async function verifyEmailTransport(): Promise<boolean> {
    if (!isEmailConfigured()) {
        logger.warn(
            '✉️  SMTP is not configured (SMTP_USER/SMTP_PASS empty). '
            + 'Emails will be skipped rather than queued.',
        );
        return false;
    }
    try {
        await getEmailTransporter().verify();
        logger.info('✉️  SMTP connection verified');
        return true;
    } catch (error) {
        logger.error(
            '✉️  SMTP is configured but the connection failed. Emails will fail until fixed.',
            { error: error instanceof Error ? error.message : String(error) },
        );
        return false;
    }
}

export interface EmailOptions {
    to: string;
    subject: string;
    html: string;
    /** Where replies go, e.g. the person who used the contact form. */
    replyTo?: string;
    attachments?: Array<{
        filename: string;
        content: Buffer;
        contentType: string;
    }>;
}

/**
 * Send email via BullMQ queue (non-blocking).
 * The email will be processed by the email worker with retry logic.
 */
export async function sendEmail(options: EmailOptions): Promise<void> {
    // Don't queue what cannot be sent. Enqueuing into an unconfigured transport
    // just builds a backlog of jobs that each fail three times, and buries the
    // one useful signal — that SMTP was never set up — under retry noise.
    if (!isEmailConfigured()) {
        logger.warn('Email skipped: SMTP is not configured', {
            to: options.to,
            subject: options.subject,
        });
        return;
    }

    try {
        // Prevent massive Base64 serialization OOM spikes by bypassing the Queue for attachments.
        if (options.attachments && options.attachments.length > 0) {
            return await sendEmailDirect(options);
        }

        await emailQueue.add('send-email', {
            to: options.to,
            subject: options.subject,
            html: options.html,
            ...(options.replyTo && { replyTo: options.replyTo }),
        });

        logger.info('Email queued successfully', { to: options.to, subject: options.subject });
    } catch (error) {
        logger.error('Failed to queue email', {
            to: options.to,
            subject: options.subject,
            error: error instanceof Error ? error.message : String(error),
        });
        throw error;
    }
}

/**
 * Send email directly (synchronous, bypasses the queue).
 * Used in critical paths where we need immediate delivery confirmation.
 */
export async function sendEmailDirect(options: EmailOptions): Promise<void> {
    if (!isEmailConfigured()) {
        logger.warn('Email skipped: SMTP is not configured', {
            to: options.to,
            subject: options.subject,
        });
        return;
    }

    try {
        const transport = getEmailTransporter();
        await transport.sendMail({
            from: `"${config.EMAIL_FROM_NAME}" <${config.EMAIL_FROM}>`,
            to: options.to,
            subject: options.subject,
            html: options.html,
            replyTo: options.replyTo,
            attachments: options.attachments,
        });
        logger.info('Email sent directly', { to: options.to, subject: options.subject });
    } catch (error) {
        logger.error('Failed to send email directly', {
            to: options.to,
            subject: options.subject,
            error: error instanceof Error ? error.message : String(error),
        });
        throw error;
    }
}

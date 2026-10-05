import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const envSchema = z.object({
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    PORT: z.coerce.number().default(5000),
    API_PREFIX: z.string().default('/api/v1'),
    /** The product name in every email subject and body. */
    APP_NAME: z.string().default('InChange'),

    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),

    REDIS_URL: z.string().default('redis://localhost:6379'),

    JWT_ACCESS_SECRET: z.string().min(32, 'JWT_ACCESS_SECRET must be at least 32 characters'),
    JWT_REFRESH_SECRET: z.string().min(32, 'JWT_REFRESH_SECRET must be at least 32 characters'),
    JWT_ACCESS_EXPIRY: z.string().default('15m'),
    JWT_REFRESH_EXPIRY: z.string().default('7d'),
    BCRYPT_SALT_ROUNDS: z.coerce.number().default(12),

    COOKIE_DOMAIN: z.string().default(''),
    COOKIE_SECURE: z.string().default('false').transform((val) => val === 'true'),
    COOKIE_SAME_SITE: z.enum(['lax', 'strict', 'none']).default('lax'),

    CORS_ORIGINS: z.string().default('http://localhost:3001'),

    RATE_LIMIT_WINDOW_MS: z.coerce.number().default(900000),
    RATE_LIMIT_MAX: z.coerce.number().default(1000),

    MINIO_ENDPOINT: z.string().default('localhost'),
    MINIO_PORT: z.coerce.number().default(9000),
    MINIO_USE_SSL: z.string().default('false').transform((v) => v === 'true'),
    MINIO_ACCESS_KEY: z.string().min(1, 'MINIO_ACCESS_KEY is required'),
    MINIO_SECRET_KEY: z.string().min(1, 'MINIO_SECRET_KEY is required'),
    MINIO_BUCKET: z.string().default('cashbook-attachments'),

    SMTP_HOST: z.string().default('smtp.gmail.com'),
    SMTP_PORT: z.coerce.number().default(587),
    SMTP_SECURE: z.string().default('false').transform((val) => val === 'true'),
    SMTP_USER: z.string().default(''),
    SMTP_PASS: z.string().default(''),
    EMAIL_FROM: z.string().default('noreply@cashbook.com'),
    EMAIL_FROM_NAME: z.string().default('InChange'),

    LOG_LEVEL: z.string().default('debug'),
    LOG_DIR: z.string().default('logs'),

    /**
     * Comma-separated list of platform superadmin emails.
     *
     * This env var is the single source of truth: on boot and on every login,
     * users in the list are promoted and users no longer in it are demoted.
     * Editing it therefore takes effect without touching the database.
     */
    SUPER_ADMIN_EMAILS: z.string().default(''),
    /** Superseded by SUPER_ADMIN_EMAILS; still read so existing deploys keep working. */
    SUPER_ADMIN_EMAIL: z.string().email().default('admin@cashbook.com'),

    /**
     * The sign-in handed to app-store reviewers (Google Play's "App access").
     * Ensured on every boot — created if missing, repaired if its password,
     * verification or workspace drifted — so the credentials in the store
     * listing always work. Set REVIEW_ACCOUNT_EMAIL to empty to stop.
     *
     * The defaults are the ones submitted to Play. They grant nothing beyond an
     * ordinary personal account, and the reviewer already holds them; override
     * both in the environment to rotate.
     */
    REVIEW_ACCOUNT_EMAIL: z.string().trim().toLowerCase().default('user@playstore.com'),
    REVIEW_ACCOUNT_PASSWORD: z.string().default('secret2026'),

    /**
     * Double-entry ledger rollout switch.
     *
     *   off    no journals are written (pre-ledger behaviour)
     *   shadow journals are written alongside the legacy balance arithmetic,
     *          which still owns the cached columns. The integrity verifier
     *          compares the two; any mismatch is a posting-rule bug caught
     *          before anything depends on it.
     *   on     the ledger is the source of truth and the sole writer of caches
     */
    LEDGER_MODE: z.enum(['off', 'shadow', 'on']).default('on'),

    GOOGLE_CLIENT_ID: z.string().default(''),

    /**
     * OC (OpenChat) OAuth. Names kept exactly as they already exist in this
     * deployment's `.env` — unconventional casing for a shell var, but renaming
     * would mean every environment's `.env` has to be edited in lockstep with
     * this file, and getting that out of sync silently breaks the login route
     * rather than failing loudly at boot the way an unset required var does.
     */
    Client_ID: z.string().default(''),
    Client_Secret: z.string().default(''),
    OC_BASE_URL: z.string().url().default('https://oc.odixtec.com'),
    /**
     * The one redirect URI registered against this OC OAuth app. OC's
     * dashboard takes redirect URIs at app-creation time as a fixed list, not
     * something a client can vary per-request — so this is not configuration
     * we accept from the frontend, only a value the server supplies itself
     * when exchanging a code. See auth.service.ts#ocLogin.
     */
    OC_REDIRECT_URI: z.string().url().default('https://inchange.odixtec.com/auth/callback'),

    /**
     * Where the frontend lives, for links that land in someone's inbox — a
     * referral share link, a contact invite.
     *
     * A single URL on purpose: CORS_ORIGINS is a comma-separated list, so
     * using it as an href (as some older templates do) renders every origin
     * joined together into one broken link.
     */
    APP_URL: z.string().url().default('https://inchange.odixtec.com'),

    /**
     * This API's own externally reachable base URL.
     *
     * Used to build links to assets the API serves — an invoice logo, which is
     * shown in the app and embedded in the email a customer opens. Rows store
     * only the object key, so changing this re-points every logo instead of
     * stranding the ones uploaded under the old address.
     *
     * Set it in production: the default is only right on a dev machine.
     */
    API_PUBLIC_URL: z.string().url().default('http://localhost:5000'),

    /**
     * Days between confirming an account deletion and carrying it out. The
     * owner can sign in and cancel at any point in between, which is what
     * makes a mistaken — or someone else's — request recoverable.
     */
    ACCOUNT_DELETION_GRACE_DAYS: z.coerce.number().int().min(0).max(30).default(14),

    /**
     * Where messages from the public contact page are forwarded, with the
     * sender as Reply-To. Every message is also stored and listed on the
     * Platform page, so leaving this empty loses nothing — it just means
     * nobody is emailed.
     */
    SUPPORT_INBOX_EMAIL: z.union([z.string().email(), z.literal('')]).default('info@odixtec.net'),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
    console.error('❌ Invalid environment variables:', JSON.stringify(parsed.error.format(), null, 2));
    process.exit(1);
}

export const config = parsed.data;
export type Config = z.infer<typeof envSchema>;

/**
 * The normalized superadmin allow-list.
 *
 * Merges SUPER_ADMIN_EMAILS (the list) with the legacy single-value
 * SUPER_ADMIN_EMAIL so existing deploys are not silently demoted on upgrade.
 * Lower-cased and de-duplicated, because email comparison is case-insensitive
 * and a stray duplicate should not change behaviour.
 */
export function superAdminEmails(): string[] {
    const fromList = config.SUPER_ADMIN_EMAILS.split(',')
        .map((e) => e.trim().toLowerCase())
        .filter(Boolean);

    const legacy = config.SUPER_ADMIN_EMAIL?.trim().toLowerCase();
    // The old default is a placeholder, not a real grant.
    if (legacy && legacy !== 'admin@cashbook.com') fromList.push(legacy);

    return [...new Set(fromList)];
}

import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const envSchema = z.object({
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    PORT: z.coerce.number().default(5000),
    API_PREFIX: z.string().default('/api/v1'),
    APP_NAME: z.string().default('CashBook SaaS'),

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
    RATE_LIMIT_MAX: z.coerce.number().default(500),

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
    EMAIL_FROM_NAME: z.string().default('CashBook SaaS'),

    LOG_LEVEL: z.string().default('debug'),
    LOG_DIR: z.string().default('logs'),

    SUPER_ADMIN_EMAIL: z.string().email().default('admin@cashbook.com'),

    GOOGLE_CLIENT_ID: z.string().default(''),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
    console.error('❌ Invalid environment variables:', JSON.stringify(parsed.error.format(), null, 2));
    process.exit(1);
}

export const config = parsed.data;
export type Config = z.infer<typeof envSchema>;

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import routes from './routes';
import healthRoutes from './routes/health.routes';
import { errorHandler } from './middlewares/errorHandler';
import { requestLogger } from './middlewares/requestLogger';
import { globalRateLimiter } from './middlewares/rateLimiter';
import { config } from './config';

const app = express();

// ─── Security Headers ──────────────────────────────────
app.use(helmet());

// ─── CORS ──────────────────────────────────────────────
app.use(
    cors({
        origin: config.CORS_ORIGINS.split(','),
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-API-Key', 'Idempotency-Key'],
    })
);

// ─── JSON serialization ────────────────────────────────
// JournalEntry.seq is a BigInt (a monotonic ordering key), and JSON.stringify
// throws on BigInt rather than serializing it — which turned a report query into
// a 500. Numbers are safe here: the values are autoincrement counters, far below
// Number.MAX_SAFE_INTEGER. Registered app-wide so no future BigInt column can
// break a route the same way.
app.set('json replacer', (_key: string, value: unknown) =>
    typeof value === 'bigint' ? Number(value) : value,
);

// ─── Body Parsing ─────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// ─── Global Middleware ─────────────────────────────────
app.use(requestLogger);
// ─── Health Routes (NO rate limit) ───
// Authenticated JSON must never be stored by a shared cache — a CDN, a
// corporate proxy, the rewrite in front of the API — or one user's
// notifications could be served to another. `no-cache` still lets the browser
// keep its own copy and revalidate it by ETag, which is where the 304s on
// polled endpoints come from. A route needing different caching sets its own
// header, which overrides this.
app.use('/api/v1', (_req, res, next) => {
    res.set('Cache-Control', 'private, no-cache');
    next();
});

app.use('/api/v1', healthRoutes);

// ─── Other API Routes ───
// Mounted from config rather than a literal: absolute links the API builds to
// its own endpoints (an invoice logo URL that goes into a customer's email)
// are derived from API_PREFIX, and the two must not be able to drift apart.
app.use(config.API_PREFIX, globalRateLimiter, routes);

// ─── 404 Handler ───────────────────────────────────────
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: `Route ${req.method} ${req.path} not found`,
    });
});

// ─── Global Error Handler ──────────────────────────────
app.use(errorHandler);

export default app;

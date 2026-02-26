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
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
    })
);

// ─── Body Parsing ─────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// ─── Global Middleware ─────────────────────────────────
app.use(requestLogger);
// ─── Health Routes (NO rate limit) ───
app.use('/api/v1', healthRoutes);

// ─── Other API Routes ───
app.use('/api/v1', globalRateLimiter, routes);

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

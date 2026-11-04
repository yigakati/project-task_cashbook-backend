import { Router } from 'express';
import { container } from 'tsyringe';
import { IntegrationController } from './integration.controller';
import { validate } from '../../middlewares/validate';
import {
    authenticateApiKey,
    requireApiKeyScope,
    requireApiKeyBookAccess,
} from '../../middlewares/authenticateApiKey';
import { integrateEntrySchema, integrateBatchSchema } from './integration.dto';
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';

const router = Router();
const ctrl = container.resolve(IntegrationController);

/**
 * Stricter rate limiting for integration endpoints.
 *
 * 300 req / 15 min per authenticated API key. This is intentionally separate from
 * the global session-based limiter so bursty integrations don't collide with
 * normal UI traffic, and so we can tune each independently.
 */
const integrationLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    keyGenerator: (req) => {
        // Authentication runs first, so never retain or key a limiter on the
        // raw secret (including a prefix of it).
        return (req as any).apiKey?.id ?? ipKeyGenerator(req.ip ?? 'unknown');
    },
    message: {
        success: false,
        error: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests from this API key. Try again in 15 minutes.',
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// All integration routes require a valid API key
router.use(authenticateApiKey() as any);
router.use(integrationLimiter);

// ─── Entry Submission ──────────────────────────────────

/**
 * POST /api/v1/integrate/entries
 *
 * Record a single entry in a cashbook from an external system.
 *
 * Headers:
 *   X-API-Key: ick_live_<key>
 *
 * Body:
 *   {
 *     "bookRef": "CB-ABCD1234",
 *     "type": "INCOME" | "EXPENSE",
 *     "amount": "1500.00",
 *     "description": "Payment from customer",
 *     "entryDate": "2026-08-18T14:30:00Z",   // optional, defaults to now
 *     "externalRef": "order-7890",            // optional, for idempotency
 *     "categoryId": "<uuid>",                 // optional
 *     "contactId": "<uuid>",                  // optional
 *     "paymentModeId": "<uuid>"               // optional
 *   }
 */
router.post(
    '/entries',
    requireApiKeyScope('WRITE_ENTRIES') as any,
    validate(integrateEntrySchema),
    requireApiKeyBookAccess() as any,
    ctrl.submitEntry.bind(ctrl) as any,
);

/**
 * POST /api/v1/integrate/entries/batch
 *
 * Record up to 100 entries in a single request.
 * All entries must share the same bookRef.
 *
 * Body:
 *   {
 *     "entries": [ ...array of entry objects (same shape as single entry) ]
 *   }
 */
router.post(
    '/entries/batch',
    requireApiKeyScope('WRITE_ENTRIES') as any,
    validate(integrateBatchSchema),
    // Use first entry's bookRef for book access check
    (req, _res, next) => {
        if (Array.isArray(req.body.entries) && req.body.entries.length > 0) {
            req.body.bookRef = req.body.entries[0].bookRef;
        }
        next();
    },
    requireApiKeyBookAccess() as any,
    ctrl.submitBatch.bind(ctrl) as any,
);

/**
 * GET /api/v1/integrate/book/:bookRef
 *
 * Read the summary (name, currency, balance) for a cashbook.
 * Requires READ_ENTRIES scope.
 */
router.get(
    '/book/:bookRef',
    requireApiKeyScope('READ_ENTRIES') as any,
    requireApiKeyBookAccess() as any,
    ctrl.getBookSummary.bind(ctrl) as any,
);

export default router;

/**
 * Contract tests for the idempotency middleware.
 *
 * Mounted on a minimal Express app so the middleware's behaviour is tested
 * directly: claim, replay, in-progress conflict, body-mismatch rejection, and
 * claim release on failure.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import { randomUUID } from 'node:crypto';
import { resetDatabase, testPrisma } from '../test/setup';
import { idempotency } from './idempotency';

// The middleware reaches for the app-wide client; point it at the test database.
vi.mock('../config/database', async () => {
    const { testPrisma: client } = await import('../test/setup');
    return { getPrismaClient: () => client };
});

const ENDPOINT = 'POST /test/things';
const WORKSPACE_ID = randomUUID();
const USER_ID = randomUUID();

/** A person-scoped endpoint: authenticated, but a member of no workspace —
 *  the shape of POST /peer-links/:peerLinkId/accept. */
function buildUnscopedApp(handler: express.RequestHandler) {
    const app = express();
    app.use(express.json());
    app.post(
        '/test/things',
        (req, _res, next) => {
            (req as never as { user: unknown }).user = { userId: USER_ID };
            next();
        },
        idempotency(ENDPOINT) as express.RequestHandler,
        handler,
    );
    app.use((err: { statusCode?: number; message: string; code?: string }, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
        res.status(err.statusCode ?? 500).json({ success: false, message: err.message, code: err.code });
    });
    return app;
}

function buildApp(handler: express.RequestHandler, mode: 'warn' | 'required' = 'warn') {
    const app = express();
    app.use(express.json());
    app.post(
        '/test/things',
        (req, _res, next) => {
            (req as never as { user: unknown }).user = { userId: USER_ID };
            (req as never as { workspaceId: string }).workspaceId = WORKSPACE_ID;
            next();
        },
        idempotency(ENDPOINT, mode) as express.RequestHandler,
        handler,
    );
    // Minimal error handler mirroring the app's shape.
    app.use((err: { statusCode?: number; message: string; code?: string }, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
        res.status(err.statusCode ?? 500).json({ success: false, message: err.message, code: err.code });
    });
    return app;
}

describe('idempotency middleware', () => {
    beforeEach(async () => {
        await resetDatabase();
    });

    it('executes the handler once and replays the stored response on retry', async () => {
        const handler = vi.fn((_req: express.Request, res: express.Response) => {
            res.status(201).json({ success: true, id: 'created-1' });
        });
        const app = buildApp(handler);
        const key = randomUUID();

        const first = await request(app)
            .post('/test/things')
            .set('Idempotency-Key', key)
            .send({ amount: '100' });

        expect(first.status).toBe(201);
        expect(first.body.id).toBe('created-1');
        expect(first.headers['idempotent-replay']).toBeUndefined();

        const second = await request(app)
            .post('/test/things')
            .set('Idempotency-Key', key)
            .send({ amount: '100' });

        expect(second.status).toBe(201);
        expect(second.body.id).toBe('created-1');
        expect(second.headers['idempotent-replay']).toBe('true');

        // The handler must not have run a second time.
        expect(handler).toHaveBeenCalledTimes(1);
    });

    it('replays regardless of key order in the request body', async () => {
        const handler = vi.fn((_req: express.Request, res: express.Response) => {
            res.status(201).json({ success: true });
        });
        const app = buildApp(handler);
        const key = randomUUID();

        await request(app)
            .post('/test/things')
            .set('Idempotency-Key', key)
            .send({ amount: '100', description: 'x' });

        const second = await request(app)
            .post('/test/things')
            .set('Idempotency-Key', key)
            .send({ description: 'x', amount: '100' });

        expect(second.status).toBe(201);
        expect(handler).toHaveBeenCalledTimes(1);
    });

    it('rejects the same key used with a different body', async () => {
        const app = buildApp((_req, res) => {
            res.status(201).json({ success: true });
        });
        const key = randomUUID();

        await request(app).post('/test/things').set('Idempotency-Key', key).send({ amount: '100' });

        const conflicting = await request(app)
            .post('/test/things')
            .set('Idempotency-Key', key)
            .send({ amount: '999' });

        expect(conflicting.status).toBe(422);
        expect(conflicting.body.code).toBe('IDEMPOTENCY_KEY_REUSE');
    });

    it('releases the claim when the handler fails, so a genuine retry can proceed', async () => {
        let attempt = 0;
        const app = buildApp((_req, res) => {
            attempt += 1;
            if (attempt === 1) {
                res.status(500).json({ success: false, message: 'boom' });
                return;
            }
            res.status(201).json({ success: true, attempt });
        });
        const key = randomUUID();

        const failed = await request(app)
            .post('/test/things')
            .set('Idempotency-Key', key)
            .send({ amount: '100' });
        expect(failed.status).toBe(500);

        const retried = await request(app)
            .post('/test/things')
            .set('Idempotency-Key', key)
            .send({ amount: '100' });

        expect(retried.status).toBe(201);
        expect(retried.body.attempt).toBe(2);
    });

    it('settles its record without a workspace scope (person-scoped endpoints)', async () => {
        // Regression: peer link acceptance runs with no workspace on the
        // request, and the settle-by-compound-key update crashed with
        // "Argument workspaceId must not be null", leaving the record
        // IN_PROGRESS forever.
        const handler = vi.fn((_req: express.Request, res: express.Response) => {
            res.status(200).json({ success: true, accepted: true });
        });
        const app = buildUnscopedApp(handler);
        const key = randomUUID();

        const response = await request(app)
            .post('/test/things')
            .set('Idempotency-Key', key)
            .send({ cashbookId: 'some-book' });

        expect(response.status).toBe(200);
        expect(response.body.accepted).toBe(true);

        // The settle happens just before the response flushes; give it a beat,
        // then the record must be COMPLETED — not stuck IN_PROGRESS.
        await new Promise((r) => setTimeout(r, 150));
        const record = await testPrisma.idempotencyRecord.findFirst({
            where: { endpoint: ENDPOINT, key },
        });
        expect(record).not.toBeNull();
        expect(record!.state).toBe('COMPLETED');
        expect(record!.workspaceId).toBeNull();
        expect(handler).toHaveBeenCalledTimes(1);
    });

    it('collapses concurrent requests with the same key to a single execution', async () => {
        const handler = vi.fn(async (_req: express.Request, res: express.Response) => {
            await new Promise((r) => setTimeout(r, 60));
            res.status(201).json({ success: true });
        });
        const app = buildApp(handler as express.RequestHandler);
        const key = randomUUID();

        const results = await Promise.all([
            request(app).post('/test/things').set('Idempotency-Key', key).send({ amount: '100' }),
            request(app).post('/test/things').set('Idempotency-Key', key).send({ amount: '100' }),
        ]);

        const statuses = results.map((r) => r.status).sort();
        // One wins; the other is told the original is still running.
        expect(statuses).toEqual([201, 409]);
        expect(handler).toHaveBeenCalledTimes(1);
    });

    it('allows requests without a key in warn mode but rejects them in required mode', async () => {
        const warnApp = buildApp((_req, res) => {
            res.status(201).json({ success: true });
        }, 'warn');
        const warned = await request(warnApp).post('/test/things').send({ amount: '100' });
        expect(warned.status).toBe(201);

        const strictApp = buildApp((_req, res) => {
            res.status(201).json({ success: true });
        }, 'required');
        const rejected = await request(strictApp).post('/test/things').send({ amount: '100' });
        expect(rejected.status).toBe(400);
        expect(rejected.body.code).toBe('IDEMPOTENCY_KEY_REQUIRED');
    });

    it('rejects a non-UUID key', async () => {
        const app = buildApp((_req, res) => {
            res.status(201).json({ success: true });
        });
        const response = await request(app)
            .post('/test/things')
            .set('Idempotency-Key', 'not-a-uuid')
            .send({ amount: '100' });

        expect(response.status).toBe(400);
        expect(response.body.code).toBe('IDEMPOTENCY_KEY_INVALID');
    });

    it('keeps completed records for replay and marks them COMPLETED', async () => {
        const app = buildApp((_req, res) => {
            res.status(201).json({ success: true });
        });
        const key = randomUUID();

        await request(app).post('/test/things').set('Idempotency-Key', key).send({ amount: '100' });

        const record = await testPrisma.idempotencyRecord.findFirstOrThrow({ where: { key } });
        expect(record.state).toBe('COMPLETED');
        expect(record.responseStatus).toBe(201);
        expect(record.expiresAt.getTime()).toBeGreaterThan(Date.now());
    });
});

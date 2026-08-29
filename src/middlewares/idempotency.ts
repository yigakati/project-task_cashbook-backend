/**
 * Idempotency for financial writes.
 *
 * A client that times out and retries must not create a second entry. This
 * middleware claims a record keyed by (workspace, endpoint, Idempotency-Key)
 * before the handler runs, and stores the response when it finishes. A retry
 * with the same key replays the stored response instead of re-executing.
 *
 * This is the HTTP layer. The database layer — a unique posting key per journal
 * entry — is the backstop that holds even when this middleware is bypassed.
 *
 * Mode:
 *   'warn'     log when the header is missing, but allow the request (rollout)
 *   'required' reject requests without the header
 */
import { Response, NextFunction } from 'express';
import { createHash } from 'node:crypto';
import { AppError, ConflictError } from '../core/errors/AppError';
import { AuthenticatedRequest } from '../core/types';
import { getPrismaClient } from '../config/database';
import { logger } from '../utils/logger';

const RETENTION_HOURS = 24;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type IdempotencyMode = 'warn' | 'required';

/** Stable hash of the request body: key order must not change the digest. */
function hashBody(body: unknown): string {
    const canonical = JSON.stringify(canonicalize(body));
    return createHash('sha256').update(canonical).digest('hex');
}

function canonicalize(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(canonicalize);
    if (value && typeof value === 'object') {
        return Object.fromEntries(
            Object.entries(value as Record<string, unknown>)
                .filter(([, v]) => v !== undefined)
                .sort(([a], [b]) => a.localeCompare(b))
                .map(([k, v]) => [k, canonicalize(v)]),
        );
    }
    return value;
}

/**
 * @param endpoint Route template, e.g. 'POST /entries/cashbook/:cashbookId'.
 *                 Must be a constant, not the resolved URL, so the same logical
 *                 operation shares a namespace.
 */
export function idempotency(endpoint: string, mode: IdempotencyMode = 'warn') {
    return async function idempotencyMiddleware(
        req: AuthenticatedRequest,
        res: Response,
        next: NextFunction,
    ): Promise<void> {
        const key = req.header('Idempotency-Key');
        const userId = req.user?.userId;

        if (!key) {
            if (mode === 'required') {
                next(
                    new AppError(
                        'Idempotency-Key header is required for this operation.',
                        400,
                        'IDEMPOTENCY_KEY_REQUIRED',
                    ),
                );
                return;
            }
            logger.warn('Financial write without Idempotency-Key', { endpoint, userId });
            next();
            return;
        }

        if (!UUID_RE.test(key)) {
            next(
                new AppError(
                    'Idempotency-Key must be a UUID.',
                    400,
                    'IDEMPOTENCY_KEY_INVALID',
                ),
            );
            return;
        }

        if (!userId) {
            next(new AppError('Authentication required', 401, 'UNAUTHENTICATED'));
            return;
        }

        const prisma = getPrismaClient();
        // Express 5 types route params as string | string[]; only a scalar is meaningful here.
        const paramWorkspaceId = Array.isArray(req.params.workspaceId)
            ? req.params.workspaceId[0]
            : req.params.workspaceId;
        const workspaceId: string | null =
            (req as { workspaceId?: string }).workspaceId ??
            (req as { workspace?: { id: string } }).workspace?.id ??
            (req as { cashbook?: { workspaceId: string } }).cashbook?.workspaceId ??
            paramWorkspaceId ??
            null;
        const requestHash = hashBody(req.body);

        // Claim. The unique index makes this atomic: exactly one concurrent
        // request wins and runs the handler.
        let claimedId: string | null = null;
        try {
            const claim = await prisma.idempotencyRecord.create({
                data: {
                    workspaceId,
                    userId,
                    key,
                    endpoint,
                    requestHash,
                    state: 'IN_PROGRESS',
                    expiresAt: new Date(Date.now() + RETENTION_HOURS * 3600_000),
                },
            });
            claimedId = claim.id;
        } catch (error) {
            const code = (error as { code?: string }).code;
            if (code !== 'P2002') {
                next(error as Error);
                return;
            }
        }

        if (!claimedId) {
            // Person-scoped endpoints (no workspace in scope, e.g. peer link
            // acceptance) claim with workspaceId NULL, which Postgres treats as
            // distinct in the unique index — their claims never collide, so a
            // P2002 here implies a workspace-scoped key. findUnique's compound
            // key cannot carry NULL; findFirst with IS NULL covers the swept
            // edge just in case a record exists.
            const existing = workspaceId
                ? await prisma.idempotencyRecord.findUnique({
                    where: { workspaceId_endpoint_key: { workspaceId, endpoint, key } },
                })
                : await prisma.idempotencyRecord.findFirst({
                    where: { workspaceId: null, endpoint, key },
                    orderBy: { claimedAt: 'asc' },
                });

            if (!existing) {
                // Swept between the failed insert and this read; treat as fresh.
                next();
                return;
            }

            if (existing.requestHash !== requestHash) {
                next(
                    new AppError(
                        'This Idempotency-Key was already used with a different request body.',
                        422,
                        'IDEMPOTENCY_KEY_REUSE',
                    ),
                );
                return;
            }

            if (existing.state === 'COMPLETED') {
                res.setHeader('Idempotent-Replay', 'true');
                res.status(existing.responseStatus ?? 200).json(existing.responseBody);
                return;
            }

            // Still running. The client should retry rather than get a duplicate.
            res.setHeader('Retry-After', '1');
            next(
                new ConflictError(
                    'A request with this Idempotency-Key is still in progress. Retry shortly.',
                ),
            );
            return;
        }

        // We own the record. Capture the response so a retry can replay it.
        //
        // The record is settled BEFORE the response is flushed. If it were
        // fire-and-forget, a crash in that window would leave the row
        // IN_PROGRESS and every retry would 409 until it expired — the exact
        // failure this middleware exists to prevent.
        const originalJson = res.json.bind(res);
        res.json = (body: unknown) => {
            const status = res.statusCode;
            void (async () => {
                try {
                    if (status >= 200 && status < 300) {
                        // Settle by the record's own id rather than the
                        // (workspaceId, endpoint, key) compound: the compound
                        // requires a non-null workspaceId, and person-scoped
                        // endpoints — peer link acceptance and settlement
                        // decisions — have none.
                        await prisma.idempotencyRecord.update({
                            where: { id: claimedId! },
                            data: {
                                state: 'COMPLETED',
                                responseStatus: status,
                                responseBody: body as never,
                                completedAt: new Date(),
                            },
                        });
                    } else {
                        // Failed request: drop the claim so the client can genuinely retry.
                        await prisma.idempotencyRecord.deleteMany({
                            where: { id: claimedId!, state: 'IN_PROGRESS' },
                        });
                    }
                } catch (error) {
                    logger.error('Failed to settle idempotency record', {
                        endpoint,
                        key,
                        error: (error as Error).message,
                    });
                } finally {
                    originalJson(body);
                }
            })();
            return res;
        };

        next();
    };
}

/** Delete expired records. Safe to run concurrently. */
export async function sweepIdempotencyRecords(): Promise<number> {
    const { count } = await getPrismaClient().idempotencyRecord.deleteMany({
        where: { expiresAt: { lt: new Date() } },
    });
    return count;
}

import { injectable, inject } from 'tsyringe';
import {
    Prisma,
    PrismaClient,
    StorageRequestStatus,
    NotificationType,
    NotificationEntityType,
} from '@prisma/client';
import { StorageService } from '../files/storage.service';
import { invoiceLogoUrl } from '../invoicing/invoice-logo';
import {
    AppError,
    ConflictError,
    NotFoundError,
    StorageQuotaExceededError,
} from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';
import { NotificationsService } from '../notifications/notifications.service';
import { logger } from '../../utils/logger';
import { formatBytes } from '../../utils/format-bytes';

type DbClient = PrismaClient | Prisma.TransactionClient;

export const GIB = 1024 ** 3;
/** What every workspace gets until a superadmin says otherwise. */
export const DEFAULT_STORAGE_QUOTA_BYTES = GIB;
export const DEFAULT_QUOTA_SETTING_KEY = 'default_storage_quota_bytes';
/** A sanity ceiling on what can be granted, so a typo cannot hand out a petabyte. */
export const MAX_STORAGE_QUOTA_BYTES = 1024 * GIB;

export const gbToBytes = (gb: number): number => Math.round(gb * GIB);

export type StorageFileKind = 'entry' | 'task' | 'report' | 'claim';

const KIND_LABELS: Record<StorageFileKind | 'logo', string> = {
    logo: 'Invoice logo',
    entry: 'Entry attachments',
    task: 'Task files',
    report: 'Task report files',
    claim: 'Expense claim receipts',
};

const KIND_FILTERS: Record<StorageFileKind, Prisma.AttachmentWhereInput> = {
    entry: { cashbookId: { not: null } },
    task: { taskId: { not: null } },
    report: { taskReportId: { not: null } },
    claim: { expenseClaimId: { not: null } },
};

// ─── The rules every upload path goes through ──────────────────────────────

/** The platform-wide default, falling back to 1 GB if it was never set. */
export async function getDefaultQuotaBytes(db: DbClient): Promise<number> {
    const row = await db.platformSetting.findUnique({
        where: { key: DEFAULT_QUOTA_SETTING_KEY },
        select: { value: true },
    });
    const value = Number(row?.value);
    return Number.isFinite(value) && value > 0 ? value : DEFAULT_STORAGE_QUOTA_BYTES;
}

export async function getStorageLimitBytes(db: DbClient, workspaceId: string): Promise<number> {
    const workspace = await db.workspace.findUnique({
        where: { id: workspaceId },
        select: { storageQuotaBytes: true },
    });
    if (!workspace) throw new NotFoundError('Workspace');
    return workspace.storageQuotaBytes != null
        ? Number(workspace.storageQuotaBytes)
        : getDefaultQuotaBytes(db);
}

/**
 * Bytes this workspace is using, counted from the files that already exist.
 *
 * Deleted attachments stop counting the moment they are deleted. They are
 * kept on disk for the audit trail, but that is the platform's choice, not
 * something the workspace should pay for.
 */
export async function getStorageUsedBytes(db: DbClient, workspaceId: string): Promise<number> {
    const [attachments, settings] = await Promise.all([
        db.attachment.aggregate({
            where: { workspaceId, isDeleted: false },
            _sum: { fileSize: true },
        }),
        db.invoiceSettings.findUnique({ where: { workspaceId }, select: { logoSize: true } }),
    ]);
    return (attachments._sum.fileSize ?? 0) + (settings?.logoSize ?? 0);
}

/**
 * Refuse a file that would take the workspace past its allowance.
 *
 * `freedBytes` covers replacements: swapping a logo frees the old one, so
 * only the difference has to fit.
 */
export async function assertStorageAvailable(
    db: DbClient,
    workspaceId: string,
    incomingBytes: number,
    freedBytes = 0,
): Promise<void> {
    const [used, limit] = await Promise.all([
        getStorageUsedBytes(db, workspaceId),
        getStorageLimitBytes(db, workspaceId),
    ]);
    if (used - freedBytes + incomingBytes > limit) {
        throw new StorageQuotaExceededError(used, limit, incomingBytes);
    }
}

/**
 * The cheap check before any work is done: a workspace already at its limit
 * cannot take anything, whatever the file compresses down to.
 */
export async function assertStorageNotFull(
    db: DbClient,
    workspaceId: string,
    incomingBytes: number,
): Promise<void> {
    const [used, limit] = await Promise.all([
        getStorageUsedBytes(db, workspaceId),
        getStorageLimitBytes(db, workspaceId),
    ]);
    if (used >= limit) throw new StorageQuotaExceededError(used, limit, incomingBytes);
}

/**
 * Serialise storage decisions for one workspace for the rest of a transaction.
 *
 * Without it two uploads arriving together each see room for themselves,
 * both commit, and the workspace ends up over its limit.
 */
export async function lockWorkspaceStorage(tx: Prisma.TransactionClient, workspaceId: string) {
    await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(${`storage:${workspaceId}`}, 0))`;
}

// ─── The service behind the settings page and the platform page ────────────

@injectable()
export class StorageQuotaService {
    constructor(
        private storage: StorageService,
        @inject('PrismaClient') private prisma: PrismaClient,
    ) { }

    async getOverview(workspaceId: string) {
        await this.backfillLogoSize(workspaceId);

        const live = { workspaceId, isDeleted: false };
        const [limitBytes, workspace, settings, pendingRequest, lastDecision, ...kindTotals] = await Promise.all([
            getStorageLimitBytes(this.prisma, workspaceId),
            this.prisma.workspace.findUnique({ where: { id: workspaceId }, select: { storageQuotaBytes: true } }),
            this.prisma.invoiceSettings.findUnique({
                where: { workspaceId },
                select: { logoKey: true, logoSize: true },
            }),
            this.prisma.storageQuotaRequest.findFirst({
                where: { workspaceId, status: StorageRequestStatus.PENDING },
                select: { id: true, requestedBytes: true, reason: true, createdAt: true },
            }),
            this.prisma.storageQuotaRequest.findFirst({
                where: {
                    workspaceId,
                    status: { in: [StorageRequestStatus.APPROVED, StorageRequestStatus.DECLINED] },
                },
                orderBy: { decidedAt: 'desc' },
                select: {
                    id: true, status: true, requestedBytes: true, grantedBytes: true,
                    decisionNote: true, decidedAt: true,
                },
            }),
            ...(Object.keys(KIND_FILTERS) as StorageFileKind[]).map((kind) =>
                this.prisma.attachment.aggregate({
                    where: { ...live, ...KIND_FILTERS[kind] },
                    _sum: { fileSize: true },
                    _count: { _all: true },
                }).then((r) => ({ kind, bytes: r._sum.fileSize ?? 0, count: r._count._all })),
            ),
        ]);

        const logoBytes = settings?.logoSize ?? 0;
        const breakdown = [
            { kind: 'logo' as const, label: KIND_LABELS.logo, bytes: logoBytes, count: settings?.logoKey ? 1 : 0 },
            ...kindTotals.map((t) => ({ ...t, label: KIND_LABELS[t.kind] })),
        ];
        const usedBytes = breakdown.reduce((sum, b) => sum + b.bytes, 0);

        return {
            usedBytes,
            limitBytes,
            remainingBytes: Math.max(0, limitBytes - usedBytes),
            percentUsed: limitBytes > 0 ? Math.min(100, Math.round((usedBytes / limitBytes) * 1000) / 10) : 100,
            isDefaultLimit: workspace?.storageQuotaBytes == null,
            breakdown,
            logo: settings?.logoKey
                ? { url: invoiceLogoUrl(settings.logoKey), bytes: logoBytes }
                : null,
            pendingRequest: pendingRequest
                ? { ...pendingRequest, requestedBytes: Number(pendingRequest.requestedBytes) }
                : null,
            lastDecision: lastDecision
                ? {
                    ...lastDecision,
                    requestedBytes: Number(lastDecision.requestedBytes),
                    grantedBytes: lastDecision.grantedBytes != null ? Number(lastDecision.grantedBytes) : null,
                }
                : null,
        };
    }

    async listFiles(
        workspaceId: string,
        params: { page: number; limit: number; kind: StorageFileKind | 'all'; sort: 'size' | 'recent' },
    ) {
        const where: Prisma.AttachmentWhereInput = {
            workspaceId,
            isDeleted: false,
            ...(params.kind !== 'all' ? KIND_FILTERS[params.kind] : {}),
        };

        const [total, rows] = await Promise.all([
            this.prisma.attachment.count({ where }),
            this.prisma.attachment.findMany({
                where,
                // Largest first by default: the storage view is where someone
                // goes to free space, and that is the order that helps.
                orderBy: params.sort === 'recent'
                    ? [{ createdAt: 'desc' }]
                    : [{ fileSize: 'desc' }, { createdAt: 'desc' }],
                skip: (params.page - 1) * params.limit,
                take: params.limit,
                select: {
                    id: true, fileName: true, fileSize: true, mimeType: true, createdAt: true,
                    cashbookId: true, taskId: true, taskReportId: true, expenseClaimId: true,
                    uploadedById: true,
                    cashbook: { select: { name: true } },
                    entry: { select: { description: true } },
                    task: { select: { title: true } },
                },
            }),
        ]);

        const uploaderIds = [...new Set(rows.map((r) => r.uploadedById))];
        const uploaders = await this.prisma.user.findMany({
            where: { id: { in: uploaderIds } },
            select: { id: true, firstName: true, lastName: true },
        });
        const byId = new Map(uploaders.map((u) => [u.id, u]));

        const data = rows.map((r) => {
            const kind: StorageFileKind = r.cashbookId ? 'entry'
                : r.taskId ? 'task'
                    : r.taskReportId ? 'report'
                        : 'claim';
            const context = kind === 'entry'
                ? [r.cashbook?.name, r.entry?.description].filter(Boolean).join(' · ') || null
                : kind === 'task' ? r.task?.title ?? null
                    : null;
            const uploader = byId.get(r.uploadedById);
            return {
                id: r.id,
                fileName: r.fileName,
                fileSize: r.fileSize,
                mimeType: r.mimeType,
                createdAt: r.createdAt,
                kind,
                kindLabel: KIND_LABELS[kind],
                context,
                uploadedBy: uploader ? { firstName: uploader.firstName, lastName: uploader.lastName } : null,
            };
        });

        return { data, total, page: params.page, limit: params.limit };
    }

    async createRequest(
        workspaceId: string,
        userId: string,
        dto: { requestedGb: number; reason?: string },
    ) {
        const requestedBytes = gbToBytes(dto.requestedGb);
        const limit = await getStorageLimitBytes(this.prisma, workspaceId);

        if (requestedBytes <= limit) {
            throw new AppError(
                `Ask for more than the current ${formatBytes(limit)} allowance.`,
                400,
                'REQUEST_NOT_AN_INCREASE',
            );
        }
        if (requestedBytes > MAX_STORAGE_QUOTA_BYTES) {
            throw new AppError(
                `The most that can be requested is ${formatBytes(MAX_STORAGE_QUOTA_BYTES)}.`,
                400,
                'REQUEST_TOO_LARGE',
            );
        }

        let request;
        try {
            request = await this.prisma.storageQuotaRequest.create({
                data: {
                    workspaceId,
                    requestedById: userId,
                    requestedBytes: BigInt(requestedBytes),
                    reason: dto.reason?.trim() || null,
                },
            });
        } catch (error) {
            // The partial unique index on (workspace_id) WHERE status =
            // 'PENDING' is what actually prevents a second one.
            if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
                throw new ConflictError('This workspace already has a storage request waiting for review.');
            }
            throw error;
        }

        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.STORAGE_QUOTA_REQUESTED,
                resource: 'storage_quota_request',
                resourceId: request.id,
                details: { requestedBytes, currentLimitBytes: limit } as any,
            },
        });

        return { ...request, requestedBytes, grantedBytes: null };
    }

    async cancelRequest(workspaceId: string, requestId: string, userId: string) {
        const { count } = await this.prisma.storageQuotaRequest.updateMany({
            where: { id: requestId, workspaceId, status: StorageRequestStatus.PENDING },
            data: { status: StorageRequestStatus.CANCELLED },
        });
        if (count === 0) throw new NotFoundError('Pending storage request');

        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.STORAGE_QUOTA_REQUEST_CANCELLED,
                resource: 'storage_quota_request',
                resourceId: requestId,
            },
        });
        return { id: requestId, status: StorageRequestStatus.CANCELLED };
    }

    // ─── Superadmin ────────────────────────────────────

    async listRequests(params: { status?: StorageRequestStatus; page: number; limit: number }) {
        const where: Prisma.StorageQuotaRequestWhereInput = params.status ? { status: params.status } : {};
        const [total, rows] = await Promise.all([
            this.prisma.storageQuotaRequest.count({ where }),
            this.prisma.storageQuotaRequest.findMany({
                where,
                orderBy: { createdAt: 'desc' },
                skip: (params.page - 1) * params.limit,
                take: params.limit,
                include: {
                    workspace: {
                        select: {
                            id: true, name: true, type: true,
                            owner: { select: { email: true, firstName: true, lastName: true } },
                        },
                    },
                    requestedBy: { select: { email: true, firstName: true, lastName: true } },
                    decidedBy: { select: { firstName: true, lastName: true } },
                },
            }),
        ]);

        // What each workspace is using right now, so the decision is made
        // against real numbers rather than just the ask.
        const workspaceIds = [...new Set(rows.map((r) => r.workspaceId))];
        const usage = new Map(await Promise.all(workspaceIds.map(async (id) => [
            id,
            {
                usedBytes: await getStorageUsedBytes(this.prisma, id),
                limitBytes: await getStorageLimitBytes(this.prisma, id),
            },
        ] as const)));

        const data = rows.map((r) => ({
            ...r,
            requestedBytes: Number(r.requestedBytes),
            grantedBytes: r.grantedBytes != null ? Number(r.grantedBytes) : null,
            usage: usage.get(r.workspaceId) ?? null,
        }));

        return { data, total, page: params.page, limit: params.limit };
    }

    async decideRequest(
        requestId: string,
        actorId: string,
        dto: { approve: boolean; grantedGb?: number; note?: string },
    ) {
        const request = await this.prisma.storageQuotaRequest.findUnique({ where: { id: requestId } });
        if (!request) throw new NotFoundError('Storage request');
        if (request.status !== StorageRequestStatus.PENDING) {
            throw new AppError(`This request is already ${request.status.toLowerCase()}`, 409, 'INVALID_STATUS');
        }

        const grantedBytes = dto.approve
            ? (dto.grantedGb != null ? gbToBytes(dto.grantedGb) : Number(request.requestedBytes))
            : null;
        if (grantedBytes != null && (grantedBytes <= 0 || grantedBytes > MAX_STORAGE_QUOTA_BYTES)) {
            throw new AppError(
                `Grant between 1 byte and ${formatBytes(MAX_STORAGE_QUOTA_BYTES)}.`,
                400,
                'INVALID_GRANT',
            );
        }

        const status = dto.approve ? StorageRequestStatus.APPROVED : StorageRequestStatus.DECLINED;

        await this.prisma.$transaction(async (tx) => {
            // Claim it first: two superadmins deciding at once must not both
            // act, and the loser must learn it lost.
            const claimed = await tx.storageQuotaRequest.updateMany({
                where: { id: requestId, status: StorageRequestStatus.PENDING },
                data: {
                    status,
                    grantedBytes: grantedBytes != null ? BigInt(grantedBytes) : null,
                    decidedById: actorId,
                    decisionNote: dto.note?.trim() || null,
                    decidedAt: new Date(),
                },
            });
            if (claimed.count === 0) {
                throw new AppError('This request was already decided', 409, 'INVALID_STATUS');
            }

            if (grantedBytes != null) {
                await tx.workspace.update({
                    where: { id: request.workspaceId },
                    data: { storageQuotaBytes: BigInt(grantedBytes) },
                });
            }

            await tx.auditLog.create({
                data: {
                    userId: actorId,
                    workspaceId: request.workspaceId,
                    action: dto.approve ? AuditAction.STORAGE_QUOTA_APPROVED : AuditAction.STORAGE_QUOTA_DECLINED,
                    resource: 'storage_quota_request',
                    resourceId: requestId,
                    details: {
                        requestedBytes: Number(request.requestedBytes),
                        grantedBytes,
                        platformAction: AuditAction.ADMIN_WORKSPACE_ACTION,
                    } as any,
                },
            });
        });

        // Only once committed — a notification about a rolled-back decision
        // would be a lie the requester acts on.
        NotificationsService.dispatch({
            type: NotificationType.STORAGE_REQUEST_DECIDED,
            userId: request.requestedById,
            workspaceId: request.workspaceId,
            title: dto.approve ? 'More storage approved' : 'Storage request declined',
            body: dto.approve
                ? `This workspace can now store up to ${formatBytes(grantedBytes!)}.`
                : dto.note?.trim() || 'Your request for more storage was declined.',
            entityType: NotificationEntityType.STORAGE_QUOTA_REQUEST,
            entityId: requestId,
        });

        return { id: requestId, status, grantedBytes };
    }

    /** Every workspace, fullest first — the order a superadmin needs. */
    async listWorkspaceUsage(params: { page: number; limit: number; search?: string }) {
        const search = params.search?.trim();
        const filter = search ? Prisma.sql`AND w.name ILIKE ${`%${search}%`}` : Prisma.empty;
        const offset = (params.page - 1) * params.limit;

        const [rows, countRows, defaultQuota] = await Promise.all([
            this.prisma.$queryRaw<Array<{
                id: string; name: string; type: string; storage_quota_bytes: bigint | null;
                used_bytes: bigint; owner_email: string;
            }>>`
                SELECT w.id, w.name, w.type::text AS type, w.storage_quota_bytes,
                       (COALESCE(a.used, 0) + COALESCE(s.logo_size, 0))::bigint AS used_bytes,
                       u.email AS owner_email
                FROM workspaces w
                JOIN users u ON u.id = w.owner_id
                LEFT JOIN (
                    SELECT workspace_id, SUM(file_size)::bigint AS used
                    FROM attachments
                    WHERE is_deleted = false AND workspace_id IS NOT NULL
                    GROUP BY workspace_id
                ) a ON a.workspace_id = w.id
                LEFT JOIN invoice_settings s ON s.workspace_id = w.id
                WHERE w.is_active = true ${filter}
                ORDER BY used_bytes DESC, w.name ASC
                LIMIT ${params.limit} OFFSET ${offset}`,
            this.prisma.$queryRaw<Array<{ count: bigint }>>`
                SELECT COUNT(*)::bigint AS count FROM workspaces w WHERE w.is_active = true ${filter}`,
            getDefaultQuotaBytes(this.prisma),
        ]);

        const data = rows.map((r) => ({
            id: r.id,
            name: r.name,
            type: r.type,
            ownerEmail: r.owner_email,
            usedBytes: Number(r.used_bytes),
            limitBytes: r.storage_quota_bytes != null ? Number(r.storage_quota_bytes) : defaultQuota,
            isDefaultLimit: r.storage_quota_bytes == null,
        }));

        return { data, total: Number(countRows[0]?.count ?? 0), page: params.page, limit: params.limit };
    }

    /** Set a workspace's allowance directly, or put it back on the default. */
    async setWorkspaceQuota(workspaceId: string, quotaGb: number | null, actorId: string) {
        const bytes = quotaGb == null ? null : gbToBytes(quotaGb);
        if (bytes != null && (bytes <= 0 || bytes > MAX_STORAGE_QUOTA_BYTES)) {
            throw new AppError(`Set between 1 byte and ${formatBytes(MAX_STORAGE_QUOTA_BYTES)}.`, 400, 'INVALID_GRANT');
        }

        const workspace = await this.prisma.workspace.findUnique({ where: { id: workspaceId }, select: { id: true } });
        if (!workspace) throw new NotFoundError('Workspace');

        await this.prisma.workspace.update({
            where: { id: workspaceId },
            data: { storageQuotaBytes: bytes != null ? BigInt(bytes) : null },
        });

        await this.prisma.auditLog.create({
            data: {
                userId: actorId,
                workspaceId,
                action: AuditAction.STORAGE_QUOTA_SET,
                resource: 'workspace',
                resourceId: workspaceId,
                details: { quotaBytes: bytes, platformAction: AuditAction.ADMIN_WORKSPACE_ACTION } as any,
            },
        });

        return {
            workspaceId,
            limitBytes: bytes ?? await getDefaultQuotaBytes(this.prisma),
            isDefaultLimit: bytes == null,
        };
    }

    /**
     * Logos uploaded before sizes were recorded have a key but no size. Read
     * it from the bucket once and keep it, so they count like any other file.
     * Best-effort with a short timeout: a slow bucket must not stall the page.
     */
    private async backfillLogoSize(workspaceId: string) {
        const settings = await this.prisma.invoiceSettings.findUnique({
            where: { workspaceId },
            select: { logoKey: true, logoSize: true },
        });
        if (!settings?.logoKey || settings.logoSize != null) return;

        try {
            const stat = await this.storage.statObject(settings.logoKey);
            if (typeof stat.size === 'number') {
                await this.prisma.invoiceSettings.update({
                    where: { workspaceId },
                    data: { logoSize: stat.size },
                });
            }
        } catch (error) {
            logger.warn('Could not read logo size from storage', {
                workspaceId,
                error: error instanceof Error ? error.message : error,
            });
        }
    }
}

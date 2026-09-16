import { z } from 'zod';

/** Amounts travel as GB (decimals allowed) and are stored as bytes. */
const gb = z.number().positive('Must be more than 0').max(1024, 'At most 1024 GB');

export const requestStorageSchema = z.object({
    /** The total allowance wanted, not an increment. */
    requestedGb: gb,
    reason: z.string().trim().max(500).optional(),
});

export const decideStorageRequestSchema = z.object({
    approve: z.boolean(),
    /** Defaults to what was asked for. */
    grantedGb: gb.optional(),
    note: z.string().trim().max(500).optional(),
});

export const setWorkspaceQuotaSchema = z.object({
    /** Null puts the workspace back on the platform default. */
    quotaGb: gb.nullable(),
});

export const storageFilesQuerySchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
    kind: z.enum(['all', 'entry', 'task', 'report', 'claim']).default('all'),
    sort: z.enum(['size', 'recent']).default('size'),
});

export const storageRequestsQuerySchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(25),
    status: z.enum(['PENDING', 'APPROVED', 'DECLINED', 'CANCELLED']).optional(),
});

export const storageWorkspacesQuerySchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(25),
    search: z.string().trim().max(200).optional(),
});

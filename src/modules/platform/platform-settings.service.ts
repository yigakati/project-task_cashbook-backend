import { injectable, inject } from 'tsyringe';
import { Prisma, PrismaClient } from '@prisma/client';
import { AppError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';
import {
    DEFAULT_QUOTA_SETTING_KEY,
    MAX_STORAGE_QUOTA_BYTES,
    getDefaultQuotaBytes,
} from '../storage/storage-quota.service';
import { formatBytes } from '../../utils/format-bytes';

type DbClient = PrismaClient | Prisma.TransactionClient;

/**
 * Platform-wide switches — true of every workspace at once.
 *
 * Distinct from WorkspaceFeature, which unlocks a module for one organisation.
 * A switch belongs here when granting it to one workspace but not the next
 * would be arbitrary rather than a deliberate decision about that org.
 */
export const PLATFORM_SETTINGS = {
    /**
     * Whether contact details may be typed in by hand anywhere on the platform.
     *
     * Off by default: the intended way to record a counterparty is to invite
     * them, so the details are theirs and stay current. Manual entry is the
     * escape hatch, and it is opened for everyone or for nobody.
     */
    MANUAL_CONTACTS: 'manual_contacts_enabled',
} as const;

export const MANUAL_CONTACTS_MESSAGE =
    'Adding contact details by hand is switched off. Invite the contact instead, so their details come from them.';

/**
 * Read a boolean switch, defaulting to OFF when the row is missing.
 *
 * Absence means off on purpose: a switch that has never been set should not be
 * assumed permissive, and a failed migration should close a feature rather
 * than open one.
 */
export async function isPlatformSettingEnabled(db: DbClient, key: string): Promise<boolean> {
    const row = await db.platformSetting.findUnique({ where: { key }, select: { value: true } });
    return row?.value === true;
}

/** Refuse an action the platform has switched off. */
export async function assertManualContactsEnabled(db: DbClient): Promise<void> {
    if (!(await isPlatformSettingEnabled(db, PLATFORM_SETTINGS.MANUAL_CONTACTS))) {
        throw new AppError(MANUAL_CONTACTS_MESSAGE, 403, 'MANUAL_CONTACTS_DISABLED');
    }
}

@injectable()
export class PlatformSettingsService {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    /** Everything the platform page shows, and the app-wide flags clients read. */
    async getAll() {
        const rows = await this.prisma.platformSetting.findMany({
            select: { key: true, value: true, updatedAt: true },
        });
        const byKey = new Map(rows.map((r) => [r.key, r.value]));

        return {
            manualContactsEnabled: byKey.get(PLATFORM_SETTINGS.MANUAL_CONTACTS) === true,
            /** What every workspace gets unless it has its own allowance. */
            defaultStorageQuotaBytes: await getDefaultQuotaBytes(this.prisma),
            updatedAt: rows.reduce<Date | null>(
                (latest, r) => (!latest || r.updatedAt > latest ? r.updatedAt : latest),
                null,
            ),
        };
    }

    async setManualContacts(enabled: boolean, actorId: string) {
        await this.prisma.platformSetting.upsert({
            where: { key: PLATFORM_SETTINGS.MANUAL_CONTACTS },
            update: { value: enabled, updatedById: actorId },
            create: { key: PLATFORM_SETTINGS.MANUAL_CONTACTS, value: enabled, updatedById: actorId },
        });

        await this.prisma.auditLog.create({
            data: {
                userId: actorId,
                action: enabled
                    ? AuditAction.PLATFORM_SETTING_ENABLED
                    : AuditAction.PLATFORM_SETTING_DISABLED,
                resource: 'platform_setting',
                resourceId: PLATFORM_SETTINGS.MANUAL_CONTACTS,
                details: {
                    key: PLATFORM_SETTINGS.MANUAL_CONTACTS,
                    enabled,
                    platformAction: AuditAction.ADMIN_WORKSPACE_ACTION,
                } as any,
            },
        });

        return this.getAll();
    }

    /** Change the storage every workspace without its own allowance gets. */
    async setDefaultStorageQuota(bytes: number, actorId: string) {
        if (!Number.isFinite(bytes) || bytes <= 0 || bytes > MAX_STORAGE_QUOTA_BYTES) {
            throw new AppError(
                `The default must be between 1 byte and ${formatBytes(MAX_STORAGE_QUOTA_BYTES)}.`,
                400,
                'INVALID_DEFAULT_QUOTA',
            );
        }
        await this.prisma.platformSetting.upsert({
            where: { key: DEFAULT_QUOTA_SETTING_KEY },
            update: { value: bytes, updatedById: actorId },
            create: { key: DEFAULT_QUOTA_SETTING_KEY, value: bytes, updatedById: actorId },
        });
        await this.prisma.auditLog.create({
            data: {
                userId: actorId,
                action: AuditAction.STORAGE_DEFAULT_QUOTA_SET,
                resource: 'platform_setting',
                resourceId: DEFAULT_QUOTA_SETTING_KEY,
                details: { bytes, platformAction: AuditAction.ADMIN_WORKSPACE_ACTION } as any,
            },
        });
        return this.getAll();
    }
}

import { injectable, inject } from 'tsyringe';
import { PrismaClient, Prisma } from '@prisma/client';
import { ensureWorkspaceProfile } from './workspace-profile.helpers';
import { AuditAction } from '../../core/types';
import {
    UpdateWorkspaceProfileDto,
    checkProfileCompleteness,
} from './workspace-profile.dto';

/**
 * A workspace's own identity and billing details.
 *
 * Every workspace has exactly one, created with the workspace (and backfilled
 * for those that predate it), so callers never have to deal with "does this
 * exist yet" — only with whether it has been filled in enough to share.
 */
@injectable()
export class WorkspaceProfileService {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    async getProfile(workspaceId: string) {
        const profile = await this.ensureProfile(workspaceId);
        return {
            ...profile,
            completeness: checkProfileCompleteness(profile),
        };
    }

    async updateProfile(workspaceId: string, userId: string, dto: UpdateWorkspaceProfileDto) {
        await this.ensureProfile(workspaceId);

        // Empty strings from a cleared form field mean "remove this", not
        // "store a blank" — otherwise a blanked email would still read as
        // present to the completeness check.
        const data: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(dto)) {
            if (value === undefined) continue;
            if (typeof value === 'string') {
                const trimmed = value.trim();
                data[key] = trimmed === '' ? null : trimmed;
            } else if (key === 'paymentDetails') {
                data[key] = value === null ? Prisma.DbNull : value;
            } else {
                data[key] = value;
            }
        }

        const updated = await this.prisma.$transaction(async (tx) => {
            const profile = await tx.workspaceProfile.update({
                where: { workspaceId },
                data: data as Prisma.WorkspaceProfileUpdateInput,
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.WORKSPACE_PROFILE_UPDATED,
                    resource: 'workspace_profile',
                    resourceId: profile.id,
                    details: { fields: Object.keys(data) } as any,
                },
            });

            // Everyone holding this workspace as a connected contact sees the
            // change. Imported lazily so the two modules do not import each
            // other — the same shape entries.service uses for peer links.
            const { ContactLinksService } = await import('../contact-links/contact-links.service');
            await ContactLinksService.onProfileUpdated(tx, workspaceId);

            return profile;
        });

        return {
            ...updated,
            completeness: checkProfileCompleteness(updated),
        };
    }

    /**
     * Workspaces created before profiles existed, and any created by a path
     * that predates this, are filled in from what is already known on first
     * read rather than 404-ing at the moment someone tries to accept a
     * request. See ensureWorkspaceProfile for what "already known" covers.
     */
    private ensureProfile(workspaceId: string) {
        return ensureWorkspaceProfile(this.prisma, workspaceId);
    }
}

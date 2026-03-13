import { injectable, inject } from 'tsyringe';
import { PrismaClient, WorkspaceRole } from '@prisma/client';
import crypto from 'crypto';
import { logger } from '../../utils/logger';
import { NotFoundError, AppError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';

export interface PendingInviteData {
    email: string;
    workspaceId: string;
    role?: WorkspaceRole;
    invitedById: string;
}

/**
 * Manages invite flows for users.
 *
 * When a member is invited to a workspace, we store a PendingInvite with a unique token and expiry. 
 * The user can explicitly accept or decline it from their dashboard.
 */
@injectable()
export class InvitesService {
    constructor(
        @inject('PrismaClient') private prisma: PrismaClient,
    ) { }

    /**
     * Create a pending invite for an unregistered email.
     */
    async createPendingInvite(data: PendingInviteData) {
        // Avoid duplicate invites (unique constraint on [workspaceId, email])
        const existing = await this.prisma.pendingInvite.findUnique({
            where: {
                workspaceId_email: {
                    workspaceId: data.workspaceId,
                    email: data.email,
                },
            },
        });

        if (existing) {
            logger.info('Pending invite already exists', { email: data.email, workspaceId: data.workspaceId });
            return existing;
        }

        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

        return this.prisma.pendingInvite.create({
            data: {
                email: data.email,
                workspaceId: data.workspaceId,
                role: data.role ?? WorkspaceRole.MEMBER,
                invitedById: data.invitedById,
                token,
                expiresAt,
            },
        });
    }

    /**
     * Explicitly accept an invitation to join a workspace.
     */
    async acceptInvite(inviteId: string, userId: string, email: string) {
        const invite = await this.prisma.pendingInvite.findUnique({
            where: { id: inviteId },
        });

        if (!invite || invite.email !== email) {
            throw new NotFoundError('Invitation');
        }

        if (invite.expiresAt < new Date()) {
            await this.prisma.pendingInvite.delete({ where: { id: invite.id } });
            throw new AppError('Invitation has expired', 400, 'INVITE_EXPIRED');
        }

        const member = await this.prisma.$transaction(async (tx) => {
            // Check if user is already a member
            const existingMember = await tx.workspaceMember.findUnique({
                where: {
                    workspaceId_userId: {
                        workspaceId: invite.workspaceId,
                        userId,
                    },
                },
            });

            let newMember;
            if (!existingMember) {
                newMember = await tx.workspaceMember.create({
                    data: {
                        workspaceId: invite.workspaceId,
                        userId,
                        role: invite.role,
                    },
                });

                await tx.auditLog.create({
                    data: {
                        userId,
                        workspaceId: invite.workspaceId,
                        action: AuditAction.MEMBER_INVITED,
                        resource: 'workspace_member',
                        resourceId: newMember.id,
                        details: { acceptedInviteId: invite.id } as any,
                    },
                });
            }

            // Remove the invite
            await tx.pendingInvite.delete({
                where: { id: invite.id },
            });

            return existingMember || newMember;
        });

        logger.info(`User ${userId} accepted invite ${inviteId}`);
        return member;
    }

    /**
     * Explicitly decline an invitation.
     */
    async declineInvite(inviteId: string, email: string) {
        const invite = await this.prisma.pendingInvite.findUnique({
            where: { id: inviteId },
        });

        if (!invite || invite.email !== email) {
            throw new NotFoundError('Invitation');
        }

        await this.prisma.$transaction(async (tx) => {
            await tx.pendingInvite.delete({
                where: { id: invite.id },
            });

            await tx.auditLog.create({
                data: {
                    userId: null,
                    workspaceId: invite.workspaceId,
                    action: 'INVITE_DECLINED',
                    resource: 'pending_invite',
                    resourceId: invite.id,
                    details: { declinedByEmail: email } as any,
                },
            });
        });

        logger.info(`Email ${email} declined invite ${inviteId}`);
        return { success: true };
    }

    /**
     * Get all pending invites for an email address.
     */
    async getPendingInvites(email: string) {
        return this.prisma.pendingInvite.findMany({
            where: {
                email,
                expiresAt: { gte: new Date() },
            },
            include: {
                workspace: { select: { id: true, name: true } },
                invitedBy: { select: { id: true, firstName: true, lastName: true, email: true } },
            },
            orderBy: { createdAt: 'desc' },
        });
    }

    /**
     * Get all pending invites for a specific workspace.
     */
    async getWorkspacePendingInvites(workspaceId: string) {
        return this.prisma.pendingInvite.findMany({
            where: {
                workspaceId,
                // Include both valid and expired (or just valid)
                // Assuming admins might want to see all until they are deleted or resolved.
                // Let's filter out trivially expired ones or show them?
                // Let's just show active ones:
                expiresAt: { gte: new Date() },
            },
            include: {
                invitedBy: { select: { id: true, firstName: true, lastName: true, email: true } },
            },
            orderBy: { createdAt: 'desc' },
        });
    }
}

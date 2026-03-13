import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import { MembersRepository } from './members.repository';
import { NotFoundError, ConflictError, AuthorizationError, AppError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';
import { InviteMemberDto, UpdateMemberRoleDto } from './members.dto';
import { InvitesService } from '../invites/invites.service';
import { sendEmail } from '../../config/email';
import { workspaceInviteEmailTemplate, workspaceInviteSignupEmailTemplate } from '../../utils/emailTemplates';
import { config } from '../../config';
import { logger } from '../../utils/logger';

@injectable()
export class MembersService {
    constructor(
        private membersRepository: MembersRepository,
        private invitesService: InvitesService,
        @inject('PrismaClient') private prisma: PrismaClient,
    ) { }

    async getWorkspaceMembers(workspaceId: string) {
        return this.membersRepository.findByWorkspaceId(workspaceId);
    }

    async getPendingInvites(workspaceId: string) {
        return this.invitesService.getWorkspacePendingInvites(workspaceId);
    }

    async inviteMember(workspaceId: string, invitedByUserId: string, dto: InviteMemberDto) {
        // Get workspace details for the email
        const workspace = await this.prisma.workspace.findUnique({
            where: { id: workspaceId },
            select: { name: true, type: true },
        });

        if (!workspace) {
            throw new NotFoundError('Workspace');
        }

        if (workspace.type === 'PERSONAL') {
            throw new AppError(
                'Cannot invite members to a personal workspace. Only business workspaces support invitations.',
                400,
                'INVALID_OPERATION'
            );
        }

        // Get inviter details for the email
        const inviter = await this.prisma.user.findUnique({
            where: { id: invitedByUserId },
            select: { firstName: true, lastName: true },
        });

        const inviterName = inviter
            ? `${inviter.firstName} ${inviter.lastName}`
            : 'A team member';

        // Find user by email
        const targetUser = await this.prisma.user.findUnique({
            where: { email: dto.email },
        });

        if (targetUser) {
            if (!targetUser.isActive) {
                throw new AppError('Cannot invite deactivated user', 400, 'INVALID_OPERATION');
            }

            // Check if already a member
            const existing = await this.membersRepository.findByWorkspaceAndUser(workspaceId, targetUser.id);
            if (existing) {
                throw new ConflictError('User is already a member of this workspace');
            }
        }

        const invite = await this.invitesService.createPendingInvite({
            email: dto.email,
            workspaceId,
            role: dto.role as any,
            invitedById: invitedByUserId,
        });

        await this.prisma.auditLog.create({
            data: {
                userId: invitedByUserId,
                workspaceId,
                action: AuditAction.MEMBER_INVITED,
                resource: 'pending_invite',
                resourceId: invite.id,
                details: { invitedEmail: dto.email, role: dto.role, pending: true } as any,
            },
        });

        if (targetUser) {
            // Send "you have a new invite" email
            sendEmail({
                to: dto.email,
                subject: `You've been invited to ${workspace.name} on ${config.APP_NAME}`,
                html: workspaceInviteEmailTemplate(
                    targetUser.firstName,
                    workspace.name,
                    inviterName,
                    dto.role,
                ),
            }).catch((err) => logger.error('Failed to send workspace invite email', { email: dto.email, err }));
        } else {
            // Send "sign up to join" email
            sendEmail({
                to: dto.email,
                subject: `${inviterName} invited you to join ${workspace.name} on ${config.APP_NAME}`,
                html: workspaceInviteSignupEmailTemplate(
                    dto.email,
                    workspace.name,
                    inviterName,
                    dto.role,
                ),
            }).catch((err) => logger.error('Failed to send workspace invite signup email', { email: dto.email, err }));
        }

        return { invite, status: 'pending' as const };
    }

    async updateMemberRole(
        workspaceId: string,
        targetUserId: string,
        updatedByUserId: string,
        dto: UpdateMemberRoleDto
    ) {
        const membership = await this.membersRepository.findByWorkspaceAndUser(workspaceId, targetUserId);
        if (!membership) {
            throw new NotFoundError('Workspace member');
        }

        if (membership.role === 'OWNER') {
            throw new AppError('Cannot change the role of workspace owner', 400, 'INVALID_OPERATION');
        }

        const oldRole = membership.role;
        const updated = await this.membersRepository.updateRole(workspaceId, targetUserId, dto.role);

        await this.prisma.auditLog.create({
            data: {
                userId: updatedByUserId,
                workspaceId,
                action: AuditAction.MEMBER_ROLE_CHANGED,
                resource: 'workspace_member',
                resourceId: membership.id,
                details: { oldRole, newRole: dto.role, targetUserId } as any,
            },
        });

        return updated;
    }

    async removeMember(workspaceId: string, targetUserId: string, removedByUserId: string) {
        const membership = await this.membersRepository.findByWorkspaceAndUser(workspaceId, targetUserId);
        if (!membership) {
            throw new NotFoundError('Workspace member');
        }

        if (membership.role === 'OWNER') {
            throw new AppError('Cannot remove workspace owner', 400, 'INVALID_OPERATION');
        }

        // Also remove from all cashbooks in this workspace
        await this.prisma.$transaction(async (tx) => {
            // Remove cashbook memberships in this workspace
            const cashbooks = await tx.cashbook.findMany({
                where: { workspaceId },
                select: { id: true },
            });

            if (cashbooks.length > 0) {
                await tx.cashbookMember.deleteMany({
                    where: {
                        userId: targetUserId,
                        cashbookId: { in: cashbooks.map((c) => c.id) },
                    },
                });
            }

            await tx.workspaceMember.delete({
                where: { workspaceId_userId: { workspaceId, userId: targetUserId } },
            });

            await tx.auditLog.create({
                data: {
                    userId: removedByUserId,
                    workspaceId,
                    action: AuditAction.MEMBER_REMOVED,
                    resource: 'workspace_member',
                    details: { targetUserId } as any,
                },
            });
        });
    }
}

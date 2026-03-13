import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import { MembersRepository } from './members.repository';
import { NotFoundError, ConflictError, AuthorizationError, AppError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';
import { InviteMemberDto, UpdateMemberRoleDto, ImportMembersDto } from './members.dto';
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

    async getImportableMembers(targetWorkspaceId: string, currentUserId: string) {
        // 1. Get all members in the current workspace to filter them out
        const targetMembers = await this.prisma.workspaceMember.findMany({
            where: { workspaceId: targetWorkspaceId },
            select: { userId: true },
        });
        const targetUserIds = new Set(targetMembers.map((m) => m.userId));

        // 2. Find all other workspaces where current user is OWNER
        const otherWorkspaces = await this.prisma.workspaceMember.findMany({
            where: {
                userId: currentUserId,
                role: 'OWNER',
                workspaceId: { not: targetWorkspaceId },
            },
            include: {
                workspace: {
                    select: { id: true, name: true, type: true },
                },
            },
        });

        const otherWorkspaceIds = otherWorkspaces.map((m) => m.workspaceId);

        if (otherWorkspaceIds.length === 0) {
            return [];
        }

        // 3. Find members in these other workspaces
        const possibleMembers = await this.prisma.workspaceMember.findMany({
            where: {
                workspaceId: { in: otherWorkspaceIds },
            },
            include: {
                user: {
                    select: { id: true, firstName: true, lastName: true, email: true },
                },
            },
        });

        // 4. Group by workspace, filtering out those already in target
        const importableByWorkspace = otherWorkspaces.map((ow) => {
            const members = possibleMembers
                .filter((pm) => 
                    pm.workspaceId === ow.workspaceId 
                    && pm.userId !== currentUserId 
                    && !targetUserIds.has(pm.userId)
                )
                .map((pm) => ({
                    userId: pm.user.id,
                    firstName: pm.user.firstName,
                    lastName: pm.user.lastName,
                    email: pm.user.email,
                    roleInSource: pm.role,
                }));

            return {
                sourceWorkspaceId: ow.workspace.id,
                sourceWorkspaceName: ow.workspace.name,
                sourceWorkspaceType: ow.workspace.type,
                importableMembers: members,
            };
        });

        // Filter out workspaces that have 0 importable members
        return importableByWorkspace.filter((w) => w.importableMembers.length > 0);
    }

    async importMembers(targetWorkspaceId: string, importingUserId: string, dto: ImportMembersDto) {
        if (targetWorkspaceId === dto.sourceWorkspaceId) {
            throw new AppError('Source and target workspaces must be different', 400, 'INVALID_OPERATION');
        }

        const sourceMembership = await this.prisma.workspaceMember.findUnique({
            where: {
                workspaceId_userId: {
                    workspaceId: dto.sourceWorkspaceId,
                    userId: importingUserId,
                },
            },
        });

        if (!sourceMembership || sourceMembership.role !== 'OWNER') {
            throw new AuthorizationError('You must be the OWNER of the source workspace to import its members');
        }

        const targetMembership = await this.prisma.workspaceMember.findUnique({
            where: {
                workspaceId_userId: {
                    workspaceId: targetWorkspaceId,
                    userId: importingUserId,
                },
            },
        });

        if (!targetMembership || targetMembership.role !== 'OWNER') {
            throw new AuthorizationError('You must be the OWNER of the target workspace to import members');
        }

        const userIdsToImport = dto.members.map(m => m.userId);

        const validSourceMembers = await this.prisma.workspaceMember.findMany({
            where: {
                workspaceId: dto.sourceWorkspaceId,
                userId: { in: userIdsToImport },
            },
        });

        const validSourceUserIds = new Set(validSourceMembers.map(m => m.userId));

        const existingTargetMembers = await this.prisma.workspaceMember.findMany({
            where: {
                workspaceId: targetWorkspaceId,
                userId: { in: Array.from(validSourceUserIds) },
            },
        });

        const existingTargetUserIds = new Set(existingTargetMembers.map(m => m.userId));

        const newMembersToImport = dto.members.filter(m => 
            validSourceUserIds.has(m.userId) && !existingTargetUserIds.has(m.userId)
        );

        if (newMembersToImport.length === 0) {
            return { importedCount: 0, message: 'No new valid members found to import' };
        }

        const importedMembers = await this.prisma.$transaction(async (tx) => {
            const added = [];
            for (const m of newMembersToImport) {
                const newMember = await tx.workspaceMember.create({
                    data: {
                        workspaceId: targetWorkspaceId,
                        userId: m.userId,
                        role: m.role,
                    },
                });
                added.push(newMember);

                await tx.auditLog.create({
                    data: {
                        userId: importingUserId,
                        workspaceId: targetWorkspaceId,
                        action: AuditAction.MEMBER_IMPORTED,
                        resource: 'workspace_member',
                        resourceId: newMember.id,
                        details: {
                            sourceWorkspaceId: dto.sourceWorkspaceId,
                            importedUserId: m.userId,
                            role: m.role,
                        } as any,
                    },
                });
            }
            return added;
        });

        return {
            importedCount: importedMembers.length,
            members: importedMembers,
            message: `Successfully imported ${importedMembers.length} member(s)`,
        };
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

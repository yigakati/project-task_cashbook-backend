import { Router } from 'express';
import { container } from 'tsyringe';
import { MembersController } from './members.controller';
import { authenticate } from '../../middlewares/authenticate';
import { validate } from '../../middlewares/validate';
import { requireWorkspaceMember } from '../../middlewares/authorize';
import { inviteMemberSchema, updateMemberRoleSchema, importMembersSchema } from './members.dto';
import { WorkspaceRole } from '../../core/types';

const router = Router({ mergeParams: true });
const membersController = container.resolve(MembersController);

router.use(authenticate as any);

// Get workspace members
router.get(
    '/',
    requireWorkspaceMember() as any,
    membersController.getMembers.bind(membersController) as any
);

// Get pending invites for the workspace
router.get(
    '/invites/pending',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    membersController.getPendingInvites.bind(membersController) as any
);

// Get importable members from other workspaces
router.get(
    '/importable',
    requireWorkspaceMember([WorkspaceRole.OWNER]) as any,
    membersController.getImportableMembers.bind(membersController) as any
);

// Import members from another workspace
router.post(
    '/import',
    requireWorkspaceMember([WorkspaceRole.OWNER]) as any,
    validate(importMembersSchema),
    membersController.importMembers.bind(membersController) as any
);

// Invite member
router.post(
    '/',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    validate(inviteMemberSchema),
    membersController.inviteMember.bind(membersController) as any
);

// Update member role
router.patch(
    '/:userId',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    validate(updateMemberRoleSchema),
    membersController.updateRole.bind(membersController) as any
);

// Remove member
router.delete(
    '/:userId',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    membersController.removeMember.bind(membersController) as any
);

export default router;

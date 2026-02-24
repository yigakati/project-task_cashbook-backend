import { Router } from 'express';
import { container } from 'tsyringe';
import { AccountTypesController } from './account-types.controller';
import { authenticate } from '../../middlewares/authenticate';
import { validate } from '../../middlewares/validate';
import { requireWorkspaceMember } from '../../middlewares/authorize';
import { WorkspaceRole } from '../../core/types';
import { createAccountTypeSchema, updateAccountTypeSchema } from './account-types.dto';

const router = Router({ mergeParams: true });
const controller = container.resolve(AccountTypesController);

// All account type routes require authentication and workspace scope
router.use(authenticate as any);

// List account types
router.get(
    '/',
    requireWorkspaceMember() as any,
    controller.getAll.bind(controller) as any
);

// Create account type
router.post(
    '/',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    validate(createAccountTypeSchema),
    controller.create.bind(controller) as any
);

// Update account type
router.patch(
    '/:id',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    validate(updateAccountTypeSchema),
    controller.update.bind(controller) as any
);

// Delete account type
router.delete(
    '/:id',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    controller.delete.bind(controller) as any
);

export default router;

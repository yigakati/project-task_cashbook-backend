import { Router } from 'express';
import { container } from 'tsyringe';
import { AccountsController } from './accounts.controller';
import { authenticate } from '../../middlewares/authenticate';
import { validate } from '../../middlewares/validate';
import { requireWorkspaceMember } from '../../middlewares/authorize';
import { WorkspaceRole } from '../../core/types';
import { createAccountSchema, updateAccountSchema, archiveAccountSchema } from './accounts.dto';

const router = Router({ mergeParams: true });
const controller = container.resolve(AccountsController);

// All account routes require authentication and workspace scope
router.use(authenticate as any);

// List accounts
router.get(
    '/',
    requireWorkspaceMember() as any,
    controller.getAll.bind(controller) as any
);

// Get Net Worth
router.get(
    '/net-worth',
    requireWorkspaceMember() as any,
    controller.getNetWorth.bind(controller) as any
);

// Get single account
router.get(
    '/:id',
    requireWorkspaceMember() as any,
    controller.getById.bind(controller) as any
);

// Create account
router.post(
    '/',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    validate(createAccountSchema),
    controller.create.bind(controller) as any
);

// Update account
router.patch(
    '/:id',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    validate(updateAccountSchema),
    controller.update.bind(controller) as any
);

// Archive/Unarchive account
router.post(
    '/:id/archive',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    validate(archiveAccountSchema),
    controller.archive.bind(controller) as any
);

// Delete account
router.delete(
    '/:id',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    controller.delete.bind(controller) as any
);

export default router;

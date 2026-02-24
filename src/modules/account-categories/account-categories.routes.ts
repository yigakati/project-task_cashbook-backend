import { Router } from 'express';
import { container } from 'tsyringe';
import { AccountCategoriesController } from './account-categories.controller';
import { authenticate } from '../../middlewares/authenticate';
import { validate } from '../../middlewares/validate';
import { requireWorkspaceMember } from '../../middlewares/authorize';
import { WorkspaceRole } from '../../core/types';
import { createAccountCategorySchema, updateAccountCategorySchema } from './account-categories.dto';

const router = Router({ mergeParams: true });
const controller = container.resolve(AccountCategoriesController);

// All account category routes require authentication and workspace scope
router.use(authenticate as any);

// List account categories
router.get(
    '/',
    requireWorkspaceMember() as any,
    controller.getAll.bind(controller) as any
);

// Create account category
router.post(
    '/',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    validate(createAccountCategorySchema),
    controller.create.bind(controller) as any
);

// Update account category
router.patch(
    '/:id',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    validate(updateAccountCategorySchema),
    controller.update.bind(controller) as any
);

// Delete account category
router.delete(
    '/:id',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    controller.delete.bind(controller) as any
);

export default router;

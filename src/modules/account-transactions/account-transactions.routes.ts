import { Router } from 'express';
import { container } from 'tsyringe';
import { AccountTransactionsController } from './account-transactions.controller';
import { authenticate } from '../../middlewares/authenticate';
import { validate } from '../../middlewares/validate';
import { requireWorkspaceMember } from '../../middlewares/authorize';
import { WorkspaceRole } from '../../core/types';
import { createAccountTransactionSchema, updateAccountTransactionSchema } from './account-transactions.dto';

const router = Router({ mergeParams: true });
const controller = container.resolve(AccountTransactionsController);

router.use(authenticate as any);

router.get(
    '/',
    requireWorkspaceMember() as any, // MEMBER+ can read
    controller.getAllTransactions.bind(controller) as any
);

router.post(
    '/',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    validate(createAccountTransactionSchema),
    controller.create.bind(controller) as any
);

router.patch(
    '/:id',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    validate(updateAccountTransactionSchema),
    controller.update.bind(controller) as any
);

router.delete(
    '/:id',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    controller.delete.bind(controller) as any
);

export default router;

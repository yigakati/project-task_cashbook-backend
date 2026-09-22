import { Router } from 'express';
import { container } from 'tsyringe';
import { CashbooksController } from './cashbooks.controller';
import { authenticate } from '../../middlewares/authenticate';
import { validate } from '../../middlewares/validate';
import { WorkspacePermission } from '../../core/types/workspace-permissions';
import { requireWorkspaceMember, requireCashbookMember, requireBusinessWorkspace } from '../../middlewares/authorize';
import { CashbookPermission } from '../../core/types/permissions';
import {
    createCashbookSchema,
    updateCashbookSchema,
    addCashbookMemberSchema,
    updateCashbookMemberRoleSchema,
    archiveCashbookSchema,
} from './cashbooks.dto';

const router = Router({ mergeParams: true });
const cashbooksController = container.resolve(CashbooksController);

router.use(authenticate as any);

// ─── Workspace-scoped routes ───────────────────────────
// List cashbooks in a workspace
router.get(
    '/workspace/:workspaceId',
    requireWorkspaceMember() as any,
    cashbooksController.getAll.bind(cashbooksController) as any
);

// Create cashbook in a workspace
router.post(
    '/workspace/:workspaceId',
    requireWorkspaceMember(WorkspacePermission.CREATE_CASHBOOK) as any,
    validate(createCashbookSchema),
    cashbooksController.create.bind(cashbooksController) as any
);

// Opt-in integration activation. The workspace grant allows only owner, admin
// and developer roles; the cashbook check additionally requires developers to
// have been explicitly assigned to this particular book.
router.post(
    '/workspace/:workspaceId/:cashbookId/integration/activate',
    requireWorkspaceMember(WorkspacePermission.MANAGE_API_KEYS) as any,
    requireBusinessWorkspace() as any,
    requireCashbookMember(CashbookPermission.VIEW_CASHBOOK) as any,
    cashbooksController.activateIntegration.bind(cashbooksController) as any,
);

// ─── Cashbook-scoped routes ────────────────────────────
// Get single cashbook
router.get(
    '/:cashbookId',
    requireCashbookMember(CashbookPermission.VIEW_CASHBOOK) as any,
    cashbooksController.getOne.bind(cashbooksController) as any
);

// Update cashbook
router.patch(
    '/:cashbookId',
    requireCashbookMember(CashbookPermission.UPDATE_CASHBOOK) as any,
    validate(updateCashbookSchema),
    cashbooksController.update.bind(cashbooksController) as any
);

// Archive or restore a cashbook.
//
// Guarded by DELETE_CASHBOOK rather than UPDATE_CASHBOOK: archiving retires a
// book for everyone who can see it, so it belongs to whoever could have
// deleted it. requireCashbookMember lets this through on an already-archived
// book — restoring one is the whole point.
router.post(
    '/:cashbookId/archive',
    requireCashbookMember(CashbookPermission.DELETE_CASHBOOK) as any,
    validate(archiveCashbookSchema),
    cashbooksController.archive.bind(cashbooksController) as any
);

// Delete cashbook — only ever allowed on a book with no entries at all.
router.delete(
    '/:cashbookId',
    requireCashbookMember(CashbookPermission.DELETE_CASHBOOK) as any,
    cashbooksController.delete.bind(cashbooksController) as any
);

// Financial summary
router.get(
    '/:cashbookId/summary',
    requireCashbookMember(CashbookPermission.VIEW_CASHBOOK) as any,
    cashbooksController.getSummary.bind(cashbooksController) as any
);

// ─── Cashbook members ──────────────────────────────────
router.get(
    '/:cashbookId/members',
    requireCashbookMember(CashbookPermission.VIEW_MEMBERS) as any,
    cashbooksController.getMembers.bind(cashbooksController) as any
);

router.post(
    '/:cashbookId/members',
    requireCashbookMember(CashbookPermission.ADD_MEMBER) as any,
    validate(addCashbookMemberSchema),
    cashbooksController.addMember.bind(cashbooksController) as any
);

router.patch(
    '/:cashbookId/members/:userId',
    requireCashbookMember(CashbookPermission.CHANGE_MEMBER_ROLE) as any,
    validate(updateCashbookMemberRoleSchema),
    cashbooksController.updateMemberRole.bind(cashbooksController) as any
);

router.delete(
    '/:cashbookId/members/:userId',
    requireCashbookMember(CashbookPermission.REMOVE_MEMBER) as any,
    cashbooksController.removeMember.bind(cashbooksController) as any
);

// ─── Balance Recalculation ─────────────────────────────
router.post(
    '/:cashbookId/recalculate',
    requireCashbookMember(CashbookPermission.UPDATE_CASHBOOK) as any,
    cashbooksController.recalculateBalance.bind(cashbooksController) as any
);

// ─── Reconciliation Toggle ─────────────────────────────
router.patch(
    '/:cashbookId/entries/:entryId/reconcile',
    requireCashbookMember(CashbookPermission.UPDATE_ENTRY) as any,
    cashbooksController.toggleReconciliation.bind(cashbooksController) as any
);

export default router;

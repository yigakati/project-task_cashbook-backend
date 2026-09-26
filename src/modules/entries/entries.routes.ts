import { Router } from 'express';
import { container } from 'tsyringe';
import { EntriesController } from './entries.controller';
import { authenticate } from '../../middlewares/authenticate';
import { validate } from '../../middlewares/validate';
import { requireCashbookMember } from '../../middlewares/authorize';
import { idempotency } from '../../middlewares/idempotency';
import { CashbookPermission } from '../../core/types/permissions';
import {
    createEntrySchema,
    updateEntrySchema,
    deleteEntrySchema,
    reviewDeleteRequestSchema,
    entryQuerySchema,
    reassignEntrySchema,
} from './entries.dto';

const router = Router({ mergeParams: true });
const entriesController = container.resolve(EntriesController);

router.use(authenticate as any);

/*
 * Literal paths first. `/:entryId/cashbook/:cashbookId` below has the same
 * shape as `/delete-requests/cashbook/:cashbookId`, and Express matches in
 * declaration order — with the dynamic one first, listing delete requests
 * called getOne with entryId = "delete-requests" and went to Prisma with it.
 */
router.get(
    '/delete-requests/cashbook/:cashbookId',
    requireCashbookMember(CashbookPermission.APPROVE_DELETE) as any,
    entriesController.getDeleteRequests.bind(entriesController) as any
);

// ─── Entry CRUD ────────────────────────────────────────
router.get(
    '/cashbook/:cashbookId',
    requireCashbookMember(CashbookPermission.VIEW_ENTRIES) as any,
    validate(entryQuerySchema, 'query'),
    entriesController.getAll.bind(entriesController) as any
);

// Who and what the book's entries can be filtered by.
router.get(
    '/cashbook/:cashbookId/filter-options',
    requireCashbookMember(CashbookPermission.VIEW_ENTRIES) as any,
    entriesController.filterOptions.bind(entriesController) as any
);

router.get(
    '/:entryId/cashbook/:cashbookId',
    requireCashbookMember(CashbookPermission.VIEW_ENTRIES) as any,
    entriesController.getOne.bind(entriesController) as any
);

router.post(
    '/cashbook/:cashbookId',
    requireCashbookMember(CashbookPermission.CREATE_ENTRY) as any,
    idempotency('POST /entries/cashbook/:cashbookId') as any,
    validate(createEntrySchema),
    entriesController.create.bind(entriesController) as any
);

router.patch(
    '/:entryId/cashbook/:cashbookId',
    requireCashbookMember(CashbookPermission.UPDATE_ENTRY) as any,
    idempotency('PATCH /entries/:entryId/cashbook/:cashbookId') as any,
    validate(updateEntrySchema),
    entriesController.update.bind(entriesController) as any
);

/*
 * Move an entry to another book.
 *
 * Gated on UPDATE_ENTRY in the SOURCE book (the path one). Authority over the
 * DESTINATION is checked in the service, because that id arrives in the body —
 * without it, write access to one book would be write access to all of them.
 */
router.patch(
    '/:entryId/cashbook/:cashbookId/reassign',
    requireCashbookMember(CashbookPermission.UPDATE_ENTRY) as any,
    idempotency('PATCH /entries/:entryId/cashbook/:cashbookId/reassign') as any,
    validate(reassignEntrySchema),
    entriesController.reassign.bind(entriesController) as any
);

router.delete(
    '/:entryId/cashbook/:cashbookId',
    requireCashbookMember(CashbookPermission.DELETE_ENTRY) as any,
    idempotency('DELETE /entries/:entryId/cashbook/:cashbookId') as any,
    validate(deleteEntrySchema),
    entriesController.delete.bind(entriesController) as any
);

// ─── Delete Requests ───────────────────────────────────
router.post(
    '/delete-requests/:requestId/review/cashbook/:cashbookId',
    requireCashbookMember(CashbookPermission.APPROVE_DELETE) as any,
    validate(reviewDeleteRequestSchema),
    entriesController.reviewDeleteRequest.bind(entriesController) as any
);

// ─── Audit Trail ───────────────────────────────────────
router.get(
    '/:entryId/audit/cashbook/:cashbookId',
    requireCashbookMember(CashbookPermission.VIEW_AUDIT_LOG) as any,
    entriesController.getAuditTrail.bind(entriesController) as any
);

// ─── Receipts ──────────────────────────────────────────
/*
 * The receipt as JSON, for on-screen preview and printing.
 *
 * Printing is the client's job — it already has the page open, and the browser
 * prints better than we do. Emailing stays server-side below, because the
 * recipient never loads our page. Both read the same model so the printed and
 * emailed copies cannot disagree.
 */
router.get(
    '/:entryId/receipt/cashbook/:cashbookId',
    requireCashbookMember(CashbookPermission.VIEW_ENTRIES) as any,
    entriesController.receiptModel.bind(entriesController) as any
);

router.post(
    '/:entryId/receipt/send/cashbook/:cashbookId',
    requireCashbookMember(CashbookPermission.VIEW_ENTRIES) as any,
    entriesController.sendReceipt.bind(entriesController) as any
);

export default router;

import { Router } from 'express';
import { container } from 'tsyringe';
import { FilesController } from './files.controller';
import { authenticate } from '../../middlewares/authenticate';
import { CashbookPermission } from '../../core/types/permissions';
import { requireCashbookMember } from '../../middlewares/authorize';
import { upload } from '../../middlewares/upload';

const router = Router();
const controller = container.resolve(FilesController);

/**
 * All routes here require authentication
 */
router.use(authenticate as any);

/**
 * Upload an attachment to a specific entry
 * POST /api/files/cashbooks/:cashbookId/entries/:entryId
 */
router.post(
    '/cashbooks/:cashbookId/entries/:entryId',
    requireCashbookMember(CashbookPermission.CREATE_ENTRY) as any,
    upload.single('file'),
    controller.upload.bind(controller) as any
);

/**
 * Get all attachments for an entry
 * GET /api/files/entries/:entryId
 */
router.get(
    '/entries/:entryId',
    controller.getAll.bind(controller) as any
);

/**
 * Get a secure, temporary Presigned URL for an attachment
 * GET /api/files/:attachmentId/url/cashbooks/:cashbookId
 */
router.get(
    '/:attachmentId/url/cashbooks/:cashbookId',
    requireCashbookMember(CashbookPermission.VIEW_ATTACHMENTS) as any,
    controller.getFileUrl.bind(controller) as any
);

/**
 * Soft-delete an attachment
 * DELETE /api/files/:attachmentId/cashbooks/:cashbookId
 */
router.delete(
    '/:attachmentId/cashbooks/:cashbookId',
    requireCashbookMember(CashbookPermission.DELETE_ATTACHMENT) as any,
    controller.delete.bind(controller) as any
);

export default router;
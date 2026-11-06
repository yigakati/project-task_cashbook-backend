import { Router } from 'express';
import { container } from 'tsyringe';
import { InvoicingController } from './invoicing.controller';
import { authenticate } from '../../middlewares/authenticate';
import { validate } from '../../middlewares/validate';
import { requireWorkspaceMember } from '../../middlewares/authorize';
import { WorkspacePermission } from '../../core/types/workspace-permissions';
import {
    createInvoiceSchema,
    updateInvoiceSchema,
    invoiceQuerySchema,
    updateInvoiceSettingsSchema,
    sendInvoiceSchema,
    invoicePreviewSchema,
} from './invoicing.dto';
import { z } from 'zod';
import { uploadImageMemory } from '../../middlewares/uploadImage';

const router = Router({ mergeParams: true });
const controller = container.resolve(InvoicingController);

router.use(authenticate as any);

// ─── Reporting (BEFORE /:invoiceId to avoid route conflict) ─

router.get(
    '/reports/overdue',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVOICING) as any,
    controller.getOverdueInvoices.bind(controller) as any,
);

router.get(
    '/reports/summary',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVOICING) as any,
    controller.getInvoiceSummary.bind(controller) as any,
);

router.get(
    '/reports/customer-outstanding',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVOICING) as any,
    controller.getCustomerOutstanding.bind(controller) as any,
);

// ─── Invoice Settings (BEFORE /:invoiceId) ─────────────

router.get(
    '/settings/current',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVOICING) as any,
    controller.getSettings.bind(controller) as any,
);

router.patch(
    '/settings/current',
    requireWorkspaceMember(WorkspacePermission.MANAGE_INVOICING) as any,
    validate(updateInvoiceSettingsSchema),
    controller.updateSettings.bind(controller) as any,
);

router.post(
    '/settings/current/logo',
    requireWorkspaceMember(WorkspacePermission.MANAGE_INVOICING) as any,
    uploadImageMemory.single('file') as any,
    controller.uploadLogo.bind(controller) as any,
);

router.post(
    '/preview/draft',
    requireWorkspaceMember(WorkspacePermission.MANAGE_INVOICING) as any,
    validate(createInvoiceSchema),
    controller.draftDocument.bind(controller) as any,
);
router.post(
    '/settings/preview',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVOICING) as any,
    validate(invoicePreviewSchema),
    controller.previewDocument.bind(controller) as any,
);
router.post(
    '/settings/preview/pdf',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVOICING) as any,
    validate(invoicePreviewSchema),
    controller.previewPdf.bind(controller) as any,
);
router.get(
    '/:invoiceId/document',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVOICING) as any,
    controller.invoiceDocument.bind(controller) as any,
);
router.get(
    '/:invoiceId/pdf',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVOICING) as any,
    controller.invoicePdf.bind(controller) as any,
);

// ─── Invoice CRUD ──────────────────────────────────────

router.get(
    '/',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVOICING) as any,
    validate(invoiceQuerySchema, 'query'),
    controller.listInvoices.bind(controller) as any,
);

router.post(
    '/',
    requireWorkspaceMember(WorkspacePermission.MANAGE_INVOICING) as any,
    validate(createInvoiceSchema),
    controller.createInvoice.bind(controller) as any,
);

router.get(
    '/:invoiceId',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVOICING) as any,
    controller.getInvoice.bind(controller) as any,
);

router.patch(
    '/:invoiceId',
    requireWorkspaceMember(WorkspacePermission.MANAGE_INVOICING) as any,
    validate(updateInvoiceSchema),
    controller.updateInvoice.bind(controller) as any,
);

router.delete(
    '/:invoiceId',
    requireWorkspaceMember(WorkspacePermission.MANAGE_INVOICING) as any,
    controller.deleteInvoice.bind(controller) as any,
);

// ─── Invoice Actions ───────────────────────────────────

router.post(
    '/:invoiceId/send',
    requireWorkspaceMember(WorkspacePermission.MANAGE_INVOICING) as any,
    validate(sendInvoiceSchema),
    controller.sendInvoice.bind(controller) as any,
);

router.post(
    '/:invoiceId/void',
    requireWorkspaceMember(WorkspacePermission.MANAGE_INVOICING) as any,
    controller.voidInvoice.bind(controller) as any,
);

export default router;

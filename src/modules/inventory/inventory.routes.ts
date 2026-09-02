import { Router } from 'express';
import { container } from 'tsyringe';
import { InventoryController } from './inventory.controller';
import { authenticate } from '../../middlewares/authenticate';
import { idempotency } from '../../middlewares/idempotency';
import { validate, validateMultiple } from '../../middlewares/validate';
import { requireWorkspaceMember } from '../../middlewares/authorize';
import { WorkspacePermission } from '../../core/types/workspace-permissions';
import {
    createInventoryItemSchema,
    updateInventoryItemSchema,
    inventoryItemQuerySchema,
    createInventoryTransactionSchema,
    inventoryTransactionQuerySchema,
    cogsReportQuerySchema,
    itemIdParamSchema,
    analyticsQuerySchema,
    createDirectRentalSchema,
    returnRentalSchema,
    rentalQuerySchema,
} from './inventory.dto';
import { z } from 'zod';

const router = Router({ mergeParams: true });
const controller = container.resolve(InventoryController);

// All inventory routes require authentication and workspace membership
router.use(authenticate as any);

// ─── Items ─────────────────────────────────────────────

// List inventory items
router.get(
    '/items',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVENTORY) as any,
    validate(inventoryItemQuerySchema, 'query'),
    controller.getItems.bind(controller) as any
);

// Get single inventory item
router.get(
    '/items/:itemId',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVENTORY) as any,
    validate(itemIdParamSchema, 'params'),
    controller.getItem.bind(controller) as any
);

// Item-level profit/loss analytics from stock movements
router.get(
    '/items/:itemId/analytics',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVENTORY) as any,
    validate(itemIdParamSchema, 'params'),
    controller.getItemAnalytics.bind(controller) as any
);

// Create inventory item
router.post(
    '/items',
    requireWorkspaceMember(WorkspacePermission.MANAGE_INVENTORY) as any,
    validate(createInventoryItemSchema),
    controller.createItem.bind(controller) as any
);

// Update inventory item
router.patch(
    '/items/:itemId',
    requireWorkspaceMember(WorkspacePermission.MANAGE_INVENTORY) as any,
    validateMultiple({
        params: itemIdParamSchema,
        body: updateInventoryItemSchema,
    }),
    controller.updateItem.bind(controller) as any
);

// Deactivate inventory item
router.delete(
    '/items/:itemId',
    requireWorkspaceMember(WorkspacePermission.MANAGE_INVENTORY) as any,
    validate(itemIdParamSchema, 'params'),
    controller.deactivateItem.bind(controller) as any
);

// ─── Transactions ──────────────────────────────────────

// Create manual inventory transaction
router.post(
    '/transactions',
    requireWorkspaceMember(WorkspacePermission.MANAGE_INVENTORY) as any,
    validate(createInventoryTransactionSchema),
    controller.createTransaction.bind(controller) as any
);

// List inventory transactions
router.get(
    '/transactions',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVENTORY) as any,
    validate(inventoryTransactionQuerySchema, 'query'),
    controller.getTransactions.bind(controller) as any
);

// ─── Reports ───────────────────────────────────────────

// Current stock levels
router.get(
    '/reports/stock-levels',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVENTORY) as any,
    controller.getStockLevels.bind(controller) as any
);

// Inventory valuation
router.get(
    '/reports/valuation',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVENTORY) as any,
    controller.getValuation.bind(controller) as any
);

// Stock movement history for a specific item
router.get(
    '/reports/movements/:itemId',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVENTORY) as any,
    validate(itemIdParamSchema, 'params'),
    controller.getMovements.bind(controller) as any
);

// COGS summary
router.get(
    '/reports/cogs',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVENTORY) as any,
    validate(cogsReportQuerySchema, 'query'),
    controller.getCogs.bind(controller) as any
);

// Low stock alerts
router.get(
    '/reports/low-stock',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVENTORY) as any,
    controller.getLowStock.bind(controller) as any
);

// ─── Analytics ─────────────────────────────────────────

// Analytics metrics
router.get(
    '/analytics/metrics',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVENTORY) as any,
    validate(analyticsQuerySchema, 'query'),
    controller.getAnalyticsMetrics.bind(controller) as any
);

// Analytics trends
router.get(
    '/analytics/trends',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVENTORY) as any,
    validate(analyticsQuerySchema, 'query'),
    controller.getAnalyticsTrends.bind(controller) as any
);

// ─── Rentals (invoice-driven lifecycle) ────────────────

router.get(
    '/rentals',
    requireWorkspaceMember(WorkspacePermission.VIEW_INVENTORY) as any,
    validate(rentalQuerySchema, 'query'),
    controller.listRentals.bind(controller) as any
);

// A rental issued and paid in one step. MANAGE_INVENTORY guards the rental
// and stock side; the entry posts through the ordinary entry path inside the
// same transaction.
router.post(
    '/rentals/direct',
    requireWorkspaceMember(WorkspacePermission.MANAGE_INVENTORY) as any,
    idempotency('POST /workspaces/:workspaceId/inventory/rentals/direct') as any,
    validate(createDirectRentalSchema),
    controller.createDirectRental.bind(controller) as any
);

router.post(
    '/rentals/:rentalId/return',
    requireWorkspaceMember(WorkspacePermission.MANAGE_INVENTORY) as any,
    validateMultiple({
        params: z.object({ rentalId: z.string().uuid() }).passthrough(),
        body: returnRentalSchema,
    }),
    controller.returnRental.bind(controller) as any
);

export default router;

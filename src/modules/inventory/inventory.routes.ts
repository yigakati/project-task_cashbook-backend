import { Router } from 'express';
import { container } from 'tsyringe';
import { InventoryController } from './inventory.controller';
import { authenticate } from '../../middlewares/authenticate';
import { validate } from '../../middlewares/validate';
import { requireWorkspaceMember } from '../../middlewares/authorize';
import { WorkspaceRole } from '../../core/types';
import {
    createInventoryItemSchema,
    updateInventoryItemSchema,
    inventoryItemQuerySchema,
    createInventoryTransactionSchema,
    inventoryTransactionQuerySchema,
    cogsReportQuerySchema,
} from './inventory.dto';

const router = Router({ mergeParams: true });
const controller = container.resolve(InventoryController);

// All inventory routes require authentication and workspace membership
router.use(authenticate as any);

// ─── Items ─────────────────────────────────────────────

// List inventory items
router.get(
    '/items',
    requireWorkspaceMember() as any,
    validate(inventoryItemQuerySchema, 'query'),
    controller.getItems.bind(controller) as any
);

// Get single inventory item
router.get(
    '/items/:itemId',
    requireWorkspaceMember() as any,
    controller.getItem.bind(controller) as any
);

// Create inventory item
router.post(
    '/items',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    validate(createInventoryItemSchema),
    controller.createItem.bind(controller) as any
);

// Update inventory item
router.patch(
    '/items/:itemId',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    validate(updateInventoryItemSchema),
    controller.updateItem.bind(controller) as any
);

// Deactivate inventory item
router.delete(
    '/items/:itemId',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    controller.deactivateItem.bind(controller) as any
);

// ─── Transactions ──────────────────────────────────────

// Create manual inventory transaction
router.post(
    '/transactions',
    requireWorkspaceMember([WorkspaceRole.OWNER, WorkspaceRole.ADMIN]) as any,
    validate(createInventoryTransactionSchema),
    controller.createTransaction.bind(controller) as any
);

// List inventory transactions
router.get(
    '/transactions',
    requireWorkspaceMember() as any,
    validate(inventoryTransactionQuerySchema, 'query'),
    controller.getTransactions.bind(controller) as any
);

// ─── Reports ───────────────────────────────────────────

// Current stock levels
router.get(
    '/reports/stock-levels',
    requireWorkspaceMember() as any,
    controller.getStockLevels.bind(controller) as any
);

// Inventory valuation
router.get(
    '/reports/valuation',
    requireWorkspaceMember() as any,
    controller.getValuation.bind(controller) as any
);

// Stock movement history for a specific item
router.get(
    '/reports/movements/:itemId',
    requireWorkspaceMember() as any,
    controller.getMovements.bind(controller) as any
);

// COGS summary
router.get(
    '/reports/cogs',
    requireWorkspaceMember() as any,
    validate(cogsReportQuerySchema, 'query'),
    controller.getCogs.bind(controller) as any
);

// Low stock alerts
router.get(
    '/reports/low-stock',
    requireWorkspaceMember() as any,
    controller.getLowStock.bind(controller) as any
);

export default router;

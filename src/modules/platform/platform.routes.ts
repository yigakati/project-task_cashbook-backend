import { Router } from 'express';
import { container } from 'tsyringe';
import { PlatformController } from './platform.controller';
import { authenticate } from '../../middlewares/authenticate';
import { requireSuperAdmin } from '../../middlewares/authorize';
import { validate } from '../../middlewares/validate';
import { uuidParams } from '../../middlewares/uuidParam';
import {
    setWorkspaceFeatureSchema,
    setReferralAgentSchema,
    updatePlatformSettingsSchema,
} from './platform.dto';

const router = Router();
const controller = container.resolve(PlatformController);

router.use(authenticate as any);
router.use(requireSuperAdmin() as any);

router.get('/stats', controller.getStats.bind(controller) as any);

router.get('/users', controller.listUsers.bind(controller) as any);
router.patch('/users/:userId/toggle-status', controller.toggleUserStatus.bind(controller) as any);

router.get('/workspaces', controller.listWorkspaces.bind(controller) as any);

// Unlocking a module for one organisation. The only write this module has ever
// had against a workspace — everything else here is read-only by design.
router.patch(
    '/workspaces/:workspaceId/features',
    validate(uuidParams('workspaceId'), 'params'),
    validate(setWorkspaceFeatureSchema),
    controller.setWorkspaceFeature.bind(controller) as any,
);

// ─── Platform-wide settings ────────────────────────────
//
// Applies to every workspace at once, unlike the per-organisation feature
// grants above.
router.get('/settings', controller.getSettings.bind(controller) as any);
router.patch(
    '/settings',
    validate(updatePlatformSettingsSchema),
    controller.updateSettings.bind(controller) as any,
);

// ─── Referral agents ───────────────────────────────────
//
// Appointing is a platform act, not a workspace one: an agent brings people to
// the product, not to any one organisation.
router.get('/referral-agents', controller.listReferralAgents.bind(controller) as any);
router.get(
    '/referral-agents/:agentId/referrals',
    validate(uuidParams('agentId'), 'params'),
    controller.listAgentReferrals.bind(controller) as any,
);
router.patch(
    '/users/:userId/referral-agent',
    validate(uuidParams('userId'), 'params'),
    validate(setReferralAgentSchema),
    controller.setReferralAgent.bind(controller) as any,
);

router.get('/audit-logs', controller.listAuditLogs.bind(controller) as any);

// Read-only: the env var is the source of truth, so there is no grant/revoke
// endpoint. `reconcile` re-applies it without waiting for a restart.
router.get('/super-admins', controller.listSuperAdmins.bind(controller) as any);
router.post('/super-admins/reconcile', controller.reconcileSuperAdmins.bind(controller) as any);

export default router;

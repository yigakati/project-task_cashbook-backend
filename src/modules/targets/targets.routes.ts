import { Router } from 'express';
import { container } from 'tsyringe';
import { TargetsController } from './targets.controller';
import { authenticate } from '../../middlewares/authenticate';
import { requireWorkspaceMember } from '../../middlewares/authorize';
import { validate } from '../../middlewares/validate';
import { uuidParams } from '../../middlewares/uuidParam';
import { WorkspacePermission } from '../../core/types/workspace-permissions';
import {
    contributionListQuerySchema,
    createContributionSchema,
    createTargetSchema,
    targetListQuerySchema,
    updateContributionSchema,
    updateTargetSchema,
} from './targets.dto';

const controller = container.resolve(TargetsController);

/**
 * /workspaces/:workspaceId/targets
 *
 * Any member may read: the service shows each person only what they may see
 * (their own targets, or every target if they can see every book). Changing
 * targets takes MANAGE_TARGETS.
 *
 * Amounts recorded by hand on a MANUAL target (/contributions) are open to any
 * member at the route; the service allows the person the target is for and
 * managers, and lets a record be changed only by its recorder or a manager.
 */
const router = Router({ mergeParams: true });
router.use(authenticate as any);

const manage = requireWorkspaceMember(WorkspacePermission.MANAGE_TARGETS) as any;
const member = requireWorkspaceMember() as any;
const targetParam = validate(uuidParams('targetId'), 'params');
const contributionParams = validate(uuidParams('targetId', 'contributionId'), 'params');

router.get('/', member, validate(targetListQuerySchema, 'query'), controller.list.bind(controller) as any);
router.post('/', manage, validate(createTargetSchema), controller.create.bind(controller) as any);
router.get('/:targetId', member, targetParam, controller.get.bind(controller) as any);
router.patch('/:targetId', manage, targetParam, validate(updateTargetSchema), controller.update.bind(controller) as any);
router.post('/:targetId/archive', manage, targetParam, controller.archive.bind(controller) as any);
router.post('/:targetId/restore', manage, targetParam, controller.restore.bind(controller) as any);
router.delete('/:targetId', manage, targetParam, controller.remove.bind(controller) as any);

router.get('/:targetId/contributions', member, targetParam, validate(contributionListQuerySchema, 'query'),
    controller.listContributions.bind(controller) as any);
router.post('/:targetId/contributions', member, targetParam, validate(createContributionSchema),
    controller.recordContribution.bind(controller) as any);
router.patch('/:targetId/contributions/:contributionId', member, contributionParams, validate(updateContributionSchema),
    controller.updateContribution.bind(controller) as any);
router.delete('/:targetId/contributions/:contributionId', member, contributionParams,
    controller.deleteContribution.bind(controller) as any);

export default router;

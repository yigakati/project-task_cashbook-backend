import { Router } from 'express';
import { container } from 'tsyringe';
import { ReferralsController } from './referrals.controller';
import { authenticate } from '../../middlewares/authenticate';

/**
 * An agent's own referral figures.
 *
 * Workspace-scoped in the URL, but the service only answers for the caller's
 * own PERSONAL workspace — being a referral agent belongs to the person, and
 * showing it inside a shared business workspace would put one member's numbers
 * in front of their colleagues.
 *
 * No permission guard here on purpose: workspace membership is not the
 * question, and the service answers 404 for every other case rather than
 * confirming that a referral section exists at all.
 */
const router = Router({ mergeParams: true });
const controller = container.resolve(ReferralsController);

router.use(authenticate as any);

router.get('/', controller.getOverview.bind(controller) as any);

export default router;

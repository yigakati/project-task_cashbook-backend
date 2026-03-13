import { Router } from 'express';
import { container } from 'tsyringe';
import { InvitesController } from './invites.controller';
import { authenticate } from '../../middlewares/authenticate';
import { validate } from '../../middlewares/validate';
import { inviteIdParamSchema } from './invites.dto';

const router = Router();
const invitesController = container.resolve(InvitesController);

router.use(authenticate as any);

// Get pending invitations for the authenticated user
router.get(
    '/pending',
    invitesController.getPendingInvites.bind(invitesController) as any
);

// Accept an invitation
router.post(
    '/:inviteId/accept',
    validate(inviteIdParamSchema, 'params'),
    invitesController.acceptInvite.bind(invitesController) as any
);

// Decline an invitation
router.post(
    '/:inviteId/decline',
    validate(inviteIdParamSchema, 'params'),
    invitesController.declineInvite.bind(invitesController) as any
);

export default router;

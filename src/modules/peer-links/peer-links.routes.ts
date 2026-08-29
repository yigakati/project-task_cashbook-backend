import { Router } from 'express';
import { container } from 'tsyringe';
import { PeerLinksController } from './peer-links.controller';
import { authenticate } from '../../middlewares/authenticate';
import { requireCashbookMember, requireWorkspaceMember } from '../../middlewares/authorize';
import { CashbookPermission } from '../../core/types/permissions';
import { validateMultiple } from '../../middlewares/validate';
import { idempotency } from '../../middlewares/idempotency';
import {
    createPeerLinkSchema,
    respondPeerLinkSchema,
    declinePeerLinkSchema,
    cancelPeerLinkSchema,
    settlementDecisionSchema,
    peerLinkQuerySchema,
    userLookupQuerySchema,
    workspaceObligationsQuerySchema,
} from './peer-links.dto';

/**
 * Peer Links — user-to-user obligation agreements — split across two mounts:
 *
 *   /cashbooks/:cashbookId/peer-links   proposing from a book (book-scoped
 *                                       authority, same guard as obligations)
 *   /peer-links                         everything the two parties do with an
 *                                       existing link. Person-scoped on
 *                                       purpose: your inbox of proposals is
 *                                       yours, whichever of your books it
 *                                       eventually lands in.
 */
export const peerLinksCashbookRouter = Router({ mergeParams: true });
export const peerLinksRouter = Router();

const controller = container.resolve(PeerLinksController);

peerLinksCashbookRouter.use(authenticate as any);

peerLinksCashbookRouter.post('/',
    requireCashbookMember(CashbookPermission.MANAGE_OBLIGATIONS) as any,
    idempotency('POST /cashbooks/:cashbookId/peer-links') as any,
    validateMultiple({ body: createPeerLinkSchema }),
    controller.createPeerLink.bind(controller) as any,
);

// ─── Person-scoped peer link surface ───────────────────

peerLinksRouter.use(authenticate as any);

peerLinksRouter.get('/',
    validateMultiple({ query: peerLinkQuerySchema }),
    controller.getPeerLinks.bind(controller) as any,
);

peerLinksRouter.get('/users/lookup',
    validateMultiple({ query: userLookupQuerySchema }),
    controller.lookupUser.bind(controller) as any,
);

peerLinksRouter.get('/:peerLinkId',
    controller.getPeerLink.bind(controller) as any,
);

peerLinksRouter.get('/:peerLinkId/acceptable-cashbooks',
    controller.getAcceptableCashbooks.bind(controller) as any,
);

peerLinksRouter.post('/:peerLinkId/accept',
    idempotency('POST /peer-links/:peerLinkId/accept') as any,
    validateMultiple({ body: respondPeerLinkSchema }),
    controller.acceptPeerLink.bind(controller) as any,
);

peerLinksRouter.post('/:peerLinkId/decline',
    validateMultiple({ body: declinePeerLinkSchema }),
    controller.declinePeerLink.bind(controller) as any,
);

peerLinksRouter.post('/:peerLinkId/cancel',
    validateMultiple({ body: cancelPeerLinkSchema }),
    controller.cancelPeerLink.bind(controller) as any,
);

peerLinksRouter.post('/settlements/:settlementId/decision',
    idempotency('POST /peer-links/settlements/:settlementId/decision') as any,
    validateMultiple({ body: settlementDecisionSchema }),
    controller.decideSettlement.bind(controller) as any,
);

// ─── Workspace-wide obligations (new Obligations page) ──

export const workspaceObligationsRouter = Router({ mergeParams: true });
workspaceObligationsRouter.use(authenticate as any);
workspaceObligationsRouter.get('/',
    requireWorkspaceMember() as any,
    validateMultiple({ query: workspaceObligationsQuerySchema }),
    controller.getWorkspaceObligations.bind(controller) as any,
);

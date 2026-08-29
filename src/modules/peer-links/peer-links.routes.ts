import { Router, NextFunction, Request, Response } from 'express';
import { container } from 'tsyringe';
import { PeerLinksController } from './peer-links.controller';
import { authenticate } from '../../middlewares/authenticate';
import { requireCashbookMember, requireWorkspaceMember } from '../../middlewares/authorize';
import { getPrismaClient } from '../../config/database';
import { NotFoundError } from '../../core/errors/AppError';
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

/**
 * The accept URL names no cashbook — the counterparty's chosen book arrives in
 * the body. Copy it into params (the same move requireEntryAccess makes when a
 * route names an entry instead of its book) so requireCashbookMember enforces
 * book-level authority AND resolves the workspace the idempotency middleware
 * keys its record on. Without a workspace scope the claim would be keyed on
 * NULL, which Postgres treats as always-distinct — no replay protection.
 */
const cashbookIdFromBody = (req: Request, _res: Response, next: NextFunction) => {
    // respondPeerLinkSchema guarantees a uuid; the validate step runs first.
    req.params.cashbookId = (req.body as { cashbookId?: string }).cashbookId as string;
    next();
};

peerLinksRouter.post('/:peerLinkId/accept',
    validateMultiple({ body: respondPeerLinkSchema }),
    cashbookIdFromBody,
    requireCashbookMember(CashbookPermission.MANAGE_OBLIGATIONS) as any,
    idempotency('POST /peer-links/:peerLinkId/accept') as any,
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

/**
 * Settlement decisions are party-checked in the service, not by a book guard —
 * the counterparty owes no membership in the recorder's workspace. But the
 * idempotency record still needs a workspace to key on, so resolve the
 * recording entry's workspace here. Who may decide stays in the service.
 */
const settlementWorkspace = async (req: Request, _res: Response, next: NextFunction) => {
    try {
        const settlement = await getPrismaClient().peerLinkSettlement.findUnique({
            where: { id: req.params.settlementId as string },
            select: { entry: { select: { cashbook: { select: { workspaceId: true } } } } },
        });
        if (!settlement) throw new NotFoundError('Settlement');
        (req as Request & { workspaceId?: string }).workspaceId =
            settlement.entry.cashbook.workspaceId;
        next();
    } catch (error) {
        next(error as Error);
    }
};

peerLinksRouter.post('/settlements/:settlementId/decision',
    validateMultiple({ body: settlementDecisionSchema }),
    settlementWorkspace,
    idempotency('POST /peer-links/settlements/:settlementId/decision') as any,
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

import { Router, RequestHandler } from 'express';
import { container } from 'tsyringe';
import { authenticate } from '../../middlewares/authenticate';
import { validate } from '../../middlewares/validate';
import { uuidParams } from '../../middlewares/uuidParam';
import { idempotency } from '../../middlewares/idempotency';
import { AuthenticatedRequest } from '../../core/types';
import { SharedEntriesService } from './shared-entries.service';
import { acceptSharedEntrySchema, declineSharedEntrySchema, sharedEntryQuerySchema, SharedEntryQueryDto } from './shared-entries.dto';

const router = Router();
const service = container.resolve(SharedEntriesService);
const handle = (fn: (req: AuthenticatedRequest) => Promise<unknown>): RequestHandler => async (req, res, next) => {
    try { res.json({ success: true, data: await fn(req as AuthenticatedRequest) }); }
    catch (error) { next(error); }
};

// Person-scoped: the recipient decides which workspace will receive a copy.
router.use(authenticate as RequestHandler);
router.get('/', validate(sharedEntryQuerySchema, 'query'), handle(req => service.list(req.user.userId, req.query as unknown as SharedEntryQueryDto)));
router.get('/count', handle(req => service.count(req.user.userId)));
router.get('/:id/destinations', validate(uuidParams('id'), 'params'), handle(req => service.destinations(req.params.id as string, req.user.userId)));
router.get('/:id/options/:cashbookId', validate(uuidParams('id', 'cashbookId'), 'params'), handle(req => service.options(req.params.id as string, req.user.userId, req.params.cashbookId as string)));
router.post('/:id/accept', validate(uuidParams('id'), 'params'), validate(acceptSharedEntrySchema),
    idempotency('POST /shared-entries/:id/accept') as RequestHandler,
    handle(req => service.accept(req.params.id as string, req.user.userId, req.body)));
router.post('/:id/decline', validate(uuidParams('id'), 'params'), validate(declineSharedEntrySchema),
    handle(req => service.decline(req.params.id as string, req.user.userId, req.body.reason)));

export default router;

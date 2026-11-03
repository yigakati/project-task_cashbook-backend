import { Router, RequestHandler } from 'express';
import { container } from 'tsyringe';
import { authenticate } from '../../middlewares/authenticate';
import { validate } from '../../middlewares/validate';
import { uuidParams } from '../../middlewares/uuidParam';
import { idempotency } from '../../middlewares/idempotency';
import { AuthenticatedRequest } from '../../core/types';
import { pageSchema } from '../housing/housing.dto';
import { RentalIssuesService } from './rental-issues.service';
import { issueQuerySchema, issueSchema, messageSchema } from './rental-issues.dto';
const router = Router();
const service = container.resolve(RentalIssuesService);
const handle =
    (fn: (r: AuthenticatedRequest) => Promise<unknown>): RequestHandler =>
    async (req, res, next) => {
        try {
            res.json({ success: true, data: await fn(req as AuthenticatedRequest) });
        } catch (error) {
            next(error);
        }
    };
router.use(authenticate as RequestHandler);
router.get(
    '/rentals/mine',
    handle((r) => service.rentals(r.user.userId)),
);
router.get(
    '/',
    validate(issueQuerySchema, 'query'),
    handle((r) => service.list(r.user.userId, issueQuerySchema.parse(r.query))),
);
router.post(
    '/',
    validate(issueSchema),
    idempotency('POST /rental-issues') as RequestHandler,
    handle((r) => service.create(r.user.userId, r.body)),
);
router.get(
    '/:id',
    validate(uuidParams('id'), 'params'),
    validate(pageSchema, 'query'),
    handle((r) => service.detail(r.params.id as string, r.user.userId, pageSchema.parse(r.query))),
);
router.post(
    '/:id/messages',
    validate(uuidParams('id'), 'params'),
    validate(messageSchema),
    idempotency('POST /rental-issues/:id/messages') as RequestHandler,
    handle((r) => service.respond(r.params.id as string, r.user.userId, r.body)),
);
export default router;

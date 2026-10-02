import { Router } from 'express';
import { container } from 'tsyringe';
import rateLimit from 'express-rate-limit';
import { AccountDeletionController } from './account-deletion.controller';
import { authenticate } from '../../middlewares/authenticate';
import { validate } from '../../middlewares/validate';
import { uuidParams } from '../../middlewares/uuidParam';
import {
    adminCancelDeletionSchema,
    adminScheduleDeletionSchema,
    confirmDeletionSchema,
    deletionListQuerySchema,
    requestDeletionSchema,
    webDeletionRequestSchema,
} from './account-deletion.dto';

const controller = container.resolve(AccountDeletionController);

const limited = (max: number, windowMinutes: number, message: string) => rateLimit({
    windowMs: windowMinutes * 60 * 1000,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message },
});

/**
 * The person's own account: /users/me/deletion.
 *
 * Asking re-confirms with a password, so it is rate-limited like a sign-in.
 */
export const accountDeletionMeRouter = Router();
accountDeletionMeRouter.use(authenticate as any);
accountDeletionMeRouter.get('/', controller.getMine.bind(controller) as any);
accountDeletionMeRouter.post(
    '/',
    limited(10, 15, 'Too many attempts. Please wait a few minutes and try again.'),
    validate(requestDeletionSchema),
    controller.requestMine.bind(controller) as any,
);
accountDeletionMeRouter.post('/cancel', controller.cancelMine.bind(controller) as any);

/**
 * Signed out, from the website: /account-deletion.
 *
 * App stores require a way to ask for deletion without the app. Both
 * endpoints are public, so both are tightly rate-limited per IP.
 */
export const accountDeletionPublicRouter = Router();
accountDeletionPublicRouter.post(
    '/requests',
    limited(5, 60, 'Too many requests. Please try again later.'),
    validate(webDeletionRequestSchema),
    controller.requestFromWeb.bind(controller) as any,
);
accountDeletionPublicRouter.post(
    '/confirm',
    limited(20, 15, 'Too many attempts. Please try again later.'),
    validate(confirmDeletionSchema),
    controller.confirmFromWeb.bind(controller) as any,
);

/** Superadmin: mounted inside the platform router, which already requires one. */
export const accountDeletionPlatformRouter = Router();
accountDeletionPlatformRouter.get('/', validate(deletionListQuerySchema, 'query'), controller.list.bind(controller) as any);
accountDeletionPlatformRouter.get('/attention-count', controller.attentionCount.bind(controller) as any);
accountDeletionPlatformRouter.post(
    '/users/:userId',
    validate(uuidParams('userId'), 'params'),
    validate(adminScheduleDeletionSchema),
    controller.scheduleForUser.bind(controller) as any,
);
accountDeletionPlatformRouter.get(
    '/:requestId',
    validate(uuidParams('requestId'), 'params'),
    controller.getOne.bind(controller) as any,
);
accountDeletionPlatformRouter.post(
    '/:requestId/process',
    validate(uuidParams('requestId'), 'params'),
    controller.processNow.bind(controller) as any,
);
accountDeletionPlatformRouter.post(
    '/:requestId/cancel',
    validate(uuidParams('requestId'), 'params'),
    validate(adminCancelDeletionSchema),
    controller.cancel.bind(controller) as any,
);

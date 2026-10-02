import { Router } from 'express';
import { container } from 'tsyringe';
import rateLimit from 'express-rate-limit';
import { SupportController } from './support.controller';
import { validate } from '../../middlewares/validate';
import { uuidParams } from '../../middlewares/uuidParam';
import { contactListQuerySchema, contactMessageSchema, updateContactMessageSchema } from './support.dto';

const controller = container.resolve(SupportController);

/** Public: /support. */
export const supportPublicRouter = Router();
supportPublicRouter.post(
    '/contact',
    rateLimit({
        windowMs: 60 * 60 * 1000,
        max: 5,
        standardHeaders: true,
        legacyHeaders: false,
        message: { success: false, message: 'Too many messages. Please try again later or email us directly.' },
    }),
    validate(contactMessageSchema),
    controller.submit.bind(controller) as any,
);

/** Superadmin: mounted inside the platform router. */
export const supportPlatformRouter = Router();
supportPlatformRouter.get('/messages', validate(contactListQuerySchema, 'query'), controller.list.bind(controller) as any);
supportPlatformRouter.get('/messages/open-count', controller.openCount.bind(controller) as any);
supportPlatformRouter.patch(
    '/messages/:messageId',
    validate(uuidParams('messageId'), 'params'),
    validate(updateContactMessageSchema),
    controller.setStatus.bind(controller) as any,
);

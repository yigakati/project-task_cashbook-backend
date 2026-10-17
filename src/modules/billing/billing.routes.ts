import { Router } from 'express';
import { container } from 'tsyringe';
import { BillingController } from './billing.controller';
import { authenticate } from '../../middlewares/authenticate';
import { validate } from '../../middlewares/validate';
import { checkoutSchema, quoteQuerySchema } from './billing.dto';

const controller = container.resolve(BillingController);

/**
 * /billing
 *
 * The catalogue and quotes are public: the pricing page can be visited before
 * signing in, and checkout sends a new account to sign up first. The account
 * and checkout routes need a session.
 */
const publicRouter = Router();
publicRouter.get('/plans', controller.plans.bind(controller) as any);
publicRouter.get('/plans/quote', validate(quoteQuerySchema, 'query'), controller.quote.bind(controller) as any);

const privateRouter = Router();
privateRouter.use(authenticate as any);
privateRouter.get('/account', controller.account.bind(controller) as any);
// Checkout is reachable now so the flow is end-to-end; with no payment
// provider configured it answers PAYMENTS_COMING_SOON (503), which the app
// shows as a notice. Nothing is charged or recorded.
privateRouter.post('/checkout', validate(checkoutSchema), controller.checkout.bind(controller) as any);

export { publicRouter as billingPublicRouter, privateRouter as billingRouter };

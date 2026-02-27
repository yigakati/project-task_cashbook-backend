import { Router } from 'express';
import { ObligationsController } from './obligations.controller';
import { authenticate } from '../../middlewares/authenticate';
import { requireWorkspaceMember } from '../../middlewares/authorize';
import { CashbookRole } from '../../core/types';
import { validateMultiple } from '../../middlewares/validate';
import { createObligationSchema, updateObligationSchema, obligationQuerySchema } from './obligations.dto';
import { container } from 'tsyringe';

export const obligationsRouter = Router({ mergeParams: true });
const controller = container.resolve(ObligationsController);

// All routes require authentication
obligationsRouter.use(authenticate as any);
obligationsRouter.use(requireWorkspaceMember() as any);

// Reports
obligationsRouter.get('/reports/receivables',
    controller.getOutstandingReceivables.bind(controller) as any
);

obligationsRouter.get('/reports/payables',
    controller.getOutstandingPayables.bind(controller) as any
);

// Core CRUD
obligationsRouter.get('/',
    validateMultiple({ query: obligationQuerySchema }),
    controller.getObligations.bind(controller) as any
);

obligationsRouter.post('/',
    validateMultiple({ body: createObligationSchema }),
    controller.createObligation.bind(controller) as any
);

obligationsRouter.get('/:id',
    controller.getObligation.bind(controller) as any
);

obligationsRouter.patch('/:id',
    validateMultiple({ body: updateObligationSchema }),
    controller.updateObligation.bind(controller) as any
);

obligationsRouter.delete('/:id/archive',
    controller.archiveObligation.bind(controller) as any
);

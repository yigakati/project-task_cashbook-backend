import { Router } from 'express';
import { ObligationsController } from './obligations.controller';
import { authenticate } from '../../middlewares/authenticate';
import { requireCashbookMember } from '../../middlewares/authorize';
import { CashbookPermission } from '../../core/types/permissions';
import { validateMultiple } from '../../middlewares/validate';
import { createObligationSchema, updateObligationSchema, obligationQuerySchema } from './obligations.dto';
import { container } from 'tsyringe';

export const obligationsRouter = Router({ mergeParams: true });
const controller = container.resolve(ObligationsController);

// All routes require authentication
obligationsRouter.use(authenticate as any);

// Reports
obligationsRouter.get('/reports/receivables',
    requireCashbookMember(CashbookPermission.VIEW_OBLIGATIONS) as any,
    controller.getOutstandingReceivables.bind(controller) as any
);

obligationsRouter.get('/reports/payables',
    requireCashbookMember(CashbookPermission.VIEW_OBLIGATIONS) as any,
    controller.getOutstandingPayables.bind(controller) as any
);

// Core CRUD
obligationsRouter.get('/',
    requireCashbookMember(CashbookPermission.VIEW_OBLIGATIONS) as any,
    validateMultiple({ query: obligationQuerySchema }),
    controller.getObligations.bind(controller) as any
);

obligationsRouter.post('/',
    requireCashbookMember(CashbookPermission.MANAGE_OBLIGATIONS) as any,
    validateMultiple({ body: createObligationSchema }),
    controller.createObligation.bind(controller) as any
);

obligationsRouter.get('/:id',
    requireCashbookMember(CashbookPermission.VIEW_OBLIGATIONS) as any,
    controller.getObligation.bind(controller) as any
);

obligationsRouter.patch('/:id',
    requireCashbookMember(CashbookPermission.MANAGE_OBLIGATIONS) as any,
    validateMultiple({ body: updateObligationSchema }),
    controller.updateObligation.bind(controller) as any
);

obligationsRouter.delete('/:id/archive',
    requireCashbookMember(CashbookPermission.MANAGE_OBLIGATIONS) as any,
    controller.archiveObligation.bind(controller) as any
);

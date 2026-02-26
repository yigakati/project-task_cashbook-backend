import { Router } from 'express';
import { container } from 'tsyringe';
import { ReportsController } from './reports.controller';
import { authenticate } from '../../middlewares/authenticate';
import { validate } from '../../middlewares/validate';
import { requireCashbookMember } from '../../middlewares/authorize';
import { CashbookPermission } from '../../core/types/permissions';
import { reportQuerySchema } from './reports.dto';

const router = Router({ mergeParams: true });
const reportsController = container.resolve(ReportsController);

router.use(authenticate as any);

// Get report data as JSON
router.get(
    '/:cashbookId',
    requireCashbookMember(CashbookPermission.GENERATE_REPORT) as any,
    validate(reportQuerySchema, 'query'),
    reportsController.generate.bind(reportsController) as any
);

// Download report as file (PDF/Excel)
router.get(
    '/:cashbookId/download',
    requireCashbookMember(CashbookPermission.GENERATE_REPORT) as any,
    validate(reportQuerySchema, 'query'),
    reportsController.download.bind(reportsController) as any
);

// Queue async report generation (emailed when done)
// router.post(
//     '/:cashbookId/queue',
//     requireCashbookMember(CashbookPermission.GENERATE_REPORT) as any,
//     validate(reportQuerySchema, 'query'),
//     reportsController.queueReport.bind(reportsController) as any
// );

// Check async report job status
// router.get(
//     '/jobs/:jobId/status',
//     reportsController.jobStatus.bind(reportsController) as any
// );

export default router;

import { Router, Response, NextFunction } from 'express';
import { injectable, container } from 'tsyringe';
import { StatusCodes } from 'http-status-codes';
import { z } from 'zod';
import { authenticate } from '../../middlewares/authenticate';
import { requireWorkspaceMember } from '../../middlewares/authorize';
import { validate } from '../../middlewares/validate';
import { idempotency } from '../../middlewares/idempotency';
import { WorkspacePermission } from '../../core/types/workspace-permissions';
import { AuthenticatedRequest } from '../../core/types';
import { StockTransfersService } from './stock-transfers.service';
import { RentalAgreementsService } from './rental-agreements.service';
import {
    createStockRequestSchema, respondStockRequestSchema,
    recordTransferEntrySchema, stockTransferQuerySchema,
    createRentalAgreementSchema, respondRentalAgreementSchema, rentalAgreementQuerySchema,
    recordAgreementExpenseSchema,
    reasonSchema,
} from './agreements.dto';

/**
 * Cross-workspace agreements — stock requests and rental contracts between
 * two platform users.
 *
 * Stock requests start in the requester's workspace (they ask a vendor for
 * stock); everything after is person-scoped, like peer links, because each
 * decision belongs to the person, not to whichever workspace they are
 * viewing. Rental contracts start from a rentable item in the lender's
 * workspace; the rest mirrors the same person-scoped shape.
 */

@injectable()
class AgreementsController {
    constructor(
        private stockTransfers: StockTransfersService,
        private rentalAgreements: RentalAgreementsService,
    ) { }

    // ─── Stock requests ─────────────────────────────────
    async createStockRequest(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.stockTransfers.createRequest(
                req.params.workspaceId as string,
                req.user.userId,
                req.body,
            );
            res.status(StatusCodes.CREATED).json({ success: true, message: 'Stock request sent', data });
        } catch (e) { next(e); }
    }

    async listStockRequests(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.stockTransfers.list(req.user.userId, req.query as any);
            res.status(StatusCodes.OK).json({ success: true, message: 'Stock requests retrieved', ...result });
        } catch (e) { next(e); }
    }

    async getStockRequest(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.stockTransfers.getForUser(req.params.transferId as string, req.user.userId);
            res.status(StatusCodes.OK).json({ success: true, message: 'Stock request retrieved', data });
        } catch (e) { next(e); }
    }

    async getSendOptions(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.stockTransfers.getSendOptions(req.params.transferId as string, req.user.userId);
            res.status(StatusCodes.OK).json({ success: true, message: 'Send options retrieved', data });
        } catch (e) { next(e); }
    }

    async sendStock(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.stockTransfers.send(req.params.transferId as string, req.user.userId, req.body);
            res.status(StatusCodes.OK).json({ success: true, message: 'Stock sent — awaiting the customer\'s confirmation', data });
        } catch (e) { next(e); }
    }

    async receiveStock(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.stockTransfers.receive(req.params.transferId as string, req.user.userId);
            res.status(StatusCodes.OK).json({ success: true, message: 'Stock received — exchange complete', data });
        } catch (e) { next(e); }
    }

    async declineStockRequest(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.stockTransfers.decline(req.params.transferId as string, req.user.userId, req.body?.reason);
            res.status(StatusCodes.OK).json({ success: true, message: 'Stock request declined', data });
        } catch (e) { next(e); }
    }

    async cancelStockRequest(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.stockTransfers.cancel(req.params.transferId as string, req.user.userId, req.body?.reason);
            res.status(StatusCodes.OK).json({ success: true, message: 'Stock request cancelled', data });
        } catch (e) { next(e); }
    }

    async recordStockExpense(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.stockTransfers.recordExpense(req.params.transferId as string, req.user.userId, req.body);
            res.status(StatusCodes.CREATED).json({ success: true, message: 'Stock expense recorded', data });
        } catch (e) { next(e); }
    }

    async recordStockIncome(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.stockTransfers.recordIncome(req.params.transferId as string, req.user.userId, req.body);
            res.status(StatusCodes.CREATED).json({ success: true, message: 'Stock income recorded', data });
        } catch (e) { next(e); }
    }

    // ─── Rental agreements ──────────────────────────────
    async proposeAgreement(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.rentalAgreements.create(
                req.params.workspaceId as string,
                req.params.itemId as string,
                req.user.userId,
                req.body,
            );
            res.status(StatusCodes.CREATED).json({ success: true, message: 'Rental agreement offered', data });
        } catch (e) { next(e); }
    }

    async listAgreements(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.rentalAgreements.list(req.user.userId, req.query as any);
            res.status(StatusCodes.OK).json({ success: true, message: 'Agreements retrieved', ...result });
        } catch (e) { next(e); }
    }

    async getAgreement(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.rentalAgreements.getForUser(req.params.agreementId as string, req.user.userId);
            res.status(StatusCodes.OK).json({ success: true, message: 'Agreement retrieved', data });
        } catch (e) { next(e); }
    }

    async agreementAcceptanceOptions(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.rentalAgreements.getAcceptanceOptions(req.params.agreementId as string, req.user.userId);
            res.status(StatusCodes.OK).json({ success: true, message: 'Acceptance options retrieved', data });
        } catch (e) { next(e); }
    }

    async acceptAgreement(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.rentalAgreements.accept(req.params.agreementId as string, req.user.userId, req.body);
            res.status(StatusCodes.OK).json({ success: true, message: 'Agreement accepted — the items are now out on rental', data });
        } catch (e) { next(e); }
    }

    async declineAgreement(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.rentalAgreements.decline(req.params.agreementId as string, req.user.userId, req.body?.reason);
            res.status(StatusCodes.OK).json({ success: true, message: 'Agreement declined', data });
        } catch (e) { next(e); }
    }

    async cancelAgreement(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.rentalAgreements.cancel(req.params.agreementId as string, req.user.userId, req.body?.reason);
            res.status(StatusCodes.OK).json({ success: true, message: 'Agreement cancelled', data });
        } catch (e) { next(e); }
    }

    async recordAgreementIncome(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.rentalAgreements.recordLenderIncome(req.params.agreementId as string, req.user.userId, req.body);
            res.status(StatusCodes.CREATED).json({ success: true, message: 'Rental income recorded', data });
        } catch (e) { next(e); }
    }

    async recordAgreementExpense(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.rentalAgreements.recordBorrowerExpense(req.params.agreementId as string, req.user.userId, req.body);
            res.status(StatusCodes.CREATED).json({ success: true, message: 'Rental expense recorded', data });
        } catch (e) { next(e); }
    }
}

export const agreementsRouter = Router({ mergeParams: true });
const controller = container.resolve(AgreementsController);

agreementsRouter.use(authenticate as any);

// ─── Proposal (workspace-scoped: the request/offer originates here) ──

agreementsRouter.post('/stock-requests',
    requireWorkspaceMember(WorkspacePermission.MANAGE_INVENTORY) as any,
    idempotency('POST /agreements/stock-requests') as any,
    validate(createStockRequestSchema),
    controller.createStockRequest.bind(controller) as any,
);

agreementsRouter.post('/rental-agreements/:itemId',
    requireWorkspaceMember(WorkspacePermission.MANAGE_INVENTORY) as any,
    idempotency('POST /agreements/rental-agreements/:itemId') as any,
    validate(createRentalAgreementSchema),
    controller.proposeAgreement.bind(controller) as any,
);

// ─── Person-scoped stock request surface ───────────────

agreementsRouter.get('/stock-requests',
    validate(stockTransferQuerySchema, 'query'),
    controller.listStockRequests.bind(controller) as any,
);

agreementsRouter.get('/stock-requests/:transferId',
    controller.getStockRequest.bind(controller) as any,
);

agreementsRouter.get('/stock-requests/:transferId/send-options',
    controller.getSendOptions.bind(controller) as any,
);

agreementsRouter.post('/stock-requests/:transferId/send',
    idempotency('POST /agreements/stock-requests/:transferId/send') as any,
    validate(respondStockRequestSchema),
    controller.sendStock.bind(controller) as any,
);

agreementsRouter.post('/stock-requests/:transferId/receive',
    idempotency('POST /agreements/stock-requests/:transferId/receive') as any,
    controller.receiveStock.bind(controller) as any,
);

agreementsRouter.post('/stock-requests/:transferId/decline',
    validate(reasonSchema),
    controller.declineStockRequest.bind(controller) as any,
);

agreementsRouter.post('/stock-requests/:transferId/cancel',
    validate(reasonSchema),
    controller.cancelStockRequest.bind(controller) as any,
);

agreementsRouter.post('/stock-requests/:transferId/record-expense',
    idempotency('POST /agreements/stock-requests/:transferId/record-expense') as any,
    validate(recordTransferEntrySchema),
    controller.recordStockExpense.bind(controller) as any,
);

agreementsRouter.post('/stock-requests/:transferId/record-income',
    idempotency('POST /agreements/stock-requests/:transferId/record-income') as any,
    validate(recordTransferEntrySchema),
    controller.recordStockIncome.bind(controller) as any,
);

// ─── Person-scoped rental agreement surface ────────────

agreementsRouter.get('/rental-agreements',
    validate(rentalAgreementQuerySchema, 'query'),
    controller.listAgreements.bind(controller) as any,
);

agreementsRouter.get('/rental-agreements/:agreementId',
    controller.getAgreement.bind(controller) as any,
);

agreementsRouter.get('/rental-agreements/:agreementId/acceptance-options',
    controller.agreementAcceptanceOptions.bind(controller) as any,
);

agreementsRouter.post('/rental-agreements/:agreementId/accept',
    idempotency('POST /agreements/rental-agreements/:agreementId/accept') as any,
    validate(respondRentalAgreementSchema),
    controller.acceptAgreement.bind(controller) as any,
);

agreementsRouter.post('/rental-agreements/:agreementId/decline',
    validate(reasonSchema),
    controller.declineAgreement.bind(controller) as any,
);

agreementsRouter.post('/rental-agreements/:agreementId/cancel',
    validate(reasonSchema),
    controller.cancelAgreement.bind(controller) as any,
);

agreementsRouter.post('/rental-agreements/:agreementId/record-income',
    idempotency('POST /agreements/rental-agreements/:agreementId/record-income') as any,
    validate(recordAgreementExpenseSchema),
    controller.recordAgreementIncome.bind(controller) as any,
);

agreementsRouter.post('/rental-agreements/:agreementId/record-expense',
    idempotency('POST /agreements/rental-agreements/:agreementId/record-expense') as any,
    validate(recordAgreementExpenseSchema),
    controller.recordAgreementExpense.bind(controller) as any,
);

container.registerSingleton(StockTransfersService);
container.registerSingleton(RentalAgreementsService);

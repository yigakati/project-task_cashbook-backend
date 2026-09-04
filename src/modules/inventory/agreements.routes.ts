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
    createStockTransferSchema, respondStockTransferSchema, stockTransferQuerySchema,
    createRentalAgreementSchema, respondRentalAgreementSchema, rentalAgreementQuerySchema,
    recordAgreementExpenseSchema,
    reasonSchema,
} from './agreements.dto';

/**
 * Cross-workspace agreements — stock transfers and rental loans between two
 * platform users. Proposal routes are workspace-scoped (the goods must be
 * the sender's to promise); everything after is person-scoped, like peer
 * links, because the recipient's decision belongs to them personally, not to
 * whichever workspace they happen to be viewing.
 */

@injectable()
class AgreementsController {
    constructor(
        private stockTransfers: StockTransfersService,
        private rentalAgreements: RentalAgreementsService,
    ) { }

    // ─── Stock transfers ────────────────────────────────
    async proposeTransfer(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.stockTransfers.create(
                req.params.workspaceId as string,
                req.params.itemId as string,
                req.user.userId,
                req.body,
            );
            res.status(StatusCodes.CREATED).json({ success: true, message: 'Stock transfer proposed', data });
        } catch (e) { next(e); }
    }

    async listTransfers(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.stockTransfers.list(req.user.userId, req.query as any);
            res.status(StatusCodes.OK).json({ success: true, message: 'Transfers retrieved', ...result });
        } catch (e) { next(e); }
    }

    async getTransfer(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.stockTransfers.getForUser(req.params.transferId as string, req.user.userId);
            res.status(StatusCodes.OK).json({ success: true, message: 'Transfer retrieved', data });
        } catch (e) { next(e); }
    }

    async transferAcceptanceOptions(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.stockTransfers.getAcceptanceOptions(req.params.transferId as string, req.user.userId);
            res.status(StatusCodes.OK).json({ success: true, message: 'Acceptance options retrieved', data });
        } catch (e) { next(e); }
    }

    async acceptTransfer(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.stockTransfers.accept(req.params.transferId as string, req.user.userId, req.body);
            res.status(StatusCodes.OK).json({ success: true, message: 'Stock transferred', data });
        } catch (e) { next(e); }
    }

    async declineTransfer(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.stockTransfers.decline(req.params.transferId as string, req.user.userId, req.body?.reason);
            res.status(StatusCodes.OK).json({ success: true, message: 'Transfer declined', data });
        } catch (e) { next(e); }
    }

    async cancelTransfer(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.stockTransfers.cancel(req.params.transferId as string, req.user.userId, req.body?.reason);
            res.status(StatusCodes.OK).json({ success: true, message: 'Transfer cancelled', data });
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

    async recordAgreementIncome(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.rentalAgreements.recordLenderIncome(
                req.params.agreementId as string,
                req.user.userId,
                req.body,
            );
            res.status(StatusCodes.CREATED).json({ success: true, message: 'Rental income recorded', data });
        } catch (e) { next(e); }
    }

    async recordAgreementExpense(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.rentalAgreements.recordBorrowerExpense(
                req.params.agreementId as string,
                req.user.userId,
                req.body,
            );
            res.status(StatusCodes.CREATED).json({ success: true, message: 'Rental expense recorded', data });
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
}

/*
 * Mounted TWICE in routes/index.ts: at /agreements (person-scoped inbox)
 * and /workspaces/:workspaceId/agreements (proposals — the guard needs the
 * workspace param). mergeParams lets the workspace-scoped mount feed
 * requireWorkspaceMember; the bare mount simply never has it.
 */
export const agreementsRouter = Router({ mergeParams: true });
const controller = container.resolve(AgreementsController);

agreementsRouter.use(authenticate as any);

// ─── Proposal (workspace-scoped: the goods must be the sender's) ──

agreementsRouter.post('/stock-transfers/:itemId',
    requireWorkspaceMember(WorkspacePermission.MANAGE_INVENTORY) as any,
    idempotency('POST /agreements/stock-transfers/:itemId') as any,
    validate(createStockTransferSchema),
    controller.proposeTransfer.bind(controller) as any,
);

agreementsRouter.post('/rental-agreements/:itemId',
    requireWorkspaceMember(WorkspacePermission.MANAGE_INVENTORY) as any,
    idempotency('POST /agreements/rental-agreements/:itemId') as any,
    validate(createRentalAgreementSchema),
    controller.proposeAgreement.bind(controller) as any,
);

// ─── Person-scoped agreement surface ───────────────────

agreementsRouter.get('/stock-transfers',
    validate(stockTransferQuerySchema, 'query'),
    controller.listTransfers.bind(controller) as any,
);

agreementsRouter.get('/stock-transfers/:transferId',
    controller.getTransfer.bind(controller) as any,
);

agreementsRouter.get('/stock-transfers/:transferId/acceptance-options',
    controller.transferAcceptanceOptions.bind(controller) as any,
);

agreementsRouter.post('/stock-transfers/:transferId/accept',
    idempotency('POST /agreements/stock-transfers/:transferId/accept') as any,
    validate(respondStockTransferSchema),
    controller.acceptTransfer.bind(controller) as any,
);

agreementsRouter.post('/stock-transfers/:transferId/decline',
    validate(reasonSchema),
    controller.declineTransfer.bind(controller) as any,
);

agreementsRouter.post('/stock-transfers/:transferId/cancel',
    validate(reasonSchema),
    controller.cancelTransfer.bind(controller) as any,
);

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

// The lender records the rental income in their own workspace.
agreementsRouter.post('/rental-agreements/:agreementId/record-income',
    idempotency('POST /agreements/rental-agreements/:agreementId/record-income') as any,
    validate(recordAgreementExpenseSchema),
    controller.recordAgreementIncome.bind(controller) as any,
);

// The borrower records the rental cost as an expense in their accepted
// workspace. Person-scoped like the rest of the agreement surface.
agreementsRouter.post('/rental-agreements/:agreementId/record-expense',
    idempotency('POST /agreements/rental-agreements/:agreementId/record-expense') as any,
    validate(recordAgreementExpenseSchema),
    controller.recordAgreementExpense.bind(controller) as any,
);

agreementsRouter.post('/rental-agreements/:agreementId/decline',
    validate(reasonSchema),
    controller.declineAgreement.bind(controller) as any,
);

agreementsRouter.post('/rental-agreements/:agreementId/cancel',
    validate(reasonSchema),
    controller.cancelAgreement.bind(controller) as any,
);

container.registerSingleton(StockTransfersService);
container.registerSingleton(RentalAgreementsService);

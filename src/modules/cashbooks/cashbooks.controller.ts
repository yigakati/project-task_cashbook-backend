import { injectable } from 'tsyringe';
import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { CashbooksService } from './cashbooks.service';
import { AuthenticatedRequest, ApiResponse, WorkspaceRole } from '../../core/types';

@injectable()
export class CashbooksController {
    constructor(private cashbooksService: CashbooksService) { }

    async getAll(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const cashbooks = await this.cashbooksService.getCashbooks(
                req.params.workspaceId as string,
                req.user.userId,
                (req as { workspaceRole?: WorkspaceRole }).workspaceRole,
                req.query.includeArchived === 'true',
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Cashbooks retrieved successfully',
                data: cashbooks,
            });
        } catch (error) {
            next(error);
        }
    }

    async getOne(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const cashbook = await this.cashbooksService.getCashbook(req.params.cashbookId as string);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Cashbook retrieved successfully',
                data: cashbook,
            });
        } catch (error) {
            next(error);
        }
    }

    async create(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const cashbook = await this.cashbooksService.createCashbook(
                req.params.workspaceId as string,
                req.user.userId,
                req.body
            );
            res.status(StatusCodes.CREATED).json({
                success: true,
                message: 'Cashbook created successfully',
                data: cashbook,
            });
        } catch (error) {
            next(error);
        }
    }

    async update(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const cashbook = await this.cashbooksService.updateCashbook(
                req.params.cashbookId as string,
                req.user.userId,
                req.body
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Cashbook updated successfully',
                data: cashbook,
            });
        } catch (error) {
            next(error);
        }
    }

    async activateIntegration(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.cashbooksService.activateIntegration(
                req.params.cashbookId as string,
                req.params.workspaceId as string,
                req.user.userId,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: result.activated
                    ? 'Integration activated for this cashbook'
                    : 'Integration is already active for this cashbook',
                data: result,
            });
        } catch (error) {
            next(error);
        }
    }

    async delete(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.cashbooksService.deleteCashbook(req.params.cashbookId as string, req.user.userId);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Cashbook deleted successfully',
            });
        } catch (error) {
            next(error);
        }
    }

    async archive(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const { archive } = req.body as { archive: boolean };
            const cashbook = await this.cashbooksService.setArchived(
                req.params.cashbookId as string,
                req.user.userId,
                archive,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: archive
                    ? 'Book archived. Its history is kept and you can restore it any time.'
                    : 'Book restored.',
                data: cashbook,
            });
        } catch (error) {
            next(error);
        }
    }

    // ─── Members ───────────────────────────────────────
    async getMembers(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const members = await this.cashbooksService.getCashbookMembers(req.params.cashbookId as string);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Cashbook members retrieved',
                data: members,
            });
        } catch (error) {
            next(error);
        }
    }

    async addMember(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const member = await this.cashbooksService.addCashbookMember(
                req.params.cashbookId as string,
                req.user.userId,
                req.body
            );
            res.status(StatusCodes.CREATED).json({
                success: true,
                message: 'Member added to cashbook',
                data: member,
            });
        } catch (error) {
            next(error);
        }
    }

    async updateMemberRole(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const member = await this.cashbooksService.updateCashbookMemberRole(
                req.params.cashbookId as string,
                req.params.userId as string,
                req.user.userId,
                req.body
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Member role updated',
                data: member,
            });
        } catch (error) {
            next(error);
        }
    }

    async removeMember(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.cashbooksService.removeCashbookMember(
                req.params.cashbookId as string,
                req.params.userId as string,
                req.user.userId
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Member removed from cashbook',
            });
        } catch (error) {
            next(error);
        }
    }

    // ─── Financial Summary ─────────────────────────────
    async getSummary(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const summary = await this.cashbooksService.getFinancialSummary(req.params.cashbookId as string);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Financial summary retrieved',
                data: summary,
            });
        } catch (error) {
            next(error);
        }
    }

    // ─── Balance Recalculation ────────────────────────
    async recalculateBalance(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.cashbooksService.recalculateBalance(
                req.params.cashbookId as string,
                req.user.userId
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Balance recalculated successfully',
                data: result,
            });
        } catch (error) {
            next(error);
        }
    }

    // ─── Reconciliation Toggle ────────────────────────
    async toggleReconciliation(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.cashbooksService.toggleReconciliation(
                req.params.entryId as string,
                req.params.cashbookId as string,
                req.user.userId
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: `Entry ${result.isReconciled ? 'reconciled' : 'unreconciled'}`,
                data: result,
            });
        } catch (error) {
            next(error);
        }
    }
}

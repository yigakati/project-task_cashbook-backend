import { Response, NextFunction } from 'express';
import { injectable } from 'tsyringe';
import { ObligationsService } from './obligations.service';
import { AuthenticatedRequest } from '../../core/types';
import { StatusCodes } from 'http-status-codes';
import { ApiResponse } from '../../core/types';

@injectable()
export class ObligationsController {
    constructor(private obligationsService: ObligationsService) { }

    async getObligations(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const { cashbookId } = req.params;
            const result = await this.obligationsService.getObligations(cashbookId as string, req.query as any, req.cashbookRole!);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Obligations retrieved successfully',
                data: result.data,
                pagination: result.pagination
            });
        } catch (error) {
            next(error);
        }
    }

    async getObligation(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.obligationsService.getObligation(req.params.id as string, req.cashbookRole!);
            res.status(StatusCodes.OK).json({ success: true, data: result } as ApiResponse);
        } catch (error) {
            next(error);
        }
    }

    async createObligation(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const { cashbookId } = req.params;
            const result = await this.obligationsService.createObligation(cashbookId as string, req.user!.userId, req.body, req.cashbookRole!);
            res.status(StatusCodes.CREATED).json({
                success: true,
                message: 'Obligation created successfully',
                data: result
            });
        } catch (error) {
            next(error);
        }
    }

    async updateObligation(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.obligationsService.updateObligation(req.params.id as string, req.user!.userId, req.body, req.cashbookRole!);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Obligation updated successfully',
                data: result
            });
        } catch (error) {
            next(error);
        }
    }

    async archiveObligation(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.obligationsService.archiveObligation(req.params.id as string, req.user!.userId, req.cashbookRole!);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Obligation archived successfully'
            });
        } catch (error) {
            next(error);
        }
    }

    async getOutstandingReceivables(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.obligationsService.getOutstandingReceivables(req.params.cashbookId as string, req.cashbookRole!);
            res.status(StatusCodes.OK).json({ success: true, data: result } as ApiResponse);
        } catch (error) {
            next(error);
        }
    }

    async getOutstandingPayables(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.obligationsService.getOutstandingPayables(req.params.cashbookId as string, req.cashbookRole!);
            res.status(StatusCodes.OK).json({ success: true, data: result } as ApiResponse);
        } catch (error) {
            next(error);
        }
    }
}

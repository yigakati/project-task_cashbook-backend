import { Request, Response, NextFunction } from 'express';
import { injectable } from 'tsyringe';
import { AccountTransactionsService } from './account-transactions.service';
import { AuthenticatedRequest } from '../../core/types';
import { StatusCodes } from 'http-status-codes';

@injectable()
export class AccountTransactionsController {
    constructor(private service: AccountTransactionsService) { }

    async getAllTransactions(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const page = parseInt(req.query.page as string) || 1;
            const limit = parseInt(req.query.limit as string) || 50;
            const skip = (page - 1) * limit;

            const [total, data] = await this.service.getAllTransactionsByAccount(
                req.params.accountId as string,
                req.params.workspaceId as string,
                { skip, take: limit }
            );

            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Account transactions retrieved successfully',
                data,
                pagination: {
                    page,
                    limit,
                    total,
                    totalPages: Math.ceil(total / limit),
                    hasNext: page * limit < total,
                    hasPrevious: page > 1
                }
            });
        } catch (error) {
            next(error);
        }
    }

    async create(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.createDirectTransaction(
                req.params.workspaceId as string,
                req.params.accountId as string,
                req.user.userId,
                req.body
            );
            res.status(StatusCodes.CREATED).json({
                success: true,
                message: 'Account transaction created successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async update(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.updateDirectTransaction(
                req.params.id as string,
                req.params.workspaceId as string,
                req.params.accountId as string,
                req.user.userId,
                req.body
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Account transaction updated successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async delete(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.service.deleteDirectTransaction(
                req.params.id as string,
                req.params.workspaceId as string,
                req.params.accountId as string,
                req.user.userId
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Account transaction deleted successfully',
            });
        } catch (error) {
            next(error);
        }
    }
}

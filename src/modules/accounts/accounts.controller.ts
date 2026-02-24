import { injectable } from 'tsyringe';
import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { AccountsService } from './accounts.service';
import { AuthenticatedRequest } from '../../core/types';

@injectable()
export class AccountsController {
    constructor(private service: AccountsService) { }

    async create(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.createAccount(req.params.workspaceId as string, req.user.userId, req.body);
            res.status(StatusCodes.CREATED).json({
                success: true,
                message: 'Account created successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async getAll(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getWorkspaceAccounts(req.params.workspaceId as string);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Accounts retrieved successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async getById(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getAccountById(req.params.id as string, req.params.workspaceId as string);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Account retrieved successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async update(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.updateAccount(req.params.id as string, req.params.workspaceId as string, req.user.userId, req.body);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Account updated successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async archive(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.setAccountArchiveStatus(req.params.id as string, req.params.workspaceId as string, req.user.userId, req.body);
            res.status(StatusCodes.OK).json({
                success: true,
                message: data.archivedAt ? 'Account archived successfully' : 'Account unarchived successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async delete(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.service.deleteAccount(req.params.id as string, req.params.workspaceId as string, req.user.userId);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Account deleted successfully',
            });
        } catch (error) {
            next(error);
        }
    }

    async getNetWorth(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.calculateNetWorth(req.params.workspaceId as string);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Net worth calculated successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }
}

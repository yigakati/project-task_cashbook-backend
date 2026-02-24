import { injectable } from 'tsyringe';
import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { AccountCategoriesService } from './account-categories.service';
import { AuthenticatedRequest } from '../../core/types';

@injectable()
export class AccountCategoriesController {
    constructor(private service: AccountCategoriesService) { }

    async create(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.createCategory(req.params.workspaceId as string, req.user.userId, req.body);
            res.status(StatusCodes.CREATED).json({
                success: true,
                message: 'Account category created successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async getAll(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getWorkspaceCategories(req.params.workspaceId as string);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Account categories retrieved successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async update(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.updateCategory(req.params.id as string, req.params.workspaceId as string, req.user.userId, req.body);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Account category updated successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async delete(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.service.deleteCategory(req.params.id as string, req.params.workspaceId as string, req.user.userId);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Account category deleted successfully',
            });
        } catch (error) {
            next(error);
        }
    }
}

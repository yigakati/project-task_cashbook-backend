import { injectable } from 'tsyringe';
import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { AccountTypesService } from './account-types.service';
import { AuthenticatedRequest } from '../../core/types';

@injectable()
export class AccountTypesController {
    constructor(private service: AccountTypesService) { }

    async create(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.createAccountType(req.params.workspaceId as string, req.user.userId, req.body);
            res.status(StatusCodes.CREATED).json({
                success: true,
                message: 'Account type created successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async getAll(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getWorkspaceAccountTypes(req.params.workspaceId as string);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Account types retrieved successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async update(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.updateAccountType(req.params.id as string, req.params.workspaceId as string, req.user.userId, req.body);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Account type updated successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async delete(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.service.deleteAccountType(req.params.id as string, req.params.workspaceId as string, req.user.userId);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Account type deleted successfully',
            });
        } catch (error) {
            next(error);
        }
    }
}

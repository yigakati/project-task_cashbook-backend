import { injectable } from 'tsyringe';
import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { WorkspaceProfileService } from './workspace-profile.service';
import { AuthenticatedRequest, ApiResponse } from '../../core/types';

@injectable()
export class WorkspaceProfileController {
    constructor(private service: WorkspaceProfileService) { }

    async get(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getProfile(req.params.workspaceId as string);
            const response: ApiResponse = {
                success: true,
                message: 'Workspace details retrieved successfully',
                data,
            };
            res.status(StatusCodes.OK).json(response);
        } catch (error) {
            next(error);
        }
    }

    async update(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.updateProfile(
                req.params.workspaceId as string,
                req.user.userId,
                req.body,
            );
            const response: ApiResponse = {
                success: true,
                message: 'Workspace details updated',
                data,
            };
            res.status(StatusCodes.OK).json(response);
        } catch (error) {
            next(error);
        }
    }
}

import { injectable } from 'tsyringe';
import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { ReferralsService } from './referrals.service';
import { AuthenticatedRequest, ApiResponse } from '../../core/types';

@injectable()
export class ReferralsController {
    constructor(private service: ReferralsService) { }

    async getOverview(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getAgentOverview(
                req.params.workspaceId as string,
                req.user.userId,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Referrals retrieved successfully',
                data,
            } satisfies ApiResponse);
        } catch (error) {
            next(error);
        }
    }
}

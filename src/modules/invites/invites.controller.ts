import { injectable } from 'tsyringe';
import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { InvitesService } from './invites.service';
import { AuthenticatedRequest, ApiResponse } from '../../core/types';

@injectable()
export class InvitesController {
    constructor(private invitesService: InvitesService) { }

    async getPendingInvites(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const invites = await this.invitesService.getPendingInvites(req.user.email);

            const response: ApiResponse = {
                success: true,
                message: invites.length > 0
                    ? `You have ${invites.length} pending invitation(s)`
                    : 'No pending invitations',
                data: invites,
            };

            res.status(StatusCodes.OK).json(response);
        } catch (error) {
            next(error);
        }
    }

    async acceptInvite(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const member = await this.invitesService.acceptInvite(
                req.params.inviteId as string,
                req.user.userId,
                req.user.email
            );

            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Invitation accepted successfully',
                data: member,
            });
        } catch (error) {
            next(error);
        }
    }

    async declineInvite(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.invitesService.declineInvite(
                req.params.inviteId as string,
                req.user.email
            );

            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Invitation declined successfully',
                data: null,
            });
        } catch (error) {
            next(error);
        }
    }
}

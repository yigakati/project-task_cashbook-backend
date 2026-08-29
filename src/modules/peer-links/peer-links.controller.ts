import { Response, NextFunction } from 'express';
import { injectable } from 'tsyringe';
import { PeerLinksService } from './peer-links.service';
import { AuthenticatedRequest } from '../../core/types';
import { StatusCodes } from 'http-status-codes';

@injectable()
export class PeerLinksController {
    constructor(private peerLinksService: PeerLinksService) { }

    async createPeerLink(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const { cashbookId } = req.params;
            const result = await this.peerLinksService.createPeerLink(
                cashbookId as string,
                req.user!.userId,
                req.body,
            );
            res.status(StatusCodes.CREATED).json({
                success: true,
                message: 'Peer Link proposal sent. Nothing is recorded until they accept.',
                data: result,
            });
        } catch (error) {
            next(error);
        }
    }

    async getPeerLinks(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.peerLinksService.getPeerLinks(req.user!.userId, req.query as any);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Peer Links retrieved successfully',
                ...result,
            });
        } catch (error) {
            next(error);
        }
    }

    async getPeerLink(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const { peerLinkId } = req.params;
            const result = await this.peerLinksService.getPeerLinkForUser(peerLinkId as string, req.user!.userId);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Peer Link retrieved successfully',
                data: result,
            });
        } catch (error) {
            next(error);
        }
    }

    async getAcceptableCashbooks(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const { peerLinkId } = req.params;
            const result = await this.peerLinksService.getAcceptableCashbooks(
                peerLinkId as string,
                req.user!.userId,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Acceptable cashbooks retrieved successfully',
                data: result,
            });
        } catch (error) {
            next(error);
        }
    }

    async acceptPeerLink(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const { peerLinkId } = req.params;
            const result = await this.peerLinksService.acceptPeerLink(
                peerLinkId as string,
                req.user!.userId,
                req.body,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Peer Link accepted — the loan is now recorded on both books',
                data: result,
            });
        } catch (error) {
            next(error);
        }
    }

    async declinePeerLink(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const { peerLinkId } = req.params;
            const result = await this.peerLinksService.declinePeerLink(
                peerLinkId as string,
                req.user!.userId,
                req.body,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Peer Link declined',
                data: result,
            });
        } catch (error) {
            next(error);
        }
    }

    async cancelPeerLink(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const { peerLinkId } = req.params;
            const result = await this.peerLinksService.cancelPeerLink(
                peerLinkId as string,
                req.user!.userId,
                req.body,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Peer Link cancelled',
                data: result,
            });
        } catch (error) {
            next(error);
        }
    }

    async decideSettlement(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const { settlementId } = req.params;
            const result = await this.peerLinksService.decideSettlement(
                settlementId as string,
                req.user!.userId,
                req.body,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Settlement decision recorded',
                data: result,
            });
        } catch (error) {
            next(error);
        }
    }

    async lookupUser(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.peerLinksService.lookupUserByEmail((req.query as any).email);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'User found',
                data: result,
            });
        } catch (error) {
            next(error);
        }
    }

    async getWorkspaceObligations(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const { workspaceId } = req.params;
            const result = await this.peerLinksService.getWorkspaceObligations(
                workspaceId as string,
                req.user!.userId,
                (req as any).workspaceRole,
                req.query as any,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Obligations retrieved successfully',
                ...result,
            });
        } catch (error) {
            next(error);
        }
    }
}

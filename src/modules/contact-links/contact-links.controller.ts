import { injectable } from 'tsyringe';
import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { ContactLinksService } from './contact-links.service';
import { AuthenticatedRequest, ApiResponse } from '../../core/types';

@injectable()
export class ContactLinksController {
    constructor(private service: ContactLinksService) { }

    async lookup(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.lookupRecipient(
                req.params.workspaceId as string,
                req.user.userId,
                req.query.email as string,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Lookup complete',
                data,
            } satisfies ApiResponse);
        } catch (error) {
            next(error);
        }
    }

    async createRequest(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.createRequest(
                req.params.workspaceId as string,
                req.user.userId,
                req.body,
            );
            res.status(StatusCodes.CREATED).json({
                success: true,
                message: 'Request sent. They choose which of their workspaces to share.',
                data,
            } satisfies ApiResponse);
        } catch (error) {
            next(error);
        }
    }

    async getOutgoing(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getOutgoing(
                req.params.workspaceId as string,
                req.query as any,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Requests retrieved successfully',
                data,
            } satisfies ApiResponse);
        } catch (error) {
            next(error);
        }
    }

    async cancelRequest(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.cancelRequest(
                req.params.workspaceId as string,
                req.params.requestId as string,
                req.user.userId,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Request cancelled',
                data,
            } satisfies ApiResponse);
        } catch (error) {
            next(error);
        }
    }

    async unlink(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.unlinkContact(
                req.params.workspaceId as string,
                req.params.contactId as string,
                req.user.userId,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Disconnected. You keep the details you already have.',
                data,
            } satisfies ApiResponse);
        } catch (error) {
            next(error);
        }
    }

    // ─── Person-scoped inbox ───────────────────────────

    async getIncoming(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getIncoming(req.user.userId, req.query as any);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Requests retrieved successfully',
                data,
            } satisfies ApiResponse);
        } catch (error) {
            next(error);
        }
    }

    async accept(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.acceptRequest(
                req.params.requestId as string,
                req.user.userId,
                req.body,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Connected',
                data,
            } satisfies ApiResponse);
        } catch (error) {
            next(error);
        }
    }

    async decline(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.declineRequest(
                req.params.requestId as string,
                req.user.userId,
                req.body,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Request declined',
                data,
            } satisfies ApiResponse);
        } catch (error) {
            next(error);
        }
    }
}

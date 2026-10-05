import { injectable } from 'tsyringe';
import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { TargetsService, Viewer } from './targets.service';
import { AuthenticatedRequest } from '../../core/types';

const viewer = (req: AuthenticatedRequest): Viewer => ({
    userId: req.user.userId,
    role: req.workspaceRole,
});

@injectable()
export class TargetsController {
    constructor(private service: TargetsService) { }

    async list(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const result = await this.service.list(req.params.workspaceId as string, viewer(req), req.query as never);
            res.status(StatusCodes.OK).json({ success: true, message: 'Targets retrieved', ...result });
        } catch (error) { next(error); }
    }

    async get(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.get(req.params.workspaceId as string, req.params.targetId as string, viewer(req));
            res.status(StatusCodes.OK).json({ success: true, message: 'Target retrieved', data });
        } catch (error) { next(error); }
    }

    async create(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.create(req.params.workspaceId as string, req.user.userId, req.body);
            res.status(StatusCodes.CREATED).json({ success: true, message: 'Target created', data });
        } catch (error) { next(error); }
    }

    async update(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.update(
                req.params.workspaceId as string, req.params.targetId as string, req.user.userId, req.body,
            );
            res.status(StatusCodes.OK).json({ success: true, message: 'Target updated', data });
        } catch (error) { next(error); }
    }

    async archive(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.setArchived(
                req.params.workspaceId as string, req.params.targetId as string, req.user.userId, true,
            );
            res.status(StatusCodes.OK).json({ success: true, message: 'Target archived', data });
        } catch (error) { next(error); }
    }

    async restore(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.setArchived(
                req.params.workspaceId as string, req.params.targetId as string, req.user.userId, false,
            );
            res.status(StatusCodes.OK).json({ success: true, message: 'Target restored', data });
        } catch (error) { next(error); }
    }

    async remove(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            await this.service.remove(req.params.workspaceId as string, req.params.targetId as string, req.user.userId);
            res.status(StatusCodes.OK).json({ success: true, message: 'Target deleted' });
        } catch (error) { next(error); }
    }

    async listContributions(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const result = await this.service.listContributions(
                req.params.workspaceId as string, req.params.targetId as string, viewer(req), req.query as never,
            );
            res.status(StatusCodes.OK).json({ success: true, message: 'Records retrieved', ...result });
        } catch (error) { next(error); }
    }

    async recordContribution(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.recordContribution(
                req.params.workspaceId as string, req.params.targetId as string, viewer(req), req.body,
            );
            res.status(StatusCodes.CREATED).json({ success: true, message: 'Amount recorded', data });
        } catch (error) { next(error); }
    }

    async updateContribution(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.updateContribution(
                req.params.workspaceId as string, req.params.targetId as string, req.params.contributionId as string,
                viewer(req), req.body,
            );
            res.status(StatusCodes.OK).json({ success: true, message: 'Record updated', data });
        } catch (error) { next(error); }
    }

    async deleteContribution(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            await this.service.deleteContribution(
                req.params.workspaceId as string, req.params.targetId as string, req.params.contributionId as string, viewer(req),
            );
            res.status(StatusCodes.OK).json({ success: true, message: 'Record deleted' });
        } catch (error) { next(error); }
    }
}

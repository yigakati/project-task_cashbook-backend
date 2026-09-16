import { injectable } from 'tsyringe';
import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { StorageQuotaService } from './storage-quota.service';
import { AuthenticatedRequest } from '../../core/types';

const paginated = (result: { data: unknown; total: number; page: number; limit: number }) => ({
    data: result.data,
    pagination: {
        page: result.page,
        limit: result.limit,
        total: result.total,
        totalPages: Math.max(1, Math.ceil(result.total / result.limit)),
    },
});

@injectable()
export class StorageController {
    constructor(private service: StorageQuotaService) { }

    async overview(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.getOverview(req.params.workspaceId as string);
            res.status(StatusCodes.OK).json({ success: true, message: 'Storage retrieved', data });
        } catch (error) { next(error); }
    }

    async files(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const result = await this.service.listFiles(req.params.workspaceId as string, req.query as any);
            res.status(StatusCodes.OK).json({ success: true, message: 'Files retrieved', ...paginated(result) });
        } catch (error) { next(error); }
    }

    async createRequest(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.createRequest(req.params.workspaceId as string, req.user.userId, req.body);
            res.status(StatusCodes.CREATED).json({
                success: true,
                message: 'Request sent. A superadmin will review it.',
                data,
            });
        } catch (error) { next(error); }
    }

    async cancelRequest(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.cancelRequest(
                req.params.workspaceId as string, req.params.requestId as string, req.user.userId,
            );
            res.status(StatusCodes.OK).json({ success: true, message: 'Request cancelled', data });
        } catch (error) { next(error); }
    }

    // ─── Superadmin ────────────────────────────────────

    async listRequests(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const result = await this.service.listRequests(req.query as any);
            res.status(StatusCodes.OK).json({ success: true, message: 'Storage requests retrieved', ...paginated(result) });
        } catch (error) { next(error); }
    }

    async decideRequest(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.decideRequest(req.params.requestId as string, req.user.userId, req.body);
            res.status(StatusCodes.OK).json({
                success: true,
                message: data.status === 'APPROVED' ? 'Storage increased' : 'Request declined',
                data,
            });
        } catch (error) { next(error); }
    }

    async listWorkspaces(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const result = await this.service.listWorkspaceUsage(req.query as any);
            res.status(StatusCodes.OK).json({ success: true, message: 'Workspace storage retrieved', ...paginated(result) });
        } catch (error) { next(error); }
    }

    async setWorkspaceQuota(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.setWorkspaceQuota(
                req.params.workspaceId as string, req.body.quotaGb, req.user.userId,
            );
            res.status(StatusCodes.OK).json({ success: true, message: 'Storage allowance updated', data });
        } catch (error) { next(error); }
    }
}

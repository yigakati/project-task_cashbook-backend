import { injectable } from 'tsyringe';
import { Request, Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { AccountDeletionService } from './account-deletion.service';
import { AuthenticatedRequest } from '../../core/types';
import { config } from '../../config';

const meta = (req: Request) => ({
    ipAddress: req.ip,
    userAgent: req.get('user-agent') ?? undefined,
});

/** Same words whether or not the address has an account — see requestFromWeb. */
const WEB_ACKNOWLEDGEMENT =
    'If an account uses that address, we have emailed it a link to confirm the deletion. '
    + 'Nothing is deleted until that link is used.';

@injectable()
export class AccountDeletionController {
    constructor(private service: AccountDeletionService) { }

    // ─── The person, signed in ─────────────────────────

    async getMine(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.getForUser(req.user.userId);
            res.status(StatusCodes.OK).json({ success: true, message: 'Account deletion status', data });
        } catch (error) { next(error); }
    }

    async requestMine(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.requestFromApp(req.user.userId, req.body, meta(req));
            res.status(StatusCodes.OK).json({
                success: true,
                message: `Your account will be deleted after ${config.ACCOUNT_DELETION_GRACE_DAYS} days. `
                    + 'Sign in before then to cancel.',
                data,
            });
        } catch (error) { next(error); }
    }

    async cancelMine(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.cancelFromApp(req.user.userId, meta(req));
            res.status(StatusCodes.OK).json({ success: true, message: 'Account deletion cancelled', data });
        } catch (error) { next(error); }
    }

    // ─── The website, signed out ───────────────────────

    async requestFromWeb(req: Request, res: Response, next: NextFunction) {
        try {
            // A filled honeypot is a bot: answer exactly as for anyone else.
            if (!req.body.website) await this.service.requestFromWeb(req.body);
            res.status(StatusCodes.ACCEPTED).json({ success: true, message: WEB_ACKNOWLEDGEMENT });
        } catch (error) { next(error); }
    }

    async confirmFromWeb(req: Request, res: Response, next: NextFunction) {
        try {
            const data = await this.service.confirmFromWeb(req.body.token);
            res.status(StatusCodes.OK).json({
                success: true,
                message: data.status === 'SCHEDULED'
                    ? 'Account deletion confirmed'
                    : 'Account deletion is on hold',
                data,
            });
        } catch (error) { next(error); }
    }

    // ─── Superadmin ────────────────────────────────────

    async list(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const result = await this.service.list(req.query as never);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Account deletion requests',
                data: result.data,
                pagination: {
                    page: result.page,
                    limit: result.limit,
                    total: result.total,
                    totalPages: Math.max(1, Math.ceil(result.total / result.limit)),
                },
            });
        } catch (error) { next(error); }
    }

    async attentionCount(_req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const count = await this.service.attentionCount();
            res.status(StatusCodes.OK).json({ success: true, message: 'Requests needing attention', data: { count } });
        } catch (error) { next(error); }
    }

    async getOne(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.getForAdmin(req.params.requestId as string);
            res.status(StatusCodes.OK).json({ success: true, message: 'Account deletion request', data });
        } catch (error) { next(error); }
    }

    async processNow(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.processNow(req.params.requestId as string, req.user.userId);
            res.status(StatusCodes.OK).json({
                success: true,
                message: data.status === 'COMPLETED' ? 'Account deleted' : `Request is now ${data.status.toLowerCase()}`,
                data,
            });
        } catch (error) { next(error); }
    }

    async cancel(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.cancelByAdmin(req.params.requestId as string, req.user.userId, req.body.note);
            res.status(StatusCodes.OK).json({ success: true, message: 'Account deletion cancelled', data });
        } catch (error) { next(error); }
    }

    async scheduleForUser(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.scheduleForUser(req.params.userId as string, req.user.userId, req.body);
            res.status(StatusCodes.CREATED).json({ success: true, message: 'Account deletion scheduled', data });
        } catch (error) { next(error); }
    }
}

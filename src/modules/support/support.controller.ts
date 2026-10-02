import { injectable } from 'tsyringe';
import { Request, Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { SupportService } from './support.service';
import { AuthenticatedRequest } from '../../core/types';

@injectable()
export class SupportController {
    constructor(private service: SupportService) { }

    async submit(req: Request, res: Response, next: NextFunction) {
        try {
            // A filled honeypot is a bot: answer as for anyone else, store nothing.
            if (!req.body.website) await this.service.submit(req.body);
            res.status(StatusCodes.CREATED).json({
                success: true,
                message: 'Thanks — your message has reached our team. We reply by email.',
            });
        } catch (error) { next(error); }
    }

    async list(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const result = await this.service.list(req.query as never);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Contact messages',
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

    async openCount(_req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const count = await this.service.openCount();
            res.status(StatusCodes.OK).json({ success: true, message: 'Open messages', data: { count } });
        } catch (error) { next(error); }
    }

    async setStatus(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.service.setStatus(req.params.messageId as string, req.user.userId, req.body);
            res.status(StatusCodes.OK).json({ success: true, message: 'Message updated', data });
        } catch (error) { next(error); }
    }
}

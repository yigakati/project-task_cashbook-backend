import { injectable } from 'tsyringe';
import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { BillingService } from './billing.service';
import { AuthenticatedRequest } from '../../core/types';

/**
 * Public: the catalogue and a quote, so the pricing page works signed out.
 * Signed in: the account's current plan and checkout.
 */
@injectable()
export class BillingController {
    constructor(private billing: BillingService) { }

    async plans(_req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            res.status(StatusCodes.OK).json({ success: true, message: 'Plans retrieved', data: this.billing.catalogue() });
        } catch (error) { next(error); }
    }

    async quote(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const { plan, extraStorageGb } = req.query as unknown as { plan: never; extraStorageGb: number };
            res.status(StatusCodes.OK).json({ success: true, message: 'Quote', data: this.billing.quote(plan, extraStorageGb) });
        } catch (error) { next(error); }
    }

    async account(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.billing.account(req.user.userId);
            res.status(StatusCodes.OK).json({ success: true, message: 'Plan retrieved', data });
        } catch (error) { next(error); }
    }

    async checkout(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const data = await this.billing.checkout(req.user.userId, req.body);
            res.status(StatusCodes.OK).json({ success: true, message: 'Payment requested', data });
        } catch (error) { next(error); }
    }
}

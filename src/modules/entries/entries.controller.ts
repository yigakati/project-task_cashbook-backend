import { injectable } from 'tsyringe';
import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { EntriesService } from './entries.service';
import { AuthenticatedRequest, ApiResponse, CashbookRole } from '../../core/types';
import { CashbookPermission, hasPermission } from '../../core/types/permissions';

@injectable()
export class EntriesController {
    constructor(private entriesService: EntriesService) { }

    async getAll(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.entriesService.getEntries(req.params.cashbookId as string, req.query as any);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Entries retrieved successfully',
                ...result,
            });
        } catch (error) {
            next(error);
        }
    }

    async filterOptions(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            // Only someone who may see the book's members gets its full roster;
            // everyone else sees just the people whose entries they can see.
            const role = (req as { cashbookRole?: CashbookRole }).cashbookRole;
            const includeRoster = !!role && hasPermission(role, CashbookPermission.VIEW_MEMBERS);
            const data = await this.entriesService.getEntryFilterOptions(
                req.params.cashbookId as string,
                includeRoster,
            );
            res.status(StatusCodes.OK).json({ success: true, message: 'Filter options retrieved', data });
        } catch (error) {
            next(error);
        }
    }

    async getOne(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const entry = await this.entriesService.getEntry(req.params.entryId as string);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Entry retrieved successfully',
                data: entry,
            });
        } catch (error) {
            next(error);
        }
    }

    async create(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const entry = await this.entriesService.createEntry(
                req.params.cashbookId as string,
                req.user.userId,
                req.body
            );
            res.status(StatusCodes.CREATED).json({
                success: true,
                message: 'Entry created successfully',
                data: entry,
            });
        } catch (error) {
            next(error);
        }
    }

    async update(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const entry = await this.entriesService.updateEntry(
                req.params.entryId as string,
                req.user.userId,
                req.body
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Entry updated successfully',
                data: entry,
            });
        } catch (error) {
            next(error);
        }
    }

    /**
     * Move an entry into another book. Changes attribution, never money.
     */
    async reassign(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const entry = await this.entriesService.reassignEntry(
                req.params.entryId as string,
                req.user.userId,
                req.body,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Entry moved to the selected book',
                data: entry,
            });
        } catch (error) {
            next(error);
        }
    }

    async delete(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const cashbookRole = (req as any).cashbookRole as CashbookRole;
            const result = await this.entriesService.deleteEntry(
                req.params.entryId as string,
                req.user.userId,
                req.body.reason,
                cashbookRole
            );
            res.status(StatusCodes.OK).json({
                success: true,
                ...result,
            });
        } catch (error) {
            next(error);
        }
    }

    // ─── Delete Requests ───────────────────────────────
    async getDeleteRequests(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const status = req.query.status as string | undefined;
            const requests = await this.entriesService.getDeleteRequests(req.params.cashbookId as string, status);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Delete requests retrieved',
                data: requests,
            });
        } catch (error) {
            next(error);
        }
    }

    async reviewDeleteRequest(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.entriesService.reviewDeleteRequest(
                req.params.requestId as string,
                req.user.userId,
                req.body
            );
            res.status(StatusCodes.OK).json({
                success: true,
                ...result,
            });
        } catch (error) {
            next(error);
        }
    }

    // ─── Audit Trail ───────────────────────────────────
    async getAuditTrail(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const audits = await this.entriesService.getEntryAuditTrail(req.params.entryId as string);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Entry audit trail retrieved',
                data: audits,
            });
        } catch (error) {
            next(error);
        }
    }

    // ─── Receipts ──────────────────────────────────────
    /** The receipt as data, so the client can render and print it. */
    async receiptModel(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.entriesService.getReceiptModel(req.params.entryId as string);
            res.status(StatusCodes.OK).json({ success: true, message: 'Receipt', data });
        } catch (error) {
            next(error);
        }
    }

    async sendReceipt(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.entriesService.sendReceipt(req.params.entryId as string, req.user.userId);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Receipt sent successfully',
            });
        } catch (error) {
            next(error);
        }
    }
}

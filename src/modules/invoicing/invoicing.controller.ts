import { injectable } from 'tsyringe';
import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { Prisma } from '@prisma/client';
import { AppError } from '../../core/errors/AppError';
import { InvoicingService } from './invoicing.service';
import { AuthenticatedRequest } from '../../core/types';

@injectable()
export class InvoicingController {
    private invoiceError(error: unknown, next: NextFunction) {
        if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
            next(
                new AppError(
                    'That invoice number is already in use. Choose another number or retry automatic numbering.',
                    409,
                    'DUPLICATE_INVOICE_NUMBER',
                ),
            );
            return;
        }
        next(error);
    }
    constructor(private service: InvoicingService) {}

    // ─── CRUD ──────────────────────────────────────────

    async createInvoice(
        req: AuthenticatedRequest,
        res: Response,
        next: NextFunction,
    ): Promise<void> {
        try {
            const data = await this.service.createInvoice(
                req.params.workspaceId as string,
                req.user.userId,
                req.body,
            );
            res.status(StatusCodes.CREATED).json({
                success: true,
                message: 'Invoice created successfully',
                data,
            });
        } catch (error) {
            this.invoiceError(error, next);
        }
    }

    async updateInvoice(
        req: AuthenticatedRequest,
        res: Response,
        next: NextFunction,
    ): Promise<void> {
        try {
            const data = await this.service.updateInvoice(
                req.params.invoiceId as string,
                req.params.workspaceId as string,
                req.user.userId,
                req.body,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Invoice updated successfully',
                data,
            });
        } catch (error) {
            this.invoiceError(error, next);
        }
    }

    async getInvoice(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getInvoice(
                req.params.invoiceId as string,
                req.params.workspaceId as string,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Invoice retrieved successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async listInvoices(
        req: AuthenticatedRequest,
        res: Response,
        next: NextFunction,
    ): Promise<void> {
        try {
            const result = await this.service.listInvoices(
                req.params.workspaceId as string,
                req.query as any,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Invoices retrieved successfully',
                data: result.data,
                pagination: result.pagination,
            });
        } catch (error) {
            next(error);
        }
    }

    async deleteInvoice(
        req: AuthenticatedRequest,
        res: Response,
        next: NextFunction,
    ): Promise<void> {
        try {
            await this.service.deleteInvoice(
                req.params.invoiceId as string,
                req.params.workspaceId as string,
                req.user.userId,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Invoice deleted successfully',
            });
        } catch (error) {
            next(error);
        }
    }

    // ─── Actions ───────────────────────────────────────

    async sendInvoice(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.sendInvoice(
                req.params.invoiceId as string,
                req.params.workspaceId as string,
                req.user.userId,
                req.body,
            );
            const paid = data.paymentApplied;
            res.status(StatusCodes.OK).json({
                success: true,
                message: paid
                    ? 'Invoice issued and payment recorded successfully'
                    : 'Invoice issued successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async voidInvoice(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.voidInvoice(
                req.params.invoiceId as string,
                req.params.workspaceId as string,
                req.user.userId,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Invoice voided successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    // ─── Reporting ─────────────────────────────────────

    async getOverdueInvoices(
        req: AuthenticatedRequest,
        res: Response,
        next: NextFunction,
    ): Promise<void> {
        try {
            const data = await this.service.getOverdueInvoices(req.params.workspaceId as string);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Overdue invoices retrieved successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async getInvoiceSummary(
        req: AuthenticatedRequest,
        res: Response,
        next: NextFunction,
    ): Promise<void> {
        try {
            const data = await this.service.getInvoiceSummary(req.params.workspaceId as string);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Invoice summary retrieved successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async getCustomerOutstanding(
        req: AuthenticatedRequest,
        res: Response,
        next: NextFunction,
    ): Promise<void> {
        try {
            const data = await this.service.getCustomerOutstanding(
                req.params.workspaceId as string,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Customer outstanding balances retrieved successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    // ─── Settings ──────────────────────────────────────

    async getSettings(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getSettings(req.params.workspaceId as string);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Invoice settings retrieved successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async updateSettings(
        req: AuthenticatedRequest,
        res: Response,
        next: NextFunction,
    ): Promise<void> {
        try {
            const data = await this.service.updateSettings(
                req.params.workspaceId as string,
                req.user.userId,
                req.body,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Invoice settings updated successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async draftDocument(
        req: AuthenticatedRequest,
        res: Response,
        next: NextFunction,
    ): Promise<void> {
        try {
            const data = await this.service.draftDocument(
                req.params.workspaceId as string,
                req.body,
            );
            res.setHeader('Cache-Control', 'no-store');
            res.json({ success: true, data });
        } catch (error) {
            next(error);
        }
    }

    async previewDocument(
        req: AuthenticatedRequest,
        res: Response,
        next: NextFunction,
    ): Promise<void> {
        try {
            const data = await this.service.previewDocument(
                req.params.workspaceId as string,
                req.body,
            );
            res.setHeader('Cache-Control', 'no-store');
            res.json({ success: true, data });
        } catch (error) {
            next(error);
        }
    }

    async draftPdf(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const pdf = await this.service.draftPdf(req.params.workspaceId as string, req.body);
            res.setHeader('Cache-Control', 'no-store');
            res.type('application/pdf').send(pdf);
        } catch (error) {
            next(error);
        }
    }

    async previewPdf(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const pdf = await this.service.previewPdf(req.params.workspaceId as string, req.body);
            res.setHeader('Cache-Control', 'no-store');
            res.type('application/pdf').send(pdf);
        } catch (error) {
            next(error);
        }
    }

    async invoiceDocument(
        req: AuthenticatedRequest,
        res: Response,
        next: NextFunction,
    ): Promise<void> {
        try {
            const data = await this.service.invoiceDocument(
                req.params.invoiceId as string,
                req.params.workspaceId as string,
            );
            res.setHeader('Cache-Control', 'no-store');
            res.json({ success: true, data });
        } catch (error) {
            next(error);
        }
    }

    async invoicePdf(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const pdf = await this.service.invoicePdf(
                req.params.invoiceId as string,
                req.params.workspaceId as string,
            );
            res.setHeader('Cache-Control', 'no-store');
            res.setHeader('Content-Disposition', 'attachment; filename="invoice.pdf"');
            res.type('application/pdf').send(pdf);
        } catch (error) {
            next(error);
        }
    }

    async uploadArtwork(
        req: AuthenticatedRequest,
        res: Response,
        next: NextFunction,
    ): Promise<void> {
        try {
            if (!req.file)
                throw new AppError('Choose an image to upload.', 400, 'INVALID_INVOICE_ARTWORK');
            const data = await this.service.uploadArtwork(
                req.params.workspaceId as string,
                req.user.userId,
                req.file,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Invoice artwork saved',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async uploadLogo(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const file = req.file;
            if (!file) {
                res.status(StatusCodes.BAD_REQUEST).json({
                    success: false,
                    message: 'No file uploaded',
                });
                return;
            }
            const data = await this.service.uploadLogo(
                req.params.workspaceId as string,
                req.user.userId,
                file,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Logo uploaded successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }
}

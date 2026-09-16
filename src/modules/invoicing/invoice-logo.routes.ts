import { Router, NextFunction, Request, Response } from 'express';
import { container } from 'tsyringe';
import { InvoicingService } from './invoicing.service';
import { StorageService } from '../files/storage.service';

/**
 * Serves a workspace's invoice logo.
 *
 * Deliberately without a session: this image is printed on invoices and
 * embedded in the emails those invoices are sent in, so a customer's browser
 * and mail client have to load it with no account here. What it exposes is
 * exactly what the business already puts on the invoices it sends out.
 *
 * Only the logo a workspace currently references resolves — a replaced file
 * name stops working the moment it is replaced.
 */
export const invoiceLogoRouter = Router();

invoiceLogoRouter.get('/:file', async (req: Request, res: Response, next: NextFunction) => {
    try {
        const key = await container.resolve(InvoicingService).resolveLogoKey(req.params.file as string);
        const stream = await container.resolve(StorageService).getObject(key);

        res.setHeader('Content-Type', 'image/png');
        // The file name carries a timestamp, so these bytes never change.
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        // helmet() defaults this to same-origin, which would stop the app —
        // served from a different origin than this API — from rendering it.
        res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');

        stream.on('error', next);
        stream.pipe(res);
    } catch (error) {
        next(error);
    }
});

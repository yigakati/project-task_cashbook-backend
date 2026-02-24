import { injectable } from 'tsyringe';
import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { FilesService } from './files.service';
import { AuthenticatedRequest } from '../../core/types';
import { AppError } from '../../core/errors/AppError';

@injectable()
export class FilesController {
    constructor(private filesService: FilesService) { }

    async upload(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            if (!req.file) {
                throw new AppError('No file provided', 400, 'NO_FILE');
            }

            const attachment = await this.filesService.uploadAttachment(
                req.params.cashbookId as string,
                req.params.entryId as string,
                req.user.userId,
                req.file
            );

            res.status(StatusCodes.CREATED).json({
                success: true,
                message: 'File uploaded successfully',
                data: attachment,
            });
        } catch (error) {
            next(error);
        }
    }

    async getAll(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const attachments = await this.filesService.getAttachments(req.params.entryId as string);

            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Attachments retrieved successfully',
                data: attachments,
            });
        } catch (error) {
            next(error);
        }
    }

    /**
     * Generates and returns a secure, short-lived Presigned URL from MinIO.
     * The frontend will use this URL to download the file directly.
     */
    async getFileUrl(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const fileData = await this.filesService.getPresignedUrl(
                req.params.attachmentId as string
            );

            res.status(StatusCodes.OK).json({
                success: true,
                message: 'File URL generated successfully',
                data: fileData, 
            });
        } catch (error) {
            next(error);
        }
    }

    async delete(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.filesService.deleteAttachment(req.params.attachmentId as string, req.user.userId);

            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Attachment deleted successfully',
            });
        } catch (error) {
            next(error);
        }
    }
}
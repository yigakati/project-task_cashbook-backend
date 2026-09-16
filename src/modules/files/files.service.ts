import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import { NotFoundError, AppError } from '../../core/errors/AppError';
import * as fs from 'fs/promises';
import { StorageService } from './storage.service';
import { logger } from '../../utils/logger';
import {
    assertStorageAvailable,
    assertStorageNotFull,
    lockWorkspaceStorage,
} from '../storage/storage-quota.service';

type AttachmentOwner =
    | { entryId: string; cashbookId: string }
    | { taskId: string }
    | { taskReportId: string }
    | { expenseClaimId: string };

/** Multer's disk copy, when a request is refused before processing gets to it. */
async function discardTempFile(file: Express.Multer.File) {
    if (file?.path) await fs.unlink(file.path).catch(() => {});
}

@injectable()
export class FilesService {
    constructor(
        @inject('PrismaClient') private prisma: PrismaClient,
        private storageService: StorageService,
    ) { }

    async uploadAttachment(
        cashbookId: string,
        entryId: string,
        userId: string,
        file: Express.Multer.File
    ) {
        // Verify entry belongs to cashbook and isn't deleted
        const entry = await this.prisma.entry.findUnique({
            where: { id: entryId },
            include: { cashbook: true },
        });

        if (!entry || entry.cashbookId !== cashbookId || entry.isDeleted) {
            await discardTempFile(file);
            throw new NotFoundError('Entry');
        }

        return this.storeAttachment(entry.cashbook.workspaceId, { entryId, cashbookId }, userId, file);
    }

    /**
     * Attach a file to a task, a task report, or an expense claim.
     *
     * Separate entry point from the cashbook path above because the ownership
     * check is different in kind — there is no entry to verify, and the caller
     * has already been authorized against the owning record. What this adds is
     * the guarantee that the row it writes satisfies attachments_exactly_one_owner.
     */
    async uploadOwnedAttachment(
        workspaceId: string,
        owner: { taskId: string } | { taskReportId: string } | { expenseClaimId: string },
        userId: string,
        file: Express.Multer.File,
    ) {
        return this.storeAttachment(workspaceId, owner, userId, file);
    }

    /**
     * The one place a file is stored, whoever it belongs to.
     *
     * Checked twice against the workspace allowance: once cheaply up front, so
     * a full workspace refuses before any processing happens, and once for
     * real under the workspace's storage lock with the size actually stored —
     * images shrink when re-encoded, and two uploads racing each other must
     * not both fit into the same last few megabytes.
     */
    private async storeAttachment(
        workspaceId: string,
        owner: AttachmentOwner,
        userId: string,
        file: Express.Multer.File,
    ) {
        try {
            await assertStorageNotFull(this.prisma, workspaceId, file.size);
        } catch (error) {
            await discardTempFile(file);
            throw error;
        }

        let stored: { objectName: string; mimeType: string; fileSize: number };
        try {
            stored = await this.storageService.processAndUpload(file);
        } catch (error) {
            if (error instanceof AppError) throw error;
            logger.error('File upload failed', { error, workspaceId });
            throw new AppError('File upload failed', 500, 'UPLOAD_FAILED');
        }

        try {
            return await this.prisma.$transaction(async (tx) => {
                await lockWorkspaceStorage(tx, workspaceId);
                await assertStorageAvailable(tx, workspaceId, stored.fileSize);
                return tx.attachment.create({
                    data: {
                        ...owner,
                        workspaceId,
                        uploadedById: userId,
                        fileName: file.originalname,
                        mimeType: stored.mimeType,
                        fileSize: stored.fileSize,
                        s3Key: stored.objectName,
                    },
                });
            });
        } catch (error) {
            // Refused (or failed) after the bytes were already stored: remove
            // them rather than leave an object nothing references.
            await this.storageService.deleteObject(stored.objectName).catch((cleanupError) =>
                logger.error('Could not remove an upload that was refused', {
                    cleanupError,
                    objectName: stored.objectName,
                }),
            );
            if (error instanceof AppError) throw error;
            logger.error('File upload failed', { error, workspaceId });
            throw new AppError('File upload failed', 500, 'UPLOAD_FAILED');
        }
    }

    /** Files on one owner, newest first. */
    async listOwnedAttachments(
        owner: { taskId: string } | { taskReportId: string } | { expenseClaimId: string },
    ) {
        return this.prisma.attachment.findMany({
            where: { ...owner, isDeleted: false },
            orderBy: { createdAt: 'desc' },
            select: {
                id: true,
                fileName: true,
                fileSize: true,
                mimeType: true,
                createdAt: true,
                uploadedById: true,
            },
        });
    }

    async getAttachments(entryId: string) {
        return this.prisma.attachment.findMany({
            where: { 
                entryId,
                isDeleted: false // Ensure we don't fetch soft-deleted attachments
            },
            orderBy: { createdAt: 'desc' },
        });
    }

    /**
     * Generates a 15-minute Presigned URL for direct secure access from MinIO.
     */
    async getPresignedUrl(attachmentId: string) {
        const attachment = await this.prisma.attachment.findUnique({
            where: { id: attachmentId },
        });

        if (!attachment || attachment.isDeleted) {
            throw new NotFoundError('Attachment');
        }

        // We will add generatePresignedUrl to the StorageService next.
        // 900 seconds = 15 minutes.
        const url = await this.storageService.generatePresignedUrl(attachment.s3Key, 900);

        return {
            url,
            fileName: attachment.fileName,
            mimeType: attachment.mimeType,
            fileSize: attachment.fileSize,
        };
    }

    /**
     * Soft-deletes the attachment to maintain financial audit trails.
     * The actual file remains safely in MinIO.
     */
    async deleteAttachment(attachmentId: string, userId: string) {
        const attachment = await this.prisma.attachment.findUnique({
            where: { id: attachmentId },
        });

        if (!attachment || attachment.isDeleted) {
            throw new NotFoundError('Attachment');
        }

        // Soft delete the record in the database
        await this.prisma.attachment.update({
            where: { id: attachmentId },
            data: {
                isDeleted: true,
                deletedAt: new Date(),
                // Optionally track who deleted it if you add a deletedById field to your schema
            },
        });
        
        logger.info('Attachment soft-deleted', { attachmentId, userId, objectName: attachment.s3Key });
    }
}
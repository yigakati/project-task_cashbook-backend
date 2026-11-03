import { inject, injectable } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import sharp from 'sharp';
import { randomUUID } from 'node:crypto';
import { AppError, NotFoundError } from '../../core/errors/AppError';
import { StorageService } from '../files/storage.service';
import { assertStorageAvailable, lockWorkspaceStorage } from '../storage/storage-quota.service';
import { lockHousingUnit } from './housing-properties.service';
import { housingWorkspace } from './housing-access';
import { HousingService } from './housing.service';
import { logger } from '../../utils/logger';

@injectable()
export class HousingMediaService {
    constructor(
        @inject('PrismaClient') private prisma: PrismaClient,
        private storage: StorageService,
        private housing: HousingService,
    ) {}
    async upload(workspaceId: string, unitId: string, userId: string, file: Express.Multer.File) {
        await housingWorkspace(this.prisma, workspaceId, userId, true);
        if (!file || !['image/jpeg', 'image/png', 'image/webp'].includes(file.mimetype))
            throw new AppError('Upload a JPEG, PNG or WebP image', 400, 'INVALID_IMAGE');
        if (
            !(await this.prisma.housingUnit.findFirst({
                where: {
                    id: unitId,
                    workspaceId,
                    archivedAt: null,
                    property: { archivedAt: null },
                },
            }))
        )
            throw new NotFoundError('Unit');
        let buffer: Buffer;
        try {
            const source = sharp(file.buffer, { limitInputPixels: 40_000_000 });
            const meta = await source.metadata();
            if (!['jpeg', 'png', 'webp'].includes(meta.format ?? '') || (meta.pages ?? 1) > 1)
                throw new Error('Unsupported image');
            buffer = await source
                .rotate()
                .resize({ width: 1920, height: 1920, fit: 'inside', withoutEnlargement: true })
                .webp({ quality: 80 })
                .toBuffer();
        } catch {
            throw new AppError(
                'This image could not be read. Use a JPEG, PNG or WebP image',
                400,
                'INVALID_IMAGE',
            );
        }
        const key = `attachments/${randomUUID()}.webp`;
        await this.storage.uploadBuffer(key, buffer, 'image/webp');
        try {
            return await this.prisma.$transaction(async (tx) => {
                const unit = await lockHousingUnit(tx, workspaceId, unitId);
                if (unit.archivedAt || unit.property.archivedAt)
                    throw new NotFoundError('Available unit');
                await lockWorkspaceStorage(tx, workspaceId);
                await housingWorkspace(tx, workspaceId, userId, true);
                if (
                    !(await tx.housingUnit.findFirst({
                        where: {
                            id: unitId,
                            workspaceId,
                            archivedAt: null,
                            property: { archivedAt: null },
                        },
                    }))
                )
                    throw new NotFoundError('Unit');
                if (
                    (await tx.attachment.count({
                        where: { housingUnitId: unitId, isDeleted: false },
                    })) >= 12
                )
                    throw new AppError('A unit can have up to 12 photos', 400, 'PHOTO_LIMIT');
                await assertStorageAvailable(tx, workspaceId, buffer.length);
                return tx.attachment.create({
                    data: {
                        workspaceId,
                        housingUnitId: unitId,
                        uploadedById: userId,
                        fileName: file.originalname.slice(0, 255),
                        fileSize: buffer.length,
                        mimeType: 'image/webp',
                        s3Key: key,
                    },
                    select: { id: true, fileName: true, mimeType: true },
                });
            });
        } catch (error) {
            await this.storage
                .deleteObject(key)
                .catch((cleanupError) =>
                    logger.error('Failed to clean up refused unit photo', { cleanupError, key }),
                );
            throw error;
        }
    }
    async photo(
        workspaceId: string | null,
        unitOrTenancyId: string,
        photoId: string,
        userId: string,
        remove = false,
    ) {
        let unitId = unitOrTenancyId;
        if (workspaceId) await housingWorkspace(this.prisma, workspaceId, userId, remove);
        else {
            const tenancy = await this.housing.access(this.prisma, unitOrTenancyId, userId, null);
            if (tenancy.invitationStatus !== 'ACCEPTED') throw new NotFoundError('Photo');
            unitId = tenancy.unitId;
        }
        const photo = await this.prisma.attachment.findFirst({
            where: {
                id: photoId,
                housingUnitId: unitId,
                isDeleted: false,
                ...(workspaceId ? { workspaceId } : {}),
            },
        });
        if (!photo) throw new NotFoundError('Photo');
        if (remove) {
            await this.prisma.attachment.update({
                where: { id: photoId },
                data: { isDeleted: true, deletedAt: new Date() },
            });
            return { removed: true };
        }
        return { url: await this.storage.generatePresignedUrl(photo.s3Key) };
    }
}

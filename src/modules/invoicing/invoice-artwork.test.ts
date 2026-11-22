import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import sharp from 'sharp';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { resetDatabase, testPrisma } from '../../test/setup';
import { resolveService } from '../../test/container';
import { createUser, createWorkspace } from '../../test/factories';
import { InvoicingService } from './invoicing.service';
import { normalizeInvoiceArtwork, invoiceArtworkUrl } from './invoice-artwork';
import { StorageService } from '../files/storage.service';
import { StorageQuotaService, getStorageUsedBytes } from '../storage/storage-quota.service';
import { config } from '../../config';
import { updateInvoiceSettingsSchema } from './invoicing.dto';
const environment = config.NODE_ENV;
const subscriptions = config.INVOICE_SUBSCRIPTIONS_ACTIVE;
const service = () => resolveService(InvoicingService);
const png = () =>
    sharp({ create: { width: 80, height: 60, channels: 3, background: '#567890' } })
        .png()
        .toBuffer();
beforeEach(async () => {
    await resetDatabase();
    config.NODE_ENV = 'test';
});
afterEach(() => {
    vi.restoreAllMocks();
    config.NODE_ENV = environment;
    config.INVOICE_SUBSCRIPTIONS_ACTIVE = subscriptions;
});
async function fixture() {
    const owner = await createUser();
    const workspace = await createWorkspace(owner.id);
    return { owner, workspace };
}
function store() {
    return {
        upload: vi.spyOn(StorageService.prototype, 'uploadBuffer').mockResolvedValue(),
        remove: vi.spyOn(StorageService.prototype, 'deleteObject').mockResolvedValue(),
    };
}
describe('invoice artwork ownership, quota and rollout', () => {
    it('normalizes actual bytes and rejects SVG, corrupt data, animation and oversized uploads', async () => {
        const result = await normalizeInvoiceArtwork({
            buffer: await png(),
        } as Express.Multer.File);
        expect((await sharp(result).metadata()).format).toBe('png');
        for (const buffer of [
            Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"/>'),
            Buffer.from('not image'),
            Buffer.alloc(10 * 1024 * 1024 + 1),
        ]) {
            await expect(
                normalizeInvoiceArtwork({ buffer } as Express.Multer.File),
            ).rejects.toMatchObject({ code: 'INVALID_INVOICE_ARTWORK' });
        }
        expect(
            updateInvoiceSettingsSchema.safeParse({ artworkUrl: 'https://example.test/image.png' })
                .success,
        ).toBe(false);
    });
    it('records replacements, reports storage usage and removes old artwork', async () => {
        const { owner, workspace } = await fixture();
        const storage = store();
        const first = await service().uploadArtwork(workspace.id, owner.id, {
            buffer: await png(),
        } as Express.Multer.File);
        expect(first.artworkUrl).toBe(invoiceArtworkUrl(first.artworkKey));
        expect(await getStorageUsedBytes(testPrisma, workspace.id)).toBe(first.artworkSize);
        const overview = await resolveService(StorageQuotaService).getOverview(workspace.id);
        expect(overview.breakdown.find((part) => part.kind === 'artwork')).toMatchObject({
            count: 1,
            bytes: first.artworkSize,
        });
        const second = await service().uploadArtwork(workspace.id, owner.id, {
            buffer: await png(),
        } as Express.Multer.File);
        expect(second.artworkKey).not.toBe(first.artworkKey);
        expect(storage.remove).toHaveBeenCalledWith(first.artworkKey);
        await expect(
            service().resolveArtworkKey(first.artworkKey!.split('/')[1]),
        ).rejects.toMatchObject({ statusCode: 404 });
        await expect(service().resolveArtworkKey(second.artworkKey!.split('/')[1])).resolves.toBe(
            second.artworkKey,
        );
        const preview = await service().previewDocument(workspace.id, {});
        expect(preview.appearance.artworkUrl).toBe(second.artworkUrl);
        await service().updateSettings(workspace.id, owner.id, { artworkUrl: null });
        expect(await getStorageUsedBytes(testPrisma, workspace.id)).toBe(0);
        expect(storage.remove).toHaveBeenCalledWith(second.artworkKey);
    });
    it('enforces the production gate before decoding or storing', async () => {
        const { owner, workspace } = await fixture();
        const storage = store();
        config.NODE_ENV = 'production';
        config.INVOICE_SUBSCRIPTIONS_ACTIVE = false;
        await expect(
            service().uploadArtwork(workspace.id, owner.id, {
                buffer: await png(),
            } as Express.Multer.File),
        ).rejects.toMatchObject({ code: 'INVOICE_CUSTOMIZATION_LOCKED' });
        expect(storage.upload).not.toHaveBeenCalled();
    });
    it('rejects over-quota uploads and leaves the saved artwork intact', async () => {
        const { owner, workspace } = await fixture();
        const storage = store();
        await testPrisma.workspace.update({
            where: { id: workspace.id },
            data: { storageQuotaBytes: 10 },
        });
        await expect(
            service().uploadArtwork(workspace.id, owner.id, {
                buffer: await png(),
            } as Express.Multer.File),
        ).rejects.toMatchObject({ code: 'STORAGE_QUOTA_EXCEEDED' });
        expect(storage.upload).not.toHaveBeenCalled();
        expect(
            (
                await testPrisma.invoiceSettings.findUniqueOrThrow({
                    where: { workspaceId: workspace.id },
                })
            ).artworkKey,
        ).toBeNull();
    });
    it('keeps saving successful when obsolete object cleanup fails', async () => {
        const { owner, workspace } = await fixture();
        const storage = store();
        await service().uploadArtwork(workspace.id, owner.id, {
            buffer: await png(),
        } as Express.Multer.File);
        storage.remove.mockRejectedValue(new Error('Bucket temporarily unavailable'));
        await expect(
            service().uploadArtwork(workspace.id, owner.id, {
                buffer: await png(),
            } as Express.Multer.File),
        ).resolves.toMatchObject({ workspaceId: workspace.id });
    });
    it('protects the HTTP upload from anonymous and foreign workspace access, and serves bundled themes', async () => {
        await import('../../config/container');
        const app = (await import('../../app')).default;
        const { owner, workspace } = await fixture();
        store();
        const foreign = await createUser();
        const cookie = (user: typeof owner) =>
            `accessToken=${jwt.sign({ userId: user.id, email: user.email }, config.JWT_ACCESS_SECRET)}`;
        const url = `${config.API_PREFIX}/workspaces/${workspace.id}/invoices/settings/current/artwork`;
        expect(
            (
                await request(app)
                    .post(url)
                    .attach('file', await png(), 'image.png')
            ).status,
        ).toBe(401);
        expect(
            (
                await request(app)
                    .post(url)
                    .set('Cookie', cookie(foreign))
                    .attach('file', await png(), 'image.png')
            ).status,
        ).toBe(403);
        expect(
            (
                await request(app)
                    .post(url)
                    .set('Cookie', cookie(owner))
                    .attach('file', await png(), 'image.png')
            ).status,
        ).toBe(200);
        const theme = await request(app).get(`${config.API_PREFIX}/invoice-logos/themes/wave.png`);
        expect(theme.status).toBe(200);
        expect(theme.headers['content-type']).toContain('image/png');
        expect(
            (await request(app).get(`${config.API_PREFIX}/invoice-logos/themes/unknown.png`))
                .status,
        ).toBe(404);
    });
});

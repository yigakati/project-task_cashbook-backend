/**
 * Workspace storage allowance.
 *
 * Usage is counted from files that already exist, so the counting rules are
 * tested against rows written directly. The refusals go through the real
 * upload paths with only the object stores stubbed — the quota decision, the
 * lock and the clean-up all run for real against the test database.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import sharp from 'sharp';
import { resetDatabase, testPrisma } from '../../test/setup';
import { resolveService } from '../../test/container';
import { createTask, createUser, createWorkspace } from '../../test/factories';
import { GIB, StorageQuotaService, getStorageUsedBytes } from './storage-quota.service';
import { FilesService } from '../files/files.service';
import { InvoicingService } from '../invoicing/invoicing.service';
import { PlatformSettingsService } from '../platform/platform-settings.service';
import { StorageService } from '../files/storage.service';
import { LOGO_PREFIX, invoiceLogoUrl } from '../invoicing/invoice-logo';
import { StorageQuotaExceededError } from '../../core/errors/AppError';

const MB = 1024 * 1024;
const quota = () => resolveService(StorageQuotaService);

async function addAttachment(
    workspaceId: string,
    uploadedById: string,
    taskId: string,
    fileSize: number,
    isDeleted = false,
) {
    return testPrisma.attachment.create({
        data: {
            workspaceId,
            taskId,
            uploadedById,
            fileName: 'file.pdf',
            mimeType: 'application/pdf',
            fileSize,
            s3Key: `test/${randomUUID()}`,
            isDeleted,
        },
    });
}

async function setQuota(workspaceId: string, bytes: number) {
    await testPrisma.workspace.update({
        where: { id: workspaceId },
        data: { storageQuotaBytes: BigInt(bytes) },
    });
}

/** FilesService with the object store replaced: every upload "stores" `storedSize` bytes. */
function filesWithFakeStore(storedSize: number) {
    const files = resolveService(FilesService);
    const store = {
        processAndUpload: vi.fn(async () => ({
            objectName: `obj/${randomUUID()}`,
            mimeType: 'application/pdf',
            fileSize: storedSize,
        })),
        deleteObject: vi.fn(async () => {}),
    };
    (files as unknown as { storageService: typeof store }).storageService = store;
    return { files, store };
}

const fakeFile = (size: number) =>
    ({ originalname: 'receipt.pdf', mimetype: 'application/pdf', size, path: '' }) as Express.Multer.File;

async function setup() {
    const owner = await createUser();
    const workspace = await createWorkspace(owner.id);
    const task = await createTask(workspace.id, owner.id);
    return { owner, workspace, task };
}

describe('storage allowance', () => {
    beforeEach(async () => {
        await resetDatabase();
    });

    afterEach(async () => {
        vi.restoreAllMocks();
        // Falls back to 1 GB, so no test leaks a changed default into the next.
        await testPrisma.platformSetting.deleteMany({ where: { key: 'default_storage_quota_bytes' } });
    });

    describe('counting', () => {
        it('counts live files and the logo, not deleted files or other workspaces', async () => {
            const { owner, workspace, task } = await setup();
            const other = await createWorkspace(owner.id);
            const otherTask = await createTask(other.id, owner.id);

            await addAttachment(workspace.id, owner.id, task.id, 3 * MB);
            await addAttachment(workspace.id, owner.id, task.id, 2 * MB, true);
            await addAttachment(other.id, owner.id, otherTask.id, 1 * MB);
            await testPrisma.invoiceSettings.create({
                data: { workspaceId: workspace.id, logoKey: `${LOGO_PREFIX}${workspace.id}-1.png`, logoSize: 500_000 },
            });

            expect(await getStorageUsedBytes(testPrisma, workspace.id)).toBe(3 * MB + 500_000);

            const overview = await quota().getOverview(workspace.id);
            expect(overview.usedBytes).toBe(3 * MB + 500_000);
            expect(overview.limitBytes).toBe(GIB);
            expect(overview.isDefaultLimit).toBe(true);
            expect(overview.breakdown.find((b) => b.kind === 'task')).toMatchObject({ bytes: 3 * MB, count: 1 });
            expect(overview.breakdown.find((b) => b.kind === 'logo')).toMatchObject({ bytes: 500_000, count: 1 });
        });

        it('lists only this workspace’s live files, largest first', async () => {
            const { owner, workspace, task } = await setup();
            await addAttachment(workspace.id, owner.id, task.id, 1 * MB);
            await addAttachment(workspace.id, owner.id, task.id, 5 * MB);
            await addAttachment(workspace.id, owner.id, task.id, 9 * MB, true);

            const result = await quota().listFiles(workspace.id, { page: 1, limit: 20, kind: 'all', sort: 'size' });
            expect(result.total).toBe(2);
            expect(result.data.map((f) => f.fileSize)).toEqual([5 * MB, 1 * MB]);
            expect(result.data[0]).toMatchObject({ kind: 'task', context: task.title });
        });
    });

    describe('uploads', () => {
        it('refuses a file that would pass the allowance, and removes what it stored', async () => {
            const { owner, workspace, task } = await setup();
            await setQuota(workspace.id, 10 * MB);
            await addAttachment(workspace.id, owner.id, task.id, 9 * MB);

            const { files, store } = filesWithFakeStore(2 * MB);
            await expect(
                files.uploadOwnedAttachment(workspace.id, { taskId: task.id }, owner.id, fakeFile(2 * MB)),
            ).rejects.toBeInstanceOf(StorageQuotaExceededError);

            const stored = await store.processAndUpload.mock.results[0].value;
            expect(store.deleteObject).toHaveBeenCalledWith(stored.objectName);
            expect(await testPrisma.attachment.count({ where: { workspaceId: workspace.id } })).toBe(1);
        });

        it('accepts a file that fits and records which workspace it counts against', async () => {
            const { owner, workspace, task } = await setup();
            await setQuota(workspace.id, 10 * MB);
            await addAttachment(workspace.id, owner.id, task.id, 9 * MB);

            const { files } = filesWithFakeStore(1 * MB);
            const attachment = await files.uploadOwnedAttachment(
                workspace.id, { taskId: task.id }, owner.id, fakeFile(1 * MB),
            );

            expect(attachment.workspaceId).toBe(workspace.id);
            expect(await getStorageUsedBytes(testPrisma, workspace.id)).toBe(10 * MB);
        });

        it('refuses before doing any work once the workspace is full', async () => {
            const { owner, workspace, task } = await setup();
            await setQuota(workspace.id, 5 * MB);
            await addAttachment(workspace.id, owner.id, task.id, 5 * MB);

            const { files, store } = filesWithFakeStore(1);
            await expect(
                files.uploadOwnedAttachment(workspace.id, { taskId: task.id }, owner.id, fakeFile(1)),
            ).rejects.toBeInstanceOf(StorageQuotaExceededError);
            expect(store.processAndUpload).not.toHaveBeenCalled();
        });

        it('lets only one of two racing uploads take the last space', async () => {
            const { owner, workspace, task } = await setup();
            await setQuota(workspace.id, 10 * MB);
            await addAttachment(workspace.id, owner.id, task.id, 6 * MB);

            const { files } = filesWithFakeStore(3 * MB);
            const results = await Promise.allSettled([
                files.uploadOwnedAttachment(workspace.id, { taskId: task.id }, owner.id, fakeFile(3 * MB)),
                files.uploadOwnedAttachment(workspace.id, { taskId: task.id }, owner.id, fakeFile(3 * MB)),
            ]);

            expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
            const rejected = results.find((r) => r.status === 'rejected') as PromiseRejectedResult;
            expect(rejected.reason).toBeInstanceOf(StorageQuotaExceededError);
            expect(await getStorageUsedBytes(testPrisma, workspace.id)).toBe(9 * MB);
        });
    });

    describe('invoice logo', () => {
        const png = () =>
            sharp({ create: { width: 40, height: 40, channels: 3, background: '#3355ff' } }).png().toBuffer();

        /**
         * The object store, stubbed on the prototype: the services build their
         * own instances, and what is under test is the bookkeeping around the
         * upload, not MinIO itself.
         */
        const stubObjectStore = () => ({
            uploadBuffer: vi.spyOn(StorageService.prototype, 'uploadBuffer').mockResolvedValue(undefined),
            deleteObject: vi.spyOn(StorageService.prototype, 'deleteObject').mockResolvedValue(undefined),
        });

        it('is stored by key, counts against storage, and replacing it deletes the old file', async () => {
            const { owner, workspace } = await setup();
            const store = stubObjectStore();
            const invoicing = resolveService(InvoicingService);

            const first = await invoicing.uploadLogo(workspace.id, owner.id, { buffer: await png() } as Express.Multer.File);
            expect(first.logoKey).toMatch(new RegExp(`^${LOGO_PREFIX}${workspace.id}-\\d+\\.png$`));
            expect(first.logoSize).toBeGreaterThan(0);
            expect(store.uploadBuffer).toHaveBeenCalledWith(first.logoKey, expect.any(Buffer), 'image/png');
            // The URL is derived from the key, not stored on the row.
            expect(first.logoUrl).toBe(invoiceLogoUrl(first.logoKey));

            await new Promise((r) => setTimeout(r, 5)); // distinct timestamp in the key
            const second = await invoicing.uploadLogo(workspace.id, owner.id, { buffer: await png() } as Express.Multer.File);

            expect(store.deleteObject).toHaveBeenCalledWith(first.logoKey);
            expect(await getStorageUsedBytes(testPrisma, workspace.id)).toBe(second.logoSize);
        });

        it('refuses a logo that does not fit, before storing anything', async () => {
            const { owner, workspace } = await setup();
            await setQuota(workspace.id, 10);
            const store = stubObjectStore();

            await expect(
                resolveService(InvoicingService).uploadLogo(
                    workspace.id, owner.id, { buffer: await png() } as Express.Multer.File,
                ),
            ).rejects.toBeInstanceOf(StorageQuotaExceededError);
            expect(store.uploadBuffer).not.toHaveBeenCalled();
        });

        it('will not take a typed-in URL, and removing the logo deletes its file', async () => {
            const { owner, workspace } = await setup();
            const store = stubObjectStore();
            const invoicing = resolveService(InvoicingService);

            await expect(
                invoicing.updateSettings(workspace.id, owner.id, { logoUrl: 'http://169.254.169.254/latest/meta-data' }),
            ).rejects.toMatchObject({ code: 'LOGO_URL_NOT_ALLOWED' });

            const uploaded = await invoicing.uploadLogo(workspace.id, owner.id, { buffer: await png() } as Express.Multer.File);
            // The settings form re-sends the current URL on every save; that must still work.
            await invoicing.updateSettings(workspace.id, owner.id, { logoUrl: uploaded.logoUrl, accentColor: '#112233' });

            const removed = await invoicing.updateSettings(workspace.id, owner.id, { logoUrl: null });
            expect(removed).toMatchObject({ logoUrl: null, logoKey: null, logoSize: null });
            expect(store.deleteObject).toHaveBeenCalledWith(uploaded.logoKey);
        });

        it('serves only the logo a workspace references right now', async () => {
            const { owner, workspace } = await setup();
            stubObjectStore();
            const invoicing = resolveService(InvoicingService);

            const first = await invoicing.uploadLogo(workspace.id, owner.id, { buffer: await png() } as Express.Multer.File);
            const file = first.logoKey!.slice(LOGO_PREFIX.length);
            await expect(invoicing.resolveLogoKey(file)).resolves.toBe(first.logoKey);

            // Not a name we ever issue, and a name belonging to no workspace.
            await expect(invoicing.resolveLogoKey('../../etc/passwd')).rejects.toMatchObject({ code: 'NOT_FOUND' });
            await expect(
                invoicing.resolveLogoKey(`${'0'.repeat(8)}-0000-0000-0000-000000000000-1.png`),
            ).rejects.toMatchObject({ code: 'NOT_FOUND' });

            // Replaced: the old name stops resolving, so a cached URL cannot
            // keep serving a logo the workspace has moved on from.
            await new Promise((r) => setTimeout(r, 5));
            await invoicing.uploadLogo(workspace.id, owner.id, { buffer: await png() } as Express.Multer.File);
            await expect(invoicing.resolveLogoKey(file)).rejects.toMatchObject({ code: 'NOT_FOUND' });
        });
    });

    describe('requests for more', () => {
        it('allows one open request, and approving raises the allowance', async () => {
            const { owner, workspace } = await setup();
            const admin = await createUser();

            await expect(
                quota().createRequest(workspace.id, owner.id, { requestedGb: 1 }),
            ).rejects.toMatchObject({ code: 'REQUEST_NOT_AN_INCREASE' });

            const request = await quota().createRequest(workspace.id, owner.id, { requestedGb: 5, reason: 'Receipts' });
            await expect(
                quota().createRequest(workspace.id, owner.id, { requestedGb: 6 }),
            ).rejects.toMatchObject({ code: 'CONFLICT' });

            const decided = await quota().decideRequest(request.id, admin.id, { approve: true, grantedGb: 3 });
            expect(decided).toMatchObject({ status: 'APPROVED', grantedBytes: 3 * GIB });

            const overview = await quota().getOverview(workspace.id);
            expect(overview.limitBytes).toBe(3 * GIB);
            expect(overview.isDefaultLimit).toBe(false);
            expect(overview.pendingRequest).toBeNull();
            expect(overview.lastDecision).toMatchObject({ status: 'APPROVED', grantedBytes: 3 * GIB });

            await expect(
                quota().decideRequest(request.id, admin.id, { approve: false }),
            ).rejects.toMatchObject({ code: 'INVALID_STATUS' });

            // Only an open request blocks another.
            await expect(
                quota().createRequest(workspace.id, owner.id, { requestedGb: 10 }),
            ).resolves.toMatchObject({ status: 'PENDING' });
        });

        it('declining leaves the allowance as it was and keeps the note', async () => {
            const { owner, workspace } = await setup();
            const admin = await createUser();
            const request = await quota().createRequest(workspace.id, owner.id, { requestedGb: 5 });

            await quota().decideRequest(request.id, admin.id, { approve: false, note: 'Clear old receipts first' });

            const ws = await testPrisma.workspace.findUniqueOrThrow({ where: { id: workspace.id } });
            expect(ws.storageQuotaBytes).toBeNull();
            const overview = await quota().getOverview(workspace.id);
            expect(overview.limitBytes).toBe(GIB);
            expect(overview.lastDecision).toMatchObject({ status: 'DECLINED', decisionNote: 'Clear old receipts first' });
        });

        it('a cancelled request can be replaced', async () => {
            const { owner, workspace } = await setup();
            const request = await quota().createRequest(workspace.id, owner.id, { requestedGb: 2 });

            await quota().cancelRequest(workspace.id, request.id, owner.id);
            await expect(quota().cancelRequest(workspace.id, request.id, owner.id)).rejects.toMatchObject({ code: 'NOT_FOUND' });
            await expect(
                quota().createRequest(workspace.id, owner.id, { requestedGb: 2 }),
            ).resolves.toMatchObject({ status: 'PENDING' });
        });
    });

    describe('allowances set by a superadmin', () => {
        it('the platform default applies until a workspace is given its own', async () => {
            const { workspace } = await setup();
            const admin = await createUser();

            await resolveService(PlatformSettingsService).setDefaultStorageQuota(2 * GIB, admin.id);
            expect((await quota().getOverview(workspace.id)).limitBytes).toBe(2 * GIB);

            await quota().setWorkspaceQuota(workspace.id, 4, admin.id);
            expect((await quota().getOverview(workspace.id)).limitBytes).toBe(4 * GIB);

            const reset = await quota().setWorkspaceQuota(workspace.id, null, admin.id);
            expect(reset).toMatchObject({ limitBytes: 2 * GIB, isDefaultLimit: true });
        });

        it('lists workspaces fullest first with their allowance', async () => {
            const { owner, workspace, task } = await setup();
            const quiet = await createWorkspace(owner.id);
            await addAttachment(workspace.id, owner.id, task.id, 4 * MB);
            await setQuota(quiet.id, 2 * GIB);

            const { data } = await quota().listWorkspaceUsage({ page: 1, limit: 10 });
            const ids = data.map((w) => w.id);
            expect(ids.indexOf(workspace.id)).toBeLessThan(ids.indexOf(quiet.id));
            expect(data.find((w) => w.id === workspace.id)).toMatchObject({ usedBytes: 4 * MB, isDefaultLimit: true });
            expect(data.find((w) => w.id === quiet.id)).toMatchObject({ usedBytes: 0, limitBytes: 2 * GIB });
        });
    });
});

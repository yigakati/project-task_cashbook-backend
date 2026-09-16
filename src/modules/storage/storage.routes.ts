import { Router } from 'express';
import { container } from 'tsyringe';
import { StorageController } from './storage.controller';
import { authenticate } from '../../middlewares/authenticate';
import { requireWorkspaceMember } from '../../middlewares/authorize';
import { validate } from '../../middlewares/validate';
import { uuidParams } from '../../middlewares/uuidParam';
import { WorkspacePermission } from '../../core/types/workspace-permissions';
import {
    requestStorageSchema,
    decideStorageRequestSchema,
    setWorkspaceQuotaSchema,
    storageFilesQuerySchema,
    storageRequestsQuerySchema,
    storageWorkspacesQuerySchema,
} from './storage.dto';

const controller = container.resolve(StorageController);

/**
 * A workspace's own storage: owners and admins only.
 *
 * The file list names every attachment in the workspace, including ones in
 * books a plain member was never given — so it sits behind the same
 * permission as the workspace's other settings rather than behind membership.
 */
export const storageWorkspaceRouter = Router({ mergeParams: true });
storageWorkspaceRouter.use(authenticate as any);
storageWorkspaceRouter.use(requireWorkspaceMember(WorkspacePermission.UPDATE_WORKSPACE) as any);

storageWorkspaceRouter.get('/', controller.overview.bind(controller) as any);
storageWorkspaceRouter.get(
    '/files',
    validate(storageFilesQuerySchema, 'query'),
    controller.files.bind(controller) as any,
);
storageWorkspaceRouter.post(
    '/requests',
    validate(requestStorageSchema),
    controller.createRequest.bind(controller) as any,
);
storageWorkspaceRouter.post(
    '/requests/:requestId/cancel',
    validate(uuidParams('requestId'), 'params'),
    controller.cancelRequest.bind(controller) as any,
);

/**
 * The superadmin side. Mounted inside the platform router, which already
 * authenticates and requires a superadmin for everything under it.
 */
export const storagePlatformRouter = Router();

storagePlatformRouter.get(
    '/requests',
    validate(storageRequestsQuerySchema, 'query'),
    controller.listRequests.bind(controller) as any,
);
storagePlatformRouter.patch(
    '/requests/:requestId',
    validate(uuidParams('requestId'), 'params'),
    validate(decideStorageRequestSchema),
    controller.decideRequest.bind(controller) as any,
);
storagePlatformRouter.get(
    '/workspaces',
    validate(storageWorkspacesQuerySchema, 'query'),
    controller.listWorkspaces.bind(controller) as any,
);
storagePlatformRouter.patch(
    '/workspaces/:workspaceId',
    validate(uuidParams('workspaceId'), 'params'),
    validate(setWorkspaceQuotaSchema),
    controller.setWorkspaceQuota.bind(controller) as any,
);

import { Router, RequestHandler } from 'express';
import { container } from 'tsyringe';
import { authenticate } from '../../middlewares/authenticate';
import { requireWorkspaceMember } from '../../middlewares/authorize';
import { WorkspacePermission } from '../../core/types/workspace-permissions';
import { AuthenticatedRequest } from '../../core/types';
import { validate } from '../../middlewares/validate';
import { uuidParams } from '../../middlewares/uuidParam';
import { idempotency } from '../../middlewares/idempotency';
import { uploadImageMemory } from '../../middlewares/uploadImage';
import { HousingService } from './housing.service';
import { HousingMediaService } from './housing-media.service';
import { HousingPropertiesService } from './housing-properties.service';
import * as dto from './housing.dto';

const service = container.resolve(HousingService);
const properties = container.resolve(HousingPropertiesService);
const media = container.resolve(HousingMediaService);
const handle =
    (fn: (r: AuthenticatedRequest) => Promise<unknown>): RequestHandler =>
    async (req, res, next) => {
        try {
            res.json({ success: true, data: await fn(req as AuthenticatedRequest) });
        } catch (e) {
            next(e);
        }
    };
const param = (r: AuthenticatedRequest, key: string) => r.params[key] as string;
const ids = (...keys: string[]) => validate(uuidParams(...keys), 'params');
const write = requireWorkspaceMember(WorkspacePermission.MANAGE_INVENTORY) as RequestHandler;
export const housingWorkspaceRouter = Router({ mergeParams: true });
const ws = housingWorkspaceRouter;
ws.use(
    authenticate as RequestHandler,
    ids('workspaceId'),
    requireWorkspaceMember(WorkspacePermission.VIEW_INVENTORY) as RequestHandler,
);
ws.get(
    '/summary',
    validate(dto.propertyFilterSchema, 'query'),
    handle((r) =>
        service.summary(
            param(r, 'workspaceId'),
            r.user.userId,
            dto.propertyFilterSchema.parse(r.query).propertyId,
        ),
    ),
);
ws.get(
    '/properties',
    validate(dto.propertyQuerySchema, 'query'),
    handle((r) =>
        properties.list(
            param(r, 'workspaceId'),
            r.user.userId,
            dto.propertyQuerySchema.parse(r.query),
        ),
    ),
);
ws.post(
    '/properties/preview',
    write,
    validate(dto.propertyPreviewSchema),
    handle((r) => properties.preview(param(r, 'workspaceId'), r.user.userId, r.body)),
);
ws.post(
    '/properties',
    write,
    validate(dto.createPropertySchema),
    handle((r) => properties.create(param(r, 'workspaceId'), r.user.userId, r.body)),
);
ws.get(
    '/properties/:propertyId',
    ids('propertyId'),
    handle((r) =>
        properties.detail(param(r, 'workspaceId'), r.user.userId, param(r, 'propertyId')),
    ),
);
ws.patch(
    '/properties/:propertyId',
    ids('propertyId'),
    write,
    validate(dto.updatePropertySchema),
    handle((r) =>
        properties.update(param(r, 'workspaceId'), r.user.userId, param(r, 'propertyId'), r.body),
    ),
);
ws.post(
    '/properties/:propertyId/units/preview',
    ids('propertyId'),
    write,
    validate(dto.batchPreviewSchema),
    handle((r) =>
        properties.previewUnits(
            param(r, 'workspaceId'),
            r.user.userId,
            param(r, 'propertyId'),
            r.body,
        ),
    ),
);
ws.post(
    '/properties/:propertyId/units',
    ids('propertyId'),
    write,
    validate(dto.addUnitsSchema),
    handle((r) =>
        properties.addUnits(param(r, 'workspaceId'), r.user.userId, param(r, 'propertyId'), r.body),
    ),
);
ws.get(
    '/units',
    validate(dto.unitQuerySchema, 'query'),
    handle((r) =>
        service.units(param(r, 'workspaceId'), r.user.userId, dto.unitQuerySchema.parse(r.query)),
    ),
);
ws.post(
    '/units',
    write,
    validate(dto.unitSchema),
    handle((r) => service.createUnit(param(r, 'workspaceId'), r.user.userId, r.body)),
);
ws.patch(
    '/units/:id',
    ids('id'),
    write,
    validate(dto.updateUnitSchema),
    handle((r) =>
        service.updateUnit(param(r, 'workspaceId'), r.user.userId, param(r, 'id'), r.body),
    ),
);
ws.post(
    '/units/:id/photos',
    ids('id'),
    write,
    uploadImageMemory.single('file'),
    handle((r) => media.upload(param(r, 'workspaceId'), param(r, 'id'), r.user.userId, r.file!)),
);
ws.get(
    '/units/:id/photos/:photoId',
    ids('id', 'photoId'),
    handle((r) =>
        media.photo(param(r, 'workspaceId'), param(r, 'id'), param(r, 'photoId'), r.user.userId),
    ),
);
ws.delete(
    '/units/:id/photos/:photoId',
    ids('id', 'photoId'),
    write,
    handle((r) =>
        media.photo(
            param(r, 'workspaceId'),
            param(r, 'id'),
            param(r, 'photoId'),
            r.user.userId,
            true,
        ),
    ),
);
ws.get(
    '/tenancies',
    validate(dto.tenancyQuerySchema, 'query'),
    handle((r) =>
        service.tenancies(
            param(r, 'workspaceId'),
            r.user.userId,
            dto.tenancyQuerySchema.parse(r.query),
        ),
    ),
);
ws.post(
    '/tenancies',
    write,
    validate(dto.tenancySchema),
    idempotency('POST /housing/tenancies') as RequestHandler,
    handle((r) => service.createTenancy(param(r, 'workspaceId'), r.user.userId, r.body)),
);
ws.get(
    '/tenancies/:id',
    ids('id'),
    validate(dto.pageSchema, 'query'),
    handle((r) =>
        service.detail(
            param(r, 'id'),
            r.user.userId,
            param(r, 'workspaceId'),
            dto.pageSchema.parse(r.query),
        ),
    ),
);
ws.post(
    '/tenancies/:id/invite',
    ids('id'),
    write,
    validate(dto.inviteSchema),
    handle((r) => service.invite(param(r, 'id'), param(r, 'workspaceId'), r.user.userId, r.body)),
);
ws.post(
    '/tenancies/:id/end',
    ids('id'),
    write,
    validate(dto.endTenancySchema),
    handle((r) => service.end(param(r, 'id'), param(r, 'workspaceId'), r.user.userId, r.body)),
);
ws.post(
    '/tenancies/:id/periods',
    ids('id'),
    write,
    validate(dto.generateSchema),
    handle((r) =>
        service.generate(param(r, 'id'), param(r, 'workspaceId'), r.user.userId, r.body.through),
    ),
);
ws.patch(
    '/tenancies/:id/periods/:periodId',
    ids('id', 'periodId'),
    write,
    validate(dto.periodUpdateSchema),
    handle((r) =>
        service.updatePeriod(
            param(r, 'id'),
            param(r, 'periodId'),
            param(r, 'workspaceId'),
            r.user.userId,
            r.body,
        ),
    ),
);
ws.get(
    '/tenancies/:id/payment-options',
    ids('id'),
    write,
    handle((r) => service.paymentOptions(param(r, 'id'), param(r, 'workspaceId'), r.user.userId)),
);
ws.post(
    '/tenancies/:id/payments',
    ids('id'),
    write,
    validate(dto.paymentSchema),
    idempotency('POST /housing/payments') as RequestHandler,
    handle((r) => service.payment(param(r, 'id'), param(r, 'workspaceId'), r.user.userId, r.body)),
);

export const housingTenantRouter = Router();
const tenant = housingTenantRouter;
tenant.use(authenticate as RequestHandler);
tenant.get(
    '/tenancies',
    validate(dto.pageSchema, 'query'),
    handle((r) => service.tenancies(null, r.user.userId, dto.pageSchema.parse(r.query))),
);
tenant.get(
    '/tenancies/:id/location',
    ids('id'),
    handle((r) => service.location(param(r, 'id'), r.user.userId)),
);
tenant.get(
    '/tenancies/:id',
    ids('id'),
    validate(dto.pageSchema, 'query'),
    handle((r) =>
        service.detail(param(r, 'id'), r.user.userId, null, dto.pageSchema.parse(r.query)),
    ),
);
tenant.post(
    '/tenancies/:id/accept',
    ids('id'),
    handle((r) => service.respond(param(r, 'id'), r.user.userId, true)),
);
tenant.post(
    '/tenancies/:id/decline',
    ids('id'),
    handle((r) => service.respond(param(r, 'id'), r.user.userId, false)),
);
tenant.get(
    '/tenancies/:id/photos/:photoId',
    ids('id', 'photoId'),
    handle((r) => media.photo(null, param(r, 'id'), param(r, 'photoId'), r.user.userId)),
);

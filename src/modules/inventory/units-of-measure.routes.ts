import { Router, Response, NextFunction } from 'express';
import { injectable, container } from 'tsyringe';
import { StatusCodes } from 'http-status-codes';
import { z } from 'zod';
import { authenticate } from '../../middlewares/authenticate';
import { requireWorkspaceMember } from '../../middlewares/authorize';
import { validate } from '../../middlewares/validate';
import { WorkspacePermission } from '../../core/types/workspace-permissions';
import { AuthenticatedRequest } from '../../core/types';
import { UnitsOfMeasureService } from './units-of-measure.service';

const unitNameSchema = z.object({
    name: z.string().min(1, 'Unit name is required').max(50, 'Unit name must be at most 50 characters'),
});

@injectable()
class UnitsOfMeasureController {
    constructor(private service: UnitsOfMeasureService) { }

    async list(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.list(req.params.workspaceId as string);
            res.status(StatusCodes.OK).json({ success: true, message: 'Units retrieved successfully', data });
        } catch (error) { next(error); }
    }

    async create(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.create(
                req.params.workspaceId as string, req.user.userId, req.body.name,
            );
            res.status(StatusCodes.CREATED).json({ success: true, message: 'Unit created', data });
        } catch (error) { next(error); }
    }

    async rename(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.rename(
                req.params.unitId as string,
                req.params.workspaceId as string,
                req.user.userId,
                req.body.name,
            );
            res.status(StatusCodes.OK).json({ success: true, message: 'Unit renamed', data });
        } catch (error) { next(error); }
    }

    async remove(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.service.remove(
                req.params.unitId as string,
                req.params.workspaceId as string,
                req.user.userId,
            );
            res.status(StatusCodes.OK).json({ success: true, message: 'Unit deleted' });
        } catch (error) { next(error); }
    }
}

export const unitsOfMeasureRouter = Router({ mergeParams: true });
const controller = container.resolve(UnitsOfMeasureController);

unitsOfMeasureRouter.use(authenticate as any);

// Reading the vocabulary is for anyone who can see inventory.
unitsOfMeasureRouter.get('/',
    requireWorkspaceMember() as any,
    controller.list.bind(controller) as any,
);

// Managing it is reference-data work.
unitsOfMeasureRouter.post('/',
    requireWorkspaceMember(WorkspacePermission.MANAGE_REFERENCE_DATA) as any,
    validate(unitNameSchema),
    controller.create.bind(controller) as any,
);

unitsOfMeasureRouter.patch('/:unitId',
    requireWorkspaceMember(WorkspacePermission.MANAGE_REFERENCE_DATA) as any,
    validate(unitNameSchema),
    controller.rename.bind(controller) as any,
);

unitsOfMeasureRouter.delete('/:unitId',
    requireWorkspaceMember(WorkspacePermission.MANAGE_REFERENCE_DATA) as any,
    controller.remove.bind(controller) as any,
);

container.registerSingleton(UnitsOfMeasureService);

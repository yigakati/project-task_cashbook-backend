import { Router, Response, NextFunction } from 'express';
import { injectable, container } from 'tsyringe';
import { StatusCodes } from 'http-status-codes';
import { z } from 'zod';
import { authenticate } from '../../middlewares/authenticate';
import { requireWorkspaceMember } from '../../middlewares/authorize';
import { validate } from '../../middlewares/validate';
import { WorkspacePermission } from '../../core/types/workspace-permissions';
import { AuthenticatedRequest } from '../../core/types';
import { ItemCategoriesService } from './item-categories.service';

const categoryNameSchema = z.object({
    name: z.string().min(1, 'Category name is required').max(60, 'Category name must be at most 60 characters'),
});

@injectable()
class ItemCategoriesController {
    constructor(private service: ItemCategoriesService) { }

    async list(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.list(req.params.workspaceId as string);
            res.status(StatusCodes.OK).json({ success: true, message: 'Item categories retrieved successfully', data });
        } catch (error) { next(error); }
    }

    async create(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.create(
                req.params.workspaceId as string, req.user.userId, req.body.name,
            );
            res.status(StatusCodes.CREATED).json({ success: true, message: 'Item category created', data });
        } catch (error) { next(error); }
    }

    async rename(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.rename(
                req.params.categoryId as string,
                req.params.workspaceId as string,
                req.user.userId,
                req.body.name,
            );
            res.status(StatusCodes.OK).json({ success: true, message: 'Item category renamed', data });
        } catch (error) { next(error); }
    }

    async remove(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            await this.service.remove(
                req.params.categoryId as string,
                req.params.workspaceId as string,
                req.user.userId,
            );
            res.status(StatusCodes.OK).json({ success: true, message: 'Item category deleted' });
        } catch (error) { next(error); }
    }
}

export const itemCategoriesRouter = Router({ mergeParams: true });
const controller = container.resolve(ItemCategoriesController);

itemCategoriesRouter.use(authenticate as any);

// Reading the vocabulary is for anyone who can see inventory.
itemCategoriesRouter.get('/',
    requireWorkspaceMember() as any,
    controller.list.bind(controller) as any,
);

// Managing it is reference-data work.
itemCategoriesRouter.post('/',
    requireWorkspaceMember(WorkspacePermission.MANAGE_REFERENCE_DATA) as any,
    validate(categoryNameSchema),
    controller.create.bind(controller) as any,
);

itemCategoriesRouter.patch('/:categoryId',
    requireWorkspaceMember(WorkspacePermission.MANAGE_REFERENCE_DATA) as any,
    validate(categoryNameSchema),
    controller.rename.bind(controller) as any,
);

itemCategoriesRouter.delete('/:categoryId',
    requireWorkspaceMember(WorkspacePermission.MANAGE_REFERENCE_DATA) as any,
    controller.remove.bind(controller) as any,
);

container.registerSingleton(ItemCategoriesService);

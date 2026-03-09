import { injectable } from 'tsyringe';
import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { InventoryService } from './inventory.service';
import { AuthenticatedRequest } from '../../core/types';

@injectable()
export class InventoryController {
    constructor(private service: InventoryService) { }

    // ─── Items ─────────────────────────────────────────

    async createItem(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.createItem(
                req.params.workspaceId as string,
                req.user.userId,
                req.body,
            );
            res.status(StatusCodes.CREATED).json({
                success: true,
                message: 'Inventory item created successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async getItems(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getItems(req.params.workspaceId as string, req.query as any);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Inventory items retrieved successfully',
                data: data.data,
                pagination: data.pagination,
            });
        } catch (error) {
            next(error);
        }
    }

    async getItem(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getItem(req.params.itemId as string, req.params.workspaceId as string);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Inventory item retrieved successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async updateItem(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.updateItem(
                req.params.itemId as string,
                req.params.workspaceId as string,
                req.user.userId,
                req.body,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Inventory item updated successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async deactivateItem(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.deactivateItem(
                req.params.itemId as string,
                req.params.workspaceId as string,
                req.user.userId,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Inventory item deactivated successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    // ─── Transactions ──────────────────────────────────

    async createTransaction(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.createTransaction(
                req.params.workspaceId as string,
                req.user.userId,
                req.body,
            );
            res.status(StatusCodes.CREATED).json({
                success: true,
                message: 'Inventory transaction created successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async getTransactions(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getTransactions(req.params.workspaceId as string, req.query as any);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Inventory transactions retrieved successfully',
                data: data.data,
                pagination: data.pagination,
            });
        } catch (error) {
            next(error);
        }
    }

    // ─── Reports ───────────────────────────────────────

    async getStockLevels(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getStockLevels(req.params.workspaceId as string);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Stock levels retrieved successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async getValuation(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getInventoryValuation(req.params.workspaceId as string);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Inventory valuation retrieved successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async getMovements(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getStockMovementHistory(
                req.params.workspaceId as string,
                req.params.itemId as string,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Stock movement history retrieved successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async getCogs(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getCogsSummary(req.params.workspaceId as string, req.query as any);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'COGS summary retrieved successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async getLowStock(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getLowStockAlerts(req.params.workspaceId as string);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Low stock alerts retrieved successfully',
                data,
            });
        } catch (error) {
            next(error);
        }
    }
}

import { injectable } from 'tsyringe';
import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { PlatformService } from './platform.service';
import { PlatformSettingsService } from './platform-settings.service';
import { gbToBytes } from '../storage/storage-quota.service';
import { AuthenticatedRequest } from '../../core/types';

const page = (v: unknown) => Math.max(1, Number(v) || 1);
const limit = (v: unknown) => Math.min(100, Math.max(1, Number(v) || 20));

@injectable()
export class PlatformController {
    constructor(
        private service: PlatformService,
        private settings: PlatformSettingsService,
    ) { }

    async getStats(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.getStats();
            res.status(StatusCodes.OK).json({ success: true, message: 'Platform stats', data });
        } catch (error) {
            next(error);
        }
    }

    async listUsers(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.service.listUsers({
                page: page(req.query.page),
                limit: limit(req.query.limit),
                search: req.query.search as string | undefined,
            });
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Users retrieved',
                data: result.data,
                pagination: {
                    page: result.page,
                    limit: result.limit,
                    total: result.total,
                    totalPages: Math.ceil(result.total / result.limit),
                },
            });
        } catch (error) {
            next(error);
        }
    }

    async toggleUserStatus(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.toggleUserStatus(
                req.params.userId as string,
                req.user.userId,
            );
            res.status(StatusCodes.OK).json({
                success: true,
                message: data.isActive ? 'User activated' : 'User deactivated',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async listWorkspaces(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.service.listWorkspaces({
                page: page(req.query.page),
                limit: limit(req.query.limit),
                search: req.query.search as string | undefined,
            });
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Workspaces retrieved',
                data: result.data,
                pagination: {
                    page: result.page,
                    limit: result.limit,
                    total: result.total,
                    totalPages: Math.ceil(result.total / result.limit),
                },
            });
        } catch (error) {
            next(error);
        }
    }

    async setWorkspaceFeature(
        req: AuthenticatedRequest, res: Response, next: NextFunction,
    ): Promise<void> {
        try {
            const data = await this.service.setWorkspaceFeature({
                workspaceId: req.params.workspaceId as string,
                feature: req.body.feature,
                enabled: req.body.enabled,
                actorId: req.user.userId,
            });
            res.status(StatusCodes.OK).json({
                success: true,
                message: req.body.enabled
                    ? `${req.body.feature} enabled for this workspace`
                    : `${req.body.feature} disabled for this workspace`,
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async listAuditLogs(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.service.listAuditLogs({
                page: page(req.query.page),
                limit: limit(req.query.limit),
                action: req.query.action as string | undefined,
                workspaceId: req.query.workspaceId as string | undefined,
            });
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Audit logs retrieved',
                data: result.data,
                pagination: {
                    page: result.page,
                    limit: result.limit,
                    total: result.total,
                    totalPages: Math.ceil(result.total / result.limit),
                },
            });
        } catch (error) {
            next(error);
        }
    }

    async listSuperAdmins(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.listSuperAdmins();
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Superadmins are managed by the SUPER_ADMIN_EMAILS environment variable',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    /** Re-sync the database with the env var without waiting for a restart. */
    async reconcileSuperAdmins(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.reconcileSuperAdmins();
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Superadmins reconciled with configuration',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async setReferralAgent(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.service.setReferralAgent({
                targetUserId: req.params.userId as string,
                actorId: req.user.userId,
                isActive: req.body.isActive,
                notes: req.body.notes,
            });
            res.status(StatusCodes.OK).json({
                success: true,
                message: data.isActive ? 'Referral agent appointed' : 'Referral agent revoked',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async listReferralAgents(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.service.listReferralAgents({
                page: page(req.query.page),
                limit: limit(req.query.limit),
                search: req.query.search as string | undefined,
            });
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Referral agents retrieved',
                data: result.data,
                pagination: {
                    page: result.page,
                    limit: result.limit,
                    total: result.total,
                    totalPages: Math.ceil(result.total / result.limit),
                },
            });
        } catch (error) {
            next(error);
        }
    }

    async listAgentReferrals(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const result = await this.service.listAgentReferrals(req.params.agentId as string, {
                page: page(req.query.page),
                limit: limit(req.query.limit),
            });
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Referrals retrieved',
                data: result.data,
                agent: result.agent,
                pagination: {
                    page: result.page,
                    limit: result.limit,
                    total: result.total,
                    totalPages: Math.ceil(result.total / result.limit),
                },
            });
        } catch (error) {
            next(error);
        }
    }

    // ─── Platform-wide settings ────────────────────────

    async getSettings(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            const data = await this.settings.getAll();
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Platform settings retrieved',
                data,
            });
        } catch (error) {
            next(error);
        }
    }

    async updateSettings(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
        try {
            let data = await this.settings.getAll();
            const changed: string[] = [];

            if (req.body.manualContactsEnabled !== undefined) {
                data = await this.settings.setManualContacts(req.body.manualContactsEnabled, req.user.userId);
                changed.push(data.manualContactsEnabled
                    ? 'Manual contacts switched on for every workspace'
                    : 'Manual contacts switched off for every workspace');
            }
            if (req.body.defaultStorageQuotaGb !== undefined) {
                data = await this.settings.setDefaultStorageQuota(
                    gbToBytes(req.body.defaultStorageQuotaGb),
                    req.user.userId,
                );
                changed.push('Default storage allowance updated');
            }

            res.status(StatusCodes.OK).json({ success: true, message: changed.join('. '), data });
        } catch (error) {
            next(error);
        }
    }
}

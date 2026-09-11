/**
 * Thin, as every controller here is: unpack the request, call a service, shape
 * the envelope. The one thing worth noting is `actor` — the guard has already
 * resolved role, staff tag and effective capabilities, and every service method
 * takes that rather than re-deriving it. Two derivations of "may this person
 * void a sale" is one too many.
 */
import { injectable } from 'tsyringe';
import { Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { AuthenticatedRequest, StaffTag, WorkspaceRole } from '../../core/types';
import { WorkspacePermission } from '../../core/types/workspace-permissions';
import { TicketingService, DeskActor } from './ticketing.service';
import { TicketingConfigService } from './ticketing-config.service';
import { MembershipsService } from './memberships.service';
import { TicketingAnalyticsService } from './ticketing-analytics.service';

const ok = (res: Response, message: string, data: unknown, status = StatusCodes.OK) =>
    res.status(status).json({ success: true, message, data });

function actorOf(req: AuthenticatedRequest): DeskActor {
    const r = req as any;
    return {
        userId: req.user.userId,
        role: r.workspaceRole as WorkspaceRole,
        staffTag: (r.staffTag as StaffTag | null) ?? null,
        capabilities: (r.ticketCapabilities as Set<WorkspacePermission>) ?? new Set(),
    };
}

const wsId = (req: AuthenticatedRequest) => req.params.workspaceId as string;

@injectable()
export class TicketingController {
    constructor(
        private ticketing: TicketingService,
        private config: TicketingConfigService,
        private memberships: MembershipsService,
        private analytics: TicketingAnalyticsService,
    ) { }

    // ─── Desk ─────────────────────────────────────────

    async getAccess(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const enabled = (req as any).ticketingEnabled !== false;
            ok(res, 'Ticketing access', await this.ticketing.getAccess(wsId(req), actorOf(req), enabled));
        } catch (error) { next(error); }
    }

    async getToday(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, "Today's session", await this.ticketing.getToday(wsId(req), actorOf(req)));
        } catch (error) { next(error); }
    }

    async quote(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Price quote', await this.ticketing.quote(wsId(req), req.body));
        } catch (error) { next(error); }
    }

    async ensurePaymentModeForAccount(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const paymentMode = await this.ticketing.ensurePaymentModeForAccount(
                wsId(req), req.params.accountId as string, req.user.userId,
            );
            ok(res, 'Payment method ready', paymentMode);
        } catch (error) { next(error); }
    }

    async createSale(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const sale = await this.ticketing.createSale(wsId(req), actorOf(req), req.body);
            ok(res, 'Payment recorded', sale, StatusCodes.CREATED);
        } catch (error) { next(error); }
    }

    async listSales(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const result = await this.ticketing.listSales(wsId(req), actorOf(req), req.query as any);
            res.status(StatusCodes.OK).json({
                success: true,
                message: 'Ticket sales',
                data: result.data,
                businessDate: result.businessDate,
                totals: result.totals,
                pagination: result.pagination,
            });
        } catch (error) { next(error); }
    }

    async getSale(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Ticket sale', await this.ticketing.getSale(wsId(req), req.params.saleId as string));
        } catch (error) { next(error); }
    }

    async voidSale(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const sale = await this.ticketing.voidSale(
                wsId(req), req.params.saleId as string, actorOf(req), req.body,
            );
            ok(res, 'Payment reversed', sale);
        } catch (error) { next(error); }
    }

    // ─── Days ─────────────────────────────────────────

    async listDays(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const result = await this.ticketing.listDays(wsId(req), req.query as any);
            res.status(StatusCodes.OK).json({
                success: true, message: 'Ticket days',
                data: result.data, pagination: result.pagination,
            });
        } catch (error) { next(error); }
    }

    async getDaySummary(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Day summary',
                await this.ticketing.getDaySummary(wsId(req), req.params.dayId as string));
        } catch (error) { next(error); }
    }

    async closeDay(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Day closed and reconciled', await this.ticketing.closeDay(
                wsId(req), req.params.dayId as string, actorOf(req), req.body,
            ));
        } catch (error) { next(error); }
    }

    async reopenDay(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Day reopened', await this.ticketing.reopenDay(
                wsId(req), req.params.dayId as string, actorOf(req), req.body,
            ));
        } catch (error) { next(error); }
    }

    // ─── Shifts ───────────────────────────────────────

    async openShift(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const shift = await this.ticketing.openShift(wsId(req), actorOf(req), req.body);
            ok(res, 'Drawer opened', shift, StatusCodes.CREATED);
        } catch (error) { next(error); }
    }

    async closeShift(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Drawer counted in', await this.ticketing.closeShift(
                wsId(req), req.params.shiftId as string, actorOf(req), req.body,
            ));
        } catch (error) { next(error); }
    }

    async listShifts(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Shifts', await this.ticketing.listShifts(
                wsId(req), req.query.ticketDayId as string | undefined,
            ));
        } catch (error) { next(error); }
    }

    // ─── Settings and configuration ───────────────────

    async getSettings(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Ticketing settings', await this.config.getSettings(wsId(req)));
        } catch (error) { next(error); }
    }

    async updateSettings(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Settings saved',
                await this.config.updateSettings(wsId(req), req.user.userId, req.body));
        } catch (error) { next(error); }
    }

    async provision(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const result = await this.config.provision(wsId(req), req.user.userId, req.body);
            ok(res, 'Gate book created', result, StatusCodes.CREATED);
        } catch (error) { next(error); }
    }

    async listSessions(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Sessions', await this.config.listSessions(wsId(req)));
        } catch (error) { next(error); }
    }

    async createSession(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const session = await this.config.createSession(wsId(req), req.user.userId, req.body);
            ok(res, 'Session created', session, StatusCodes.CREATED);
        } catch (error) { next(error); }
    }

    async updateSession(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Session updated', await this.config.updateSession(
                wsId(req), req.params.sessionId as string, req.user.userId, req.body,
            ));
        } catch (error) { next(error); }
    }

    async deleteSession(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Session removed', await this.config.deleteSession(
                wsId(req), req.params.sessionId as string, req.user.userId,
            ));
        } catch (error) { next(error); }
    }

    async createTicketType(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const type = await this.config.createTicketType(
                wsId(req), req.params.sessionId as string, req.user.userId, req.body,
            );
            ok(res, 'Ticket type created', type, StatusCodes.CREATED);
        } catch (error) { next(error); }
    }

    async updateTicketType(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Ticket type updated', await this.config.updateTicketType(
                wsId(req), req.params.typeId as string, req.user.userId, req.body,
            ));
        } catch (error) { next(error); }
    }

    async deleteTicketType(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Ticket type removed', await this.config.deleteTicketType(
                wsId(req), req.params.typeId as string, req.user.userId,
            ));
        } catch (error) { next(error); }
    }

    async createRule(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const rule = await this.config.createDiscountRule(wsId(req), req.user.userId, req.body);
            ok(res, 'Offer created', rule, StatusCodes.CREATED);
        } catch (error) { next(error); }
    }

    async updateRule(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Offer updated', await this.config.updateDiscountRule(
                wsId(req), req.params.ruleId as string, req.user.userId, req.body,
            ));
        } catch (error) { next(error); }
    }

    async deleteRule(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Offer removed', await this.config.deleteDiscountRule(
                wsId(req), req.params.ruleId as string, req.user.userId,
            ));
        } catch (error) { next(error); }
    }

    // ─── Memberships ──────────────────────────────────

    async listTiers(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Membership tiers', await this.memberships.listTiers(wsId(req)));
        } catch (error) { next(error); }
    }

    async createTier(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const tier = await this.memberships.createTier(wsId(req), req.user.userId, req.body);
            ok(res, 'Tier created', tier, StatusCodes.CREATED);
        } catch (error) { next(error); }
    }

    async updateTier(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Tier updated', await this.memberships.updateTier(
                wsId(req), req.params.tierId as string, req.user.userId, req.body,
            ));
        } catch (error) { next(error); }
    }

    async listMemberships(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const result = await this.memberships.list(wsId(req), req.query as any);
            res.status(StatusCodes.OK).json({
                success: true, message: 'Memberships',
                data: result.data, pagination: result.pagination,
            });
        } catch (error) { next(error); }
    }

    async lookupMembership(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Membership lookup',
                await this.memberships.lookup(wsId(req), req.query.memberNo as string));
        } catch (error) { next(error); }
    }

    async createMembership(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            const membership = await this.memberships.create(
                wsId(req), req.user.userId, req.body,
            );
            ok(res, 'Membership issued', membership, StatusCodes.CREATED);
        } catch (error) { next(error); }
    }

    async updateMembership(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Membership updated', await this.memberships.update(
                wsId(req), req.params.membershipId as string, req.user.userId, req.body,
            ));
        } catch (error) { next(error); }
    }

    async renewMembership(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Membership renewed', await this.memberships.renew(
                wsId(req), req.params.membershipId as string, req.user.userId, req.body,
            ));
        } catch (error) { next(error); }
    }

    async getMembershipUsage(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Membership usage', await this.memberships.getUsage(
                wsId(req), req.params.membershipId as string,
            ));
        } catch (error) { next(error); }
    }

    // ─── Analytics ────────────────────────────────────

    async analyticsSummary(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Ticket summary', await this.analytics.summary(wsId(req), req.query as any));
        } catch (error) { next(error); }
    }

    async analyticsByType(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Sales by ticket type',
                await this.analytics.byType(wsId(req), req.query as any));
        } catch (error) { next(error); }
    }

    async analyticsByAttendant(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Sales by attendant',
                await this.analytics.byAttendant(wsId(req), req.query as any));
        } catch (error) { next(error); }
    }

    async analyticsMemberships(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        try {
            ok(res, 'Membership analytics',
                await this.analytics.memberships(wsId(req), req.query as any));
        } catch (error) { next(error); }
    }
}

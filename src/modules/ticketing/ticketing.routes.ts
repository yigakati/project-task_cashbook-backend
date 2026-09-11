import { Router } from 'express';
import { container } from 'tsyringe';
import { TicketingController } from './ticketing.controller';
import { authenticate } from '../../middlewares/authenticate';
import { requireTicketing } from '../../middlewares/authorize';
import { WorkspacePermission as P } from '../../core/types/workspace-permissions';
import { validate } from '../../middlewares/validate';
import { uuidParams } from '../../middlewares/uuidParam';
import { idempotency } from '../../middlewares/idempotency';
import {
    updateTicketSettingsSchema,
    provisionTicketingSchema,
    createSessionSchema,
    updateSessionSchema,
    createTicketTypeSchema,
    updateTicketTypeSchema,
    createDiscountRuleSchema,
    updateDiscountRuleSchema,
    quoteSaleSchema,
    createSaleSchema,
    voidSaleSchema,
    listSalesSchema,
    listDaysSchema,
    closeDaySchema,
    openShiftSchema,
    closeShiftSchema,
    createMembershipTierSchema,
    updateMembershipTierSchema,
    createMembershipSchema,
    updateMembershipSchema,
    renewMembershipSchema,
    listMembershipsSchema,
    lookupMembershipSchema,
    analyticsRangeSchema,
} from './ticketing.dto';

const router = Router({ mergeParams: true });
const controller = container.resolve(TicketingController);

router.use(authenticate as any);

/*
 * Every route is gated by `requireTicketing`, which checks two things no other
 * guard does: that a superadmin has unlocked ticketing for this organisation (a
 * workspace without it gets 404, not 403), and that the caller's ROLE OR STAFF
 * TAG grants the permission. A ticket attendant is a plain MEMBER carrying the
 * TICKETING tag — see core/authz/ticketing-access.ts for why that resolution
 * lives outside the role matrix.
 *
 * Row-level authority stays in the services, following the same split the tasks
 * module documents. "May you void a sale" is a route question; "may you void
 * THIS sale, on THIS day" depends on who rang it up and whether the day is
 * still open, and no route-level permission can express that.
 *
 * Literal paths are declared before `/:param` paths throughout. Express matches
 * in declaration order, and there is a regression test for it:
 * src/test/routing/route-shadowing.test.ts
 */

// ─── Desk ─────────────────────────────────────────────

// Answers "is ticketing on here, and what may I do?" — so "no" is an answer,
// not a missing resource. Every other ticketing route still 404s when the
// module is off; this one reports it, after the same membership check.
router.get(
    '/access',
    requireTicketing(undefined, { reportDisabled: true }) as any,
    controller.getAccess.bind(controller) as any,
);

router.get(
    '/today',
    requireTicketing(P.VIEW_TICKETING) as any,
    controller.getToday.bind(controller) as any,
);

router.post(
    '/quote',
    requireTicketing(P.SELL_TICKETS) as any,
    validate(quoteSaleSchema),
    controller.quote.bind(controller) as any,
);

/*
 * The payment method that goes with a wallet, get-or-create.
 *
 * Called the moment the attendant picks a wallet, so the payment-mode field
 * fills itself in rather than asking the same thing twice. Get-or-create is
 * naturally idempotent (the unique constraint on the payment mode's name is
 * what stops a duplicate, not this route), so no Idempotency-Key here — unlike
 * the sale below, a double-tap costs nothing.
 */
router.post(
    '/accounts/:accountId/payment-mode',
    requireTicketing(P.SELL_TICKETS) as any,
    validate(uuidParams('accountId'), 'params'),
    controller.ensurePaymentModeForAccount.bind(controller) as any,
);

/*
 * Confirming a sale.
 *
 * Idempotency-keyed like every other financial write in this codebase. A gate
 * attendant double-tapping confirm on a slow connection is the single most
 * likely way to charge somebody twice, and the middleware replays the stored
 * response instead.
 */
router.post(
    '/sales',
    requireTicketing(P.SELL_TICKETS) as any,
    idempotency('POST /workspaces/:workspaceId/ticketing/sales') as any,
    validate(createSaleSchema),
    controller.createSale.bind(controller) as any,
);

router.get(
    '/sales',
    requireTicketing(P.VIEW_TICKETING) as any,
    validate(listSalesSchema, 'query'),
    controller.listSales.bind(controller) as any,
);

router.get(
    '/sales/:saleId',
    requireTicketing(P.VIEW_TICKETING) as any,
    validate(uuidParams('saleId'), 'params'),
    controller.getSale.bind(controller) as any,
);

router.post(
    '/sales/:saleId/void',
    requireTicketing(P.VOID_TICKET_SALE) as any,
    validate(uuidParams('saleId'), 'params'),
    validate(voidSaleSchema),
    controller.voidSale.bind(controller) as any,
);

// ─── Days ─────────────────────────────────────────────

router.get(
    '/days',
    requireTicketing(P.VIEW_TICKETING) as any,
    validate(listDaysSchema, 'query'),
    controller.listDays.bind(controller) as any,
);

router.get(
    '/days/:dayId',
    requireTicketing(P.VIEW_TICKETING) as any,
    validate(uuidParams('dayId'), 'params'),
    controller.getDaySummary.bind(controller) as any,
);

router.post(
    '/days/:dayId/close',
    requireTicketing(P.RECONCILE_TICKET_SHIFT) as any,
    validate(uuidParams('dayId'), 'params'),
    validate(closeDaySchema),
    controller.closeDay.bind(controller) as any,
);

// Reopening unreconciles a closed day, so it is a manager action rather than a
// reconciliation one.
router.post(
    '/days/:dayId/reopen',
    requireTicketing(P.MANAGE_TICKETING) as any,
    validate(uuidParams('dayId'), 'params'),
    validate(closeDaySchema),
    controller.reopenDay.bind(controller) as any,
);

// ─── Shifts ───────────────────────────────────────────

router.get(
    '/shifts',
    requireTicketing(P.VIEW_TICKETING) as any,
    controller.listShifts.bind(controller) as any,
);

router.post(
    '/shifts/open',
    requireTicketing(P.SELL_TICKETS) as any,
    validate(openShiftSchema),
    controller.openShift.bind(controller) as any,
);

/*
 * Counting the drawer in.
 *
 * Gated on SELL_TICKETS rather than RECONCILE_TICKET_SHIFT so an attendant can
 * close their OWN drawer at the end of a night without waiting for a supervisor;
 * the service refuses somebody else's unless the caller can reconcile.
 */
router.post(
    '/shifts/:shiftId/close',
    requireTicketing(P.SELL_TICKETS) as any,
    validate(uuidParams('shiftId'), 'params'),
    validate(closeShiftSchema),
    controller.closeShift.bind(controller) as any,
);

// ─── Settings ─────────────────────────────────────────

router.get(
    '/settings',
    requireTicketing(P.MANAGE_TICKETING) as any,
    controller.getSettings.bind(controller) as any,
);

router.patch(
    '/settings',
    requireTicketing(P.MANAGE_TICKETING) as any,
    validate(updateTicketSettingsSchema),
    controller.updateSettings.bind(controller) as any,
);

router.post(
    '/settings/provision',
    requireTicketing(P.MANAGE_TICKETING) as any,
    validate(provisionTicketingSchema),
    controller.provision.bind(controller) as any,
);

// ─── Sessions, tiers and offers ───────────────────────

router.get(
    '/sessions',
    requireTicketing(P.MANAGE_TICKETING) as any,
    controller.listSessions.bind(controller) as any,
);

router.post(
    '/sessions',
    requireTicketing(P.MANAGE_TICKETING) as any,
    validate(createSessionSchema),
    controller.createSession.bind(controller) as any,
);

router.patch(
    '/sessions/:sessionId',
    requireTicketing(P.MANAGE_TICKETING) as any,
    validate(uuidParams('sessionId'), 'params'),
    validate(updateSessionSchema),
    controller.updateSession.bind(controller) as any,
);

router.delete(
    '/sessions/:sessionId',
    requireTicketing(P.MANAGE_TICKETING) as any,
    validate(uuidParams('sessionId'), 'params'),
    controller.deleteSession.bind(controller) as any,
);

router.post(
    '/sessions/:sessionId/types',
    requireTicketing(P.MANAGE_TICKETING) as any,
    validate(uuidParams('sessionId'), 'params'),
    validate(createTicketTypeSchema),
    controller.createTicketType.bind(controller) as any,
);

router.patch(
    '/types/:typeId',
    requireTicketing(P.MANAGE_TICKETING) as any,
    validate(uuidParams('typeId'), 'params'),
    validate(updateTicketTypeSchema),
    controller.updateTicketType.bind(controller) as any,
);

router.delete(
    '/types/:typeId',
    requireTicketing(P.MANAGE_TICKETING) as any,
    validate(uuidParams('typeId'), 'params'),
    controller.deleteTicketType.bind(controller) as any,
);

router.post(
    '/rules',
    requireTicketing(P.MANAGE_TICKETING) as any,
    validate(createDiscountRuleSchema),
    controller.createRule.bind(controller) as any,
);

router.patch(
    '/rules/:ruleId',
    requireTicketing(P.MANAGE_TICKETING) as any,
    validate(uuidParams('ruleId'), 'params'),
    validate(updateDiscountRuleSchema),
    controller.updateRule.bind(controller) as any,
);

router.delete(
    '/rules/:ruleId',
    requireTicketing(P.MANAGE_TICKETING) as any,
    validate(uuidParams('ruleId'), 'params'),
    controller.deleteRule.bind(controller) as any,
);

// ─── Memberships ──────────────────────────────────────

router.get(
    '/membership-tiers',
    requireTicketing(P.VIEW_TICKETING) as any,
    controller.listTiers.bind(controller) as any,
);

router.post(
    '/membership-tiers',
    requireTicketing(P.MANAGE_MEMBERSHIPS) as any,
    validate(createMembershipTierSchema),
    controller.createTier.bind(controller) as any,
);

router.patch(
    '/membership-tiers/:tierId',
    requireTicketing(P.MANAGE_MEMBERSHIPS) as any,
    validate(uuidParams('tierId'), 'params'),
    validate(updateMembershipTierSchema),
    controller.updateTier.bind(controller) as any,
);

/*
 * The desk lookup, before `/memberships/:membershipId` so a literal path is not
 * shadowed by the dynamic one.
 *
 * Gated on SELL_TICKETS rather than MANAGE_MEMBERSHIPS: an attendant must be
 * able to check a card at the gate, and the response carries the tier and
 * validity only — not the member's contact history.
 */
router.get(
    '/memberships/lookup',
    requireTicketing(P.SELL_TICKETS) as any,
    validate(lookupMembershipSchema, 'query'),
    controller.lookupMembership.bind(controller) as any,
);

router.get(
    '/memberships',
    requireTicketing(P.MANAGE_MEMBERSHIPS) as any,
    validate(listMembershipsSchema, 'query'),
    controller.listMemberships.bind(controller) as any,
);

router.post(
    '/memberships',
    requireTicketing(P.MANAGE_MEMBERSHIPS) as any,
    idempotency('POST /workspaces/:workspaceId/ticketing/memberships') as any,
    validate(createMembershipSchema),
    controller.createMembership.bind(controller) as any,
);

router.get(
    '/memberships/:membershipId/usage',
    requireTicketing(P.MANAGE_MEMBERSHIPS) as any,
    validate(uuidParams('membershipId'), 'params'),
    controller.getMembershipUsage.bind(controller) as any,
);

router.patch(
    '/memberships/:membershipId',
    requireTicketing(P.MANAGE_MEMBERSHIPS) as any,
    validate(uuidParams('membershipId'), 'params'),
    validate(updateMembershipSchema),
    controller.updateMembership.bind(controller) as any,
);

router.post(
    '/memberships/:membershipId/renew',
    requireTicketing(P.MANAGE_MEMBERSHIPS) as any,
    idempotency('POST /workspaces/:workspaceId/ticketing/memberships/:membershipId/renew') as any,
    validate(uuidParams('membershipId'), 'params'),
    validate(renewMembershipSchema),
    controller.renewMembership.bind(controller) as any,
);

// ─── Analytics ────────────────────────────────────────

router.get(
    '/analytics/summary',
    requireTicketing(P.VIEW_TICKET_ANALYTICS) as any,
    validate(analyticsRangeSchema, 'query'),
    controller.analyticsSummary.bind(controller) as any,
);

router.get(
    '/analytics/by-type',
    requireTicketing(P.VIEW_TICKET_ANALYTICS) as any,
    validate(analyticsRangeSchema, 'query'),
    controller.analyticsByType.bind(controller) as any,
);

router.get(
    '/analytics/by-attendant',
    requireTicketing(P.VIEW_TICKET_ANALYTICS) as any,
    validate(analyticsRangeSchema, 'query'),
    controller.analyticsByAttendant.bind(controller) as any,
);

router.get(
    '/analytics/memberships',
    requireTicketing(P.VIEW_TICKET_ANALYTICS) as any,
    validate(analyticsRangeSchema, 'query'),
    controller.analyticsMemberships.bind(controller) as any,
);

export default router;

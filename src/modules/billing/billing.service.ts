import { injectable, inject } from 'tsyringe';
import { randomUUID } from 'node:crypto';
import { DateTime } from 'luxon';
import {
    Prisma,
    PrismaClient,
    SubscriptionPaymentStatus,
    SubscriptionPlan,
    SubscriptionStatus,
    WorkspaceType,
} from '@prisma/client';
import { AppError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';
import { config } from '../../config';
import { ENTERPRISE, PLANS, catalogue, quote, storageFor, type AccountPlanKey, type Plan } from '../../core/billing/plans';
import { isInForce } from '../../core/billing/entitlements';
import { logger } from '../../utils/logger';
import { normalizePhone } from './billing.dto';

/**
 * The seam a mobile-money provider plugs into.
 *
 * To go live: implement this for the chosen provider (MTN MoMo, Airtel Money,
 * or an aggregator), register it under the `PaymentProvider` token in
 * config/container.ts with `enabled = true`, and add the provider's webhook
 * route, which verifies the provider's signature and calls
 * BillingService.settlePayment(). Nothing else changes: the routes, the
 * prices, the checkout screen and the activation rules stay as they are.
 *
 * Mobile money is asynchronous — the payer approves a prompt on their phone —
 * so charge() only asks for the payment. The plan is activated when the
 * provider confirms, never before.
 */
export interface PaymentProvider {
    readonly name: string;
    readonly enabled: boolean;
    charge(input: { amountUgx: number; phone: string; description: string; reference: string }): Promise<
        { status: 'PENDING'; providerReference?: string } | { status: 'FAILED'; reason: string }
    >;
}

export const PAYMENTS_COMING_SOON =
    'Subscriptions are not open yet. We are finishing mobile-money payments — they will be available soon.';

/** The provider in place until one is chosen: takes nothing, refuses clearly. */
@injectable()
export class NotConfiguredPaymentProvider implements PaymentProvider {
    readonly name = 'none';
    readonly enabled = false;

    async charge(): Promise<never> {
        throw new AppError(PAYMENTS_COMING_SOON, 503, 'PAYMENTS_COMING_SOON');
    }
}

/** How long one payment prompt is left to the payer before another may be sent. */
const PROMPT_WINDOW_MS = 2 * 60 * 1000;

/** "+256 77• ••• 567" — enough to recognise a payment, not to reuse the number. */
export const maskPhone = (normalized: string) => {
    const local = normalized.replace(/^\+256/, '');
    return `+256 ${local.slice(0, 2)}• ••• ${local.slice(-3)}`;
};

export interface AccountPlan {
    plan: AccountPlanKey;
    name: string;
    status: 'ACTIVE' | 'CANCELLED';
    extraStorageGb: number;
    includedStorageGb: number;
    storageGb: number;
    maxStorageGb: number;
    /** Business workspaces allowed; null means unlimited (Enterprise). */
    businessWorkspaces: number | null;
    ownedBusinessWorkspaces: number;
    /** Whether the workspace limit is applied yet (PLAN_LIMITS_ENFORCED). */
    limitsEnforced: boolean;
    priceUgx: number;
    currentPeriodEnd: string | null;
    /** False until payments go live; the app shows checkout as "coming soon". */
    paymentsEnabled: boolean;
}

type PaidPlan = 'STARTER' | 'GROWTH';

@injectable()
export class BillingService {
    constructor(
        @inject('PrismaClient') private prisma: PrismaClient,
        @inject('PaymentProvider') private provider: PaymentProvider,
    ) { }

    catalogue() {
        return { ...catalogue(), paymentsEnabled: this.provider.enabled };
    }

    quote(plan: AccountPlanKey, extraStorageGb: number) {
        const definition = plan === 'ENTERPRISE' ? undefined : PLANS[plan];
        if (!definition) {
            throw new AppError('Enterprise plans are arranged with us — contact support.', 400, 'PLAN_NOT_QUOTABLE');
        }
        return { ...quote(definition, extraStorageGb), paymentsEnabled: this.provider.enabled };
    }

    /** The plan in force for an account. No row, a cancelled row or a lapsed period reads as Free. */
    async account(userId: string, now = new Date()): Promise<AccountPlan> {
        const [row, ownedBusinessWorkspaces] = await Promise.all([
            this.prisma.userSubscription.findUnique({ where: { userId } }),
            this.prisma.workspace.count({ where: { ownerId: userId, type: WorkspaceType.BUSINESS, isActive: true } }),
        ]);
        const inForce = isInForce(row, now);
        const key = (inForce && row ? row.plan : SubscriptionPlan.FREE) as AccountPlanKey;
        const extraStorageGb = inForce && row ? Number(row.extraStorageGb) : 0;
        // Enterprise has no fixed limits here; it is set up by arrangement.
        const plan: Plan | null = key === 'ENTERPRISE' ? null : PLANS[key];
        return {
            plan: key,
            name: plan?.name ?? ENTERPRISE.name,
            status: inForce ? 'ACTIVE' : (row?.status ?? SubscriptionStatus.ACTIVE) as AccountPlan['status'],
            extraStorageGb,
            includedStorageGb: plan?.includedStorageGb ?? 0,
            storageGb: plan ? storageFor(plan, extraStorageGb) : 0,
            maxStorageGb: plan?.maxStorageGb ?? 0,
            businessWorkspaces: plan?.businessWorkspaces ?? null,
            ownedBusinessWorkspaces,
            limitsEnforced: config.PLAN_LIMITS_ENFORCED,
            priceUgx: plan?.priceUgx ?? 0,
            currentPeriodEnd: inForce ? row?.currentPeriodEnd?.toISOString() ?? null : null,
            paymentsEnabled: this.provider.enabled,
        };
    }

    /**
     * Ask the payer's phone for the plan's price.
     *
     * The amount is computed here from the catalogue, never taken from the
     * client. The attempt is recorded under a reference of our own before the
     * provider is called, so its confirmation always has a row to settle.
     * With payments off this refuses before writing anything.
     */
    async checkout(userId: string, dto: { plan: PaidPlan; extraStorageGb: number; phone: string }, now = new Date()) {
        if (!this.provider.enabled) {
            throw new AppError(PAYMENTS_COMING_SOON, 503, 'PAYMENTS_COMING_SOON');
        }

        const priced = this.quote(dto.plan, dto.extraStorageGb);
        if (priced.totalUgx <= 0) throw new AppError('There is nothing to pay for this plan.', 400, 'NOTHING_TO_PAY');
        const phone = normalizePhone(dto.phone);
        const reference = `inch_${randomUUID().replace(/-/g, '')}`;

        await this.prisma.$transaction(async (tx) => {
            // One account's checkouts in a row, so a double tap sends one prompt.
            await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(${`billing:${userId}`}, 0))`;
            const recent = await tx.subscriptionPayment.findFirst({
                where: {
                    userId,
                    status: SubscriptionPaymentStatus.PENDING,
                    createdAt: { gt: new Date(now.getTime() - PROMPT_WINDOW_MS) },
                },
                select: { id: true },
            });
            if (recent) {
                throw new AppError(
                    'A payment prompt was just sent to your phone. Approve it there, or try again in two minutes.',
                    409,
                    'PAYMENT_IN_PROGRESS',
                );
            }
            await tx.subscriptionPayment.create({
                data: {
                    userId,
                    reference,
                    provider: this.provider.name,
                    plan: dto.plan as SubscriptionPlan,
                    extraStorageGb: new Prisma.Decimal(priced.extraStorageGb),
                    amountUgx: priced.totalUgx,
                    phoneMasked: maskPhone(phone),
                },
            });
        });

        let result: Awaited<ReturnType<PaymentProvider['charge']>>;
        try {
            result = await this.provider.charge({
                amountUgx: priced.totalUgx,
                phone,
                description: `InChange ${priced.name}${priced.extraStorageGb ? ` + ${priced.extraStorageGb} GB` : ''}, 1 month`,
                reference,
            });
        } catch (error) {
            await this.markFailed(reference, (error as Error).message || 'The provider could not be reached.');
            throw error;
        }

        if (result.status === 'FAILED') {
            await this.markFailed(reference, result.reason);
            throw new AppError(result.reason || 'The payment was not accepted. Please try again.', 402, 'PAYMENT_FAILED');
        }
        if (result.providerReference) {
            await this.prisma.subscriptionPayment.update({
                where: { reference },
                data: { providerReference: result.providerReference },
            });
        }
        return { status: 'PENDING' as const, reference, amountUgx: priced.totalUgx, quote: priced };
    }

    /**
     * Settle a payment once the provider confirms it — the only place a paid
     * plan is switched on. Called by the provider's verified webhook.
     *
     * Idempotent: a payment settles once; a repeated confirmation is a no-op.
     * A successful one starts a month of the plan — straight after the current
     * period when it renews the same plan, from now when it changes plan.
     */
    async settlePayment(
        reference: string,
        outcome: { succeeded: boolean; providerReference?: string; reason?: string },
        now = new Date(),
    ): Promise<{ settled: boolean; status: SubscriptionPaymentStatus }> {
        return this.prisma.$transaction(async (tx) => {
            const claimed = await tx.subscriptionPayment.updateMany({
                where: { reference, status: SubscriptionPaymentStatus.PENDING },
                data: {
                    status: outcome.succeeded ? SubscriptionPaymentStatus.SUCCEEDED : SubscriptionPaymentStatus.FAILED,
                    settledAt: now,
                    ...(outcome.providerReference && { providerReference: outcome.providerReference }),
                    ...(!outcome.succeeded && { failureReason: outcome.reason ?? 'Declined' }),
                },
            });
            const payment = await tx.subscriptionPayment.findUnique({ where: { reference } });
            if (!payment) throw new AppError('No payment with that reference.', 404, 'NOT_FOUND');
            if (claimed.count === 0 || !outcome.succeeded) return { settled: claimed.count > 0, status: payment.status };

            const current = await tx.userSubscription.findUnique({ where: { userId: payment.userId } });
            // Renewing the same plan early continues from the current period's end.
            const renewing = current && isInForce(current, now) && current.plan === payment.plan
                && Number(current.extraStorageGb) === Number(payment.extraStorageGb)
                && current.currentPeriodEnd && current.currentPeriodEnd > now
                ? current
                : null;
            const start = renewing?.currentPeriodEnd ?? now;
            const end = DateTime.fromJSDate(start, { zone: 'utc' }).plus({ months: 1 }).toJSDate();

            const data = {
                plan: payment.plan,
                status: SubscriptionStatus.ACTIVE,
                extraStorageGb: payment.extraStorageGb,
                currentPeriodStart: renewing ? renewing.currentPeriodStart : start,
                currentPeriodEnd: end,
            };
            await tx.userSubscription.upsert({
                where: { userId: payment.userId },
                create: { userId: payment.userId, ...data },
                update: data,
            });
            await tx.auditLog.create({
                data: {
                    userId: payment.userId,
                    action: AuditAction.SUBSCRIPTION_ACTIVATED,
                    resource: 'subscription',
                    resourceId: payment.id,
                    details: {
                        plan: payment.plan, extraStorageGb: Number(payment.extraStorageGb),
                        amountUgx: payment.amountUgx, periodEnd: end.toISOString(), renewal: Boolean(renewing),
                    } as Prisma.InputJsonValue,
                },
            });
            logger.info('[Billing] Plan activated', { userId: payment.userId, plan: payment.plan, until: end.toISOString() });
            return { settled: true, status: SubscriptionPaymentStatus.SUCCEEDED };
        });
    }

    private async markFailed(reference: string, reason: string) {
        await this.prisma.subscriptionPayment.updateMany({
            where: { reference, status: SubscriptionPaymentStatus.PENDING },
            data: { status: SubscriptionPaymentStatus.FAILED, failureReason: reason.slice(0, 500), settledAt: new Date() },
        });
    }
}

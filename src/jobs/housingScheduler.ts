import { PrismaClient } from '@prisma/client';
import { DateTime } from 'luxon';
import { container } from 'tsyringe';
import { getPrismaClient } from '../config/database';
import { HousingService, periodPaid } from '../modules/housing/housing.service';
import { rentalNotify } from '../modules/housing/housing-access';
import { dbDate, isoDate } from '../modules/housing/housing-schedule';
import { housingLabel } from '../modules/housing/housing-properties.service';
import { logger } from '../utils/logger';

/** Deterministic per-period daily reminder keys survive retries and replicas.
 * Rows and notifications commit together, without depending on Redis delivery. */
export async function scanHousing(prisma: PrismaClient, service: HousingService, now = new Date()) {
    let cursor: string | undefined;
    for (;;) {
        const batch = await prisma.housingTenancy.findMany({
            where: { status: { in: ['ACTIVE', 'ENDED'] }, workspace: { isActive: true } },
            orderBy: { id: 'asc' },
            take: 100,
            ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
            select: { id: true },
        });
        if (!batch.length) break;
        for (const item of batch) {
            try {
                await prisma.$transaction(
                    async (tx) => {
                        await tx.$queryRaw`SELECT id FROM housing_tenancies WHERE id = ${item.id}::uuid FOR UPDATE`;
                        const t = await tx.housingTenancy.findUnique({
                            where: { id: item.id },
                            include: { workspace: true, unit: { include: { property: true } } },
                        });
                        if (!t || t.status === 'CANCELLED' || !t.workspace.isActive) return;
                        const local = DateTime.fromJSDate(now).setZone(t.workspace.timezone);
                        const today = local.toISODate()!;
                        await service.ensurePeriods(tx, t, local.plus({ months: 1 }).toISODate()!);
                        const periods = await tx.rentPeriod.findMany({
                            where: {
                                tenancyId: t.id,
                                cancelledAt: null,
                                dueDate: { lte: dbDate(local.plus({ days: 3 }).toISODate()!) },
                            },
                        });
                        for (const p of periods) {
                            const outstanding = p.amount.sub(await periodPaid(tx, p.id));
                            if (outstanding.lte(0)) continue;
                            const due = isoDate(p.dueDate);
                            const late = due < today;
                            // Ahead: three days before and on the due date. Arrears:
                            // weekly, not daily notifications for every old period.
                            const daysLate = Math.floor(
                                local
                                    .startOf('day')
                                    .diff(
                                        DateTime.fromISO(due, { zone: t.workspace.timezone }),
                                        'days',
                                    ).days,
                            );
                            if (
                                late
                                    ? daysLate % 7 !== 0
                                    : due !== today && due !== local.plus({ days: 3 }).toISODate()
                            )
                                continue;
                            const notice = {
                                type: 'RENT_DUE' as const,
                                entityType: 'HOUSING_TENANCY' as const,
                                entityId: t.id,
                                title: late ? 'Rent payment overdue' : 'Rent payment due',
                                body: `${housingLabel(t.unit)}: ${t.currency} ${outstanding} outstanding for ${isoDate(p.startDate)}. Due ${due}.`,
                                groupKey: `rent-due:${p.id}:${today}`,
                            };
                            await rentalNotify(tx, t.workspace.ownerId, notice, t.workspaceId);
                            if (t.invitationStatus === 'ACCEPTED')
                                await rentalNotify(tx, t.tenantUserId, notice);
                        }
                    },
                    { timeout: 20_000 },
                );
            } catch (error) {
                logger.error('Housing schedule scan failed for tenancy', {
                    tenancyId: item.id,
                    error,
                });
            }
        }
        cursor = batch[batch.length - 1].id;
    }
}
export function startHousingScheduler() {
    let running = false;
    const run = async () => {
        if (running) return;
        running = true;
        try {
            await scanHousing(getPrismaClient(), container.resolve(HousingService));
        } catch (error) {
            logger.error('Housing scheduler failed', { error });
        } finally {
            running = false;
        }
    };
    void run();
    return setInterval(() => void run(), 60 * 60 * 1000);
}

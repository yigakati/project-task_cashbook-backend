/**
 * Targets against real entries: what counts, whose it is, who can see it,
 * and the scheduled work (recurring periods and alerts).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DateTime } from 'luxon';
import { Decimal } from '@prisma/client/runtime/library';
import { EntryStatus, EntryType, WorkspaceRole, WorkspaceType } from '@prisma/client';

const emails: Array<{ to: string; subject: string }> = [];
vi.mock('../../config/email', () => ({
    sendEmail: vi.fn(async (m: { to: string; subject: string }) => { emails.push(m); }),
}));

import { resetDatabase, testPrisma } from '../../test/setup';
import { resolveService } from '../../test/container';
import { addWorkspaceMember, createCashbook, createUser, createWorkspace } from '../../test/factories';
import { TargetsService } from './targets.service';
import { WorkspaceRole as Role } from '../../core/types';
import { NotificationsService } from '../notifications/notifications.service';

const targets = () => resolveService(TargetsService);
const ZONE = 'Africa/Kampala'; // the factory's workspace timezone
const today = () => DateTime.now().setZone(ZONE).startOf('day');
const iso = (d: DateTime) => d.toISODate() as string;

/** An entry at local noon on a given local day. */
async function entry(cashbookId: string, createdById: string, o: {
    day: DateTime; amount: string; type?: EntryType; charge?: string; status?: EntryStatus;
}) {
    return testPrisma.entry.create({
        data: {
            cashbookId,
            createdById,
            type: o.type ?? EntryType.INCOME,
            amount: new Decimal(o.amount),
            chargeAmount: o.charge ? new Decimal(o.charge) : null,
            description: 'x',
            entryDate: o.day.set({ hour: 12 }).toJSDate(),
            status: o.status ?? EntryStatus.POSTED,
            isDeleted: o.status === EntryStatus.REVERSED,
        },
    });
}

async function business() {
    const owner = await createUser();
    const workspace = await createWorkspace(owner.id);
    const shop = await createCashbook(workspace.id, owner.id, { name: 'Shop' });
    const branch = await createCashbook(workspace.id, owner.id, { name: 'Branch' });
    return { owner, workspace, shop, branch };
}

const OWNER = (userId: string) => ({ userId, role: Role.OWNER });

/** A period from N days ago to M days ahead. */
const period = (fromDaysAgo: number, toDaysAhead: number) => ({
    kind: 'custom' as const,
    startDate: iso(today().minus({ days: fromDaysAgo })),
    endDate: iso(today().plus({ days: toDaysAhead })),
});

const base = {
    source: 'BOOKS' as 'BOOKS' | 'MANUAL',
    metric: 'MONEY_IN' as const,
    workingDays: [1, 2, 3, 4, 5, 6, 7],
    cashbookIds: [] as string[],
    assigneeId: null,
    openingAmount: '0',
    repeats: false,
    alertsEnabled: true,
    emailAlerts: false,
    remindToRecord: false,
};
const manual = { ...base, source: 'MANUAL' as const };

describe('targets', () => {
    beforeEach(async () => {
        await resetDatabase();
        emails.length = 0;
    });
    afterEach(() => vi.restoreAllMocks());

    describe('what counts', () => {
        it('adds up income across every book, inside the period, posted only', async () => {
            const { owner, workspace, shop, branch } = await business();
            await entry(shop.id, owner.id, { day: today().minus({ days: 1 }), amount: '300' });
            await entry(branch.id, owner.id, { day: today(), amount: '200' });
            await entry(shop.id, owner.id, { day: today(), amount: '999', type: EntryType.EXPENSE });
            await entry(shop.id, owner.id, { day: today(), amount: '999', status: EntryStatus.REVERSED });
            await entry(shop.id, owner.id, { day: today().minus({ days: 40 }), amount: '999' }); // before the period

            const target = await targets().create(workspace.id, owner.id, {
                ...base, name: 'Sales', amount: '10000', period: period(9, 0),
            });

            expect(target.progress.achieved).toBe('500.00');
            expect(target.progress.todayAchieved).toBe('200.00');
            expect(target.currency).toBe('UGX');
        });

        it('can be limited to some books, or to what one person recorded', async () => {
            const { owner, workspace, shop, branch } = await business();
            const cashier = await createUser();
            await addWorkspaceMember(workspace.id, cashier.id, WorkspaceRole.MEMBER);
            await entry(shop.id, cashier.id, { day: today(), amount: '100' });
            await entry(branch.id, cashier.id, { day: today(), amount: '40' });
            await entry(shop.id, owner.id, { day: today(), amount: '1000' });

            const shopOnly = await targets().create(workspace.id, owner.id, {
                ...base, name: 'Shop', amount: '5000', period: period(0, 9), cashbookIds: [shop.id],
            });
            const cashierOwn = await targets().create(workspace.id, owner.id, {
                ...base, name: 'Cashier', amount: '5000', period: period(0, 9), assigneeId: cashier.id,
            });

            expect(shopOnly.progress.achieved).toBe('1100.00');
            expect(cashierOwn.progress.achieved).toBe('140.00');
        });

        it('measures net as income less expenses and charges', async () => {
            const { owner, workspace, shop } = await business();
            await entry(shop.id, owner.id, { day: today(), amount: '1000', charge: '10' });
            await entry(shop.id, owner.id, { day: today(), amount: '300', type: EntryType.EXPENSE, charge: '5' });

            const target = await targets().create(workspace.id, owner.id, {
                ...base, metric: 'NET', name: 'Profit', amount: '5000', period: period(0, 9),
            });
            expect(target.progress.achieved).toBe('685.00'); // 1000 − 10 − 300 − 5
        });

        it('counts an entry on the day it happened in the workspace timezone', async () => {
            const { owner, workspace, shop } = await business();
            // 22:30 UTC is already 01:30 the next day in Kampala (UTC+3).
            const yesterday = today().minus({ days: 1 });
            await testPrisma.entry.create({
                data: {
                    cashbookId: shop.id, createdById: owner.id, type: EntryType.INCOME, amount: new Decimal('50'),
                    description: 'late', status: EntryStatus.POSTED,
                    entryDate: yesterday.set({ hour: 1, minute: 30 }).toUTC().toJSDate(),
                },
            });
            const target = await targets().create(workspace.id, owner.id, {
                ...base, name: 'T', amount: '1000', period: period(3, 3),
            });
            const point = target.series.find((p) => p.date === iso(yesterday));
            expect(point?.actual).toBe('50.00');
        });

        it('resolves "this year" in the workspace timezone', async () => {
            const { owner, workspace } = await business();
            const target = await targets().create(workspace.id, owner.id, {
                ...base, name: 'Year', amount: '50000000', period: { kind: 'preset', preset: 'THIS_YEAR' },
            });
            expect(target.startDate).toBe(`${today().year}-01-01`);
            expect(target.endDate).toBe(`${today().year}-12-31`);
        });
    });

    describe('who sees what', () => {
        it("shows a member only their own targets, whatever they ask for", async () => {
            const { owner, workspace } = await business();
            const member = await createUser();
            await addWorkspaceMember(workspace.id, member.id, WorkspaceRole.MEMBER);
            const businessTarget = await targets().create(workspace.id, owner.id, { ...base, name: 'Business', amount: '9000', period: period(0, 9) });
            await targets().create(workspace.id, owner.id, { ...base, name: 'Theirs', amount: '100', period: period(0, 9), assigneeId: member.id });

            const asMember = { userId: member.id, role: Role.MEMBER };
            const listed = await targets().list(workspace.id, asMember, { status: 'current', assignee: 'business', limit: 50 });
            expect(listed.data.map((t) => t.name)).toEqual(['Theirs']);
            expect(listed.canManage).toBe(false);
            await expect(targets().get(workspace.id, businessTarget.id, asMember)).rejects.toMatchObject({ code: 'NOT_FOUND' });

            const asOwner = await targets().list(workspace.id, OWNER(owner.id), { status: 'current', limit: 50 });
            expect(asOwner.data).toHaveLength(2);
        });

        it("puts the viewer's own targets first, even when the list is limited", async () => {
            const { owner, workspace } = await business();
            for (const days of [3, 4, 5]) {
                await targets().create(workspace.id, owner.id, { ...base, name: `Business ${days}`, amount: '1', period: period(0, days) });
            }
            await targets().create(workspace.id, owner.id, { ...base, name: 'Mine', amount: '1', period: period(0, 30), assigneeId: owner.id });

            const listed = await targets().list(workspace.id, OWNER(owner.id), { status: 'current', limit: 2 });
            expect(listed.data.map((t) => t.name)).toEqual(['Mine', 'Business 3']);
        });

        it('keeps ended and archived targets out of the current list', async () => {
            const { owner, workspace } = await business();
            await targets().create(workspace.id, owner.id, { ...base, name: 'Old', amount: '1', period: period(30, -10) });
            const archived = await targets().create(workspace.id, owner.id, { ...base, name: 'Gone', amount: '1', period: period(0, 9) });
            await targets().setArchived(workspace.id, archived.id, owner.id, true);
            await targets().create(workspace.id, owner.id, { ...base, name: 'Now', amount: '1', period: period(0, 9) });

            const names = async (status: 'current' | 'ended' | 'archived') =>
                (await targets().list(workspace.id, OWNER(owner.id), { status, limit: 50 })).data.map((t) => t.name);
            expect(await names('current')).toEqual(['Now']);
            expect(await names('ended')).toEqual(['Old']);
            expect(await names('archived')).toEqual(['Gone']);
        });
    });

    describe('recorded by hand', () => {
        it('counts what is recorded, on top of what was already raised, and not the books', async () => {
            const { owner, workspace, shop } = await business();
            // Started two months ago; set up today with 20,000 of 50,000 already raised.
            const t = await targets().create(workspace.id, owner.id, {
                ...manual, name: 'Land', amount: '50000', period: period(60, 120), openingAmount: '20000',
            });
            expect(t.openingDate).toBe(iso(today()));
            expect(t.recordWindow).toEqual({ from: iso(today()), to: iso(today()) });
            expect(t.progress.achieved).toBe('20000.00');

            const me = OWNER(owner.id);
            await targets().recordContribution(workspace.id, t.id, me, { date: iso(today()), kind: 'ADDITION', amount: '1000' });
            await targets().recordContribution(workspace.id, t.id, me, { date: iso(today()), kind: 'WITHDRAWAL', amount: '400', note: 'school fees' });
            await entry(shop.id, owner.id, { day: today(), amount: '99999' });

            const after = await targets().get(workspace.id, t.id, me);
            expect(after.progress.achieved).toBe('20600.00');
            expect(after.progress.todayAchieved).toBe('600.00');
            expect(after.series.find((p) => p.date === iso(today()))?.opening).toBe('20000.00');
        });

        it('refuses future days, days before the opening amount, and taking out more than was raised', async () => {
            const { owner, workspace } = await business();
            const me = OWNER(owner.id);
            const t = await targets().create(workspace.id, owner.id, {
                ...manual, name: 'T', amount: '5000', period: period(30, 30), openingAmount: '100',
            });
            const record = (date: DateTime, kind: 'ADDITION' | 'WITHDRAWAL', amount: string) =>
                targets().recordContribution(workspace.id, t.id, me, { date: iso(date), kind, amount });

            await expect(record(today().plus({ days: 1 }), 'ADDITION', '1')).rejects.toMatchObject({ code: 'INVALID_RECORD_DATE' });
            await expect(record(today().minus({ days: 1 }), 'ADDITION', '1')).rejects.toMatchObject({ code: 'INVALID_RECORD_DATE' });
            await expect(record(today(), 'WITHDRAWAL', '101')).rejects.toMatchObject({ code: 'TARGET_OVERDRAWN' });
            expect(await testPrisma.targetContribution.count()).toBe(0);

            // Deleting an addition that a withdrawal depends on is refused too.
            const added = await record(today(), 'ADDITION', '50');
            await record(today(), 'WITHDRAWAL', '120');
            await expect(targets().deleteContribution(workspace.id, t.id, added.id, me)).rejects.toMatchObject({ code: 'TARGET_OVERDRAWN' });
        });

        it('lets the person it is for record, and only the recorder or a manager change a record', async () => {
            const { owner, workspace } = await business();
            const seller = await createUser();
            const other = await createUser();
            await addWorkspaceMember(workspace.id, seller.id, WorkspaceRole.MEMBER);
            await addWorkspaceMember(workspace.id, other.id, WorkspaceRole.MEMBER);
            const t = await targets().create(workspace.id, owner.id, {
                ...manual, name: 'Commission', amount: '5000', period: period(0, 9), assigneeId: seller.id,
            });
            const asSeller = { userId: seller.id, role: Role.MEMBER };
            const asOther = { userId: other.id, role: Role.MEMBER };
            const day = iso(today());

            const mine = await targets().recordContribution(workspace.id, t.id, asSeller, { date: day, kind: 'ADDITION', amount: '200' });
            expect(mine.canEdit).toBe(true);
            const managers = await targets().recordContribution(workspace.id, t.id, OWNER(owner.id), { date: day, kind: 'ADDITION', amount: '300' });

            await expect(targets().recordContribution(workspace.id, t.id, asOther, { date: day, kind: 'ADDITION', amount: '1' }))
                .rejects.toMatchObject({ code: 'NOT_FOUND' });
            await expect(targets().deleteContribution(workspace.id, t.id, managers.id, asSeller))
                .rejects.toMatchObject({ code: 'AUTHORIZATION_ERROR' });
            await targets().updateContribution(workspace.id, t.id, mine.id, asSeller, { amount: '250' });
            await targets().updateContribution(workspace.id, t.id, mine.id, OWNER(owner.id), { note: 'checked' });

            const list = await targets().listContributions(workspace.id, t.id, asSeller, { limit: 1 });
            expect(list.data).toHaveLength(1);
            expect(list.nextCursor).not.toBeNull();
            const rest = await targets().listContributions(workspace.id, t.id, asSeller, { limit: 1, cursor: list.nextCursor! });
            expect([...list.data, ...rest.data].map((c) => c.amount).sort()).toEqual(['250.00', '300.00']);
            expect(rest.nextCursor).toBeNull();
        });

        it("won't strand records when the period or the opening date moves", async () => {
            const { owner, workspace } = await business();
            const t = await targets().create(workspace.id, owner.id, { ...manual, name: 'T', amount: '5000', period: period(5, 5) });
            await targets().recordContribution(workspace.id, t.id, OWNER(owner.id), {
                date: iso(today().minus({ days: 2 })), kind: 'ADDITION', amount: '10',
            });

            await expect(targets().update(workspace.id, t.id, owner.id, { period: period(0, 5) }))
                .rejects.toMatchObject({ code: 'RECORDS_OUTSIDE_PERIOD' });
            await expect(targets().update(workspace.id, t.id, owner.id, { openingAmount: '100', openingDate: iso(today()) }))
                .rejects.toMatchObject({ code: 'RECORDS_OUTSIDE_PERIOD' });
            const ok = await targets().update(workspace.id, t.id, owner.id, { openingAmount: '100', openingDate: iso(today().minus({ days: 3 })) });
            expect(ok.progress.achieved).toBe('110.00');
        });

        it('adds an opening amount to the books on a book target', async () => {
            const { owner, workspace, shop } = await business();
            await entry(shop.id, owner.id, { day: today().minus({ days: 1 }), amount: '100' });
            const t = await targets().create(workspace.id, owner.id, {
                ...base, name: 'Year so far', amount: '1000', period: period(10, 10), openingAmount: '300',
            });
            expect(t.progress.achieved).toBe('400.00');
            await expect(targets().recordContribution(workspace.id, t.id, OWNER(owner.id), { date: iso(today()), kind: 'ADDITION', amount: '1' }))
                .rejects.toMatchObject({ code: 'NOT_MANUAL_TARGET' });
        });
    });

    describe('validation', () => {
        it('refuses fields that belong to the other kind of target, and an opening amount that covers it all', async () => {
            const { owner, workspace, shop } = await business();
            const create = (over: Record<string, unknown>) =>
                targets().create(workspace.id, owner.id, { ...base, name: 'x', amount: '1000', period: period(0, 9), ...over } as never);

            await expect(create({ source: 'MANUAL', cashbookIds: [shop.id] })).rejects.toMatchObject({ code: 'INVALID_SOURCE_FIELD' });
            await expect(create({ source: 'MANUAL', metric: 'NET' })).rejects.toMatchObject({ code: 'INVALID_SOURCE_FIELD' });
            await expect(create({ remindToRecord: true })).rejects.toMatchObject({ code: 'INVALID_SOURCE_FIELD' });
            await expect(create({ openingAmount: '1000' })).rejects.toMatchObject({ code: 'INVALID_OPENING' });
            await expect(create({ openingAmount: '10', openingDate: iso(today().plus({ days: 1 })) }))
                .rejects.toMatchObject({ code: 'INVALID_OPENING' });
        });

        it('refuses outsiders, other workspaces’ books, and periods with no working day', async () => {
            const { owner, workspace } = await business();
            const other = await business();
            const stranger = await createUser();

            await expect(targets().create(workspace.id, owner.id, { ...base, name: 'x', amount: '1', period: period(0, 9), assigneeId: stranger.id }))
                .rejects.toMatchObject({ code: 'INVALID_ASSIGNEE' });
            await expect(targets().create(workspace.id, owner.id, { ...base, name: 'x', amount: '1', period: period(0, 9), cashbookIds: [other.shop.id] }))
                .rejects.toMatchObject({ code: 'INVALID_CASHBOOK' });
            // A single day that is not one of the chosen weekdays.
            const day = today().plus({ days: 1 });
            const otherDay = (day.weekday % 7) + 1;
            await expect(targets().create(workspace.id, owner.id, {
                ...base, name: 'x', amount: '1', workingDays: [otherDay],
                period: { kind: 'custom', startDate: iso(day), endDate: iso(day) },
            })).rejects.toMatchObject({ code: 'NO_WORKING_DAYS' });
        });

        it('has no one else to assign to in a personal workspace', async () => {
            const owner = await createUser();
            const personal = await createWorkspace(owner.id);
            await testPrisma.workspace.update({ where: { id: personal.id }, data: { type: WorkspaceType.PERSONAL } });
            await expect(targets().create(personal.id, owner.id, { ...base, name: 'x', amount: '1', period: period(0, 9), assigneeId: owner.id }))
                .rejects.toMatchObject({ code: 'INVALID_ASSIGNEE' });
        });
    });

    describe('scheduled work', () => {
        it('starts the next period of a repeating target, once', async () => {
            const { owner, workspace, shop } = await business();
            const ended = await targets().create(workspace.id, owner.id, {
                ...base, name: 'Monthly', amount: '100', repeats: true, cashbookIds: [shop.id],
                period: { kind: 'custom', startDate: iso(today().minus({ months: 1 }).startOf('month')), endDate: iso(today().minus({ months: 1 }).endOf('month')) },
            });

            expect(await targets().rollOver()).toBe(1);
            expect(await targets().rollOver()).toBe(0);

            const next = await testPrisma.target.findFirstOrThrow({ where: { previousId: ended.id }, include: { cashbooks: true } });
            expect(next.startDate.toISOString().slice(0, 10)).toBe(iso(today().startOf('month')));
            expect(next.cashbooks.map((c) => c.cashbookId)).toEqual([shop.id]);
            expect(next.endDate.toISOString().slice(0, 10)).toBe(iso(today().endOf('month')));
        });

        it('repeats a week as a week, and a hand-recorded target fresh, without its opening amount', async () => {
            const { owner, workspace } = await business();
            const lastWeek = today().minus({ weeks: 1 });
            const week = await targets().create(workspace.id, owner.id, {
                ...manual, name: 'Weekly', amount: '700', repeats: true, openingAmount: '100', remindToRecord: true,
                period: { kind: 'custom', startDate: iso(lastWeek.startOf('week')), endDate: iso(lastWeek.endOf('week')) },
            });
            expect(week.cadence).toEqual({ unit: 'days', count: 7 });

            expect(await targets().rollOver()).toBe(1);
            const next = await testPrisma.target.findFirstOrThrow({ where: { previousId: week.id } });
            expect(next.startDate.toISOString().slice(0, 10)).toBe(iso(today().startOf('week')));
            expect(next.endDate.toISOString().slice(0, 10)).toBe(iso(today().endOf('week')));
            expect(next.source).toBe('MANUAL');
            expect(next.remindToRecord).toBe(true);
            expect(next.openingAmount.toString()).toBe('0');
        });

        it('reminds in the evening to record, once a day, only when nothing is recorded yet', async () => {
            const dispatch = vi.spyOn(NotificationsService, 'dispatch').mockImplementation(() => {});
            const { owner, workspace } = await business();
            const quiet = await targets().create(workspace.id, owner.id, {
                ...manual, name: 'Quiet', amount: '1000', period: period(0, 9), remindToRecord: true,
            });
            const busy = await targets().create(workspace.id, owner.id, {
                ...manual, name: 'Busy', amount: '1000', period: period(0, 9), remindToRecord: true,
            });
            await targets().recordContribution(workspace.id, busy.id, OWNER(owner.id), { date: iso(today()), kind: 'ADDITION', amount: '10' });

            const reminders = () => dispatch.mock.calls.filter(([j]) => j.type === 'TARGET_REMINDER');
            await targets().sendReminders(today().set({ hour: 10 }).toJSDate());
            expect(reminders()).toHaveLength(0);

            const evening = today().set({ hour: 20 }).toJSDate();
            await targets().sendReminders(evening);
            await targets().sendReminders(evening);
            expect(reminders()).toHaveLength(1);
            expect(reminders()[0][0]).toMatchObject({ entityId: quiet.id, userId: owner.id });
        });

        it('alerts when behind pace at most once a week, and on reaching the target once', async () => {
            const dispatch = vi.spyOn(NotificationsService, 'dispatch').mockImplementation(() => {});
            const { owner, workspace, shop } = await business();
            // Ten days in, nothing recorded: well behind.
            const t = await targets().create(workspace.id, owner.id, {
                ...base, name: 'Quarter', amount: '10000', period: period(10, 20), emailAlerts: true,
            });

            await targets().sendAlerts();
            await targets().sendAlerts();
            const behind = dispatch.mock.calls.filter(([j]) => j.type === 'TARGET_BEHIND');
            expect(behind).toHaveLength(1);
            expect(behind[0][0]).toMatchObject({ userId: owner.id, entityId: t.id });
            expect(emails).toHaveLength(1);

            await entry(shop.id, owner.id, { day: today(), amount: '10000' });
            await targets().sendAlerts();
            await targets().sendAlerts();
            expect(dispatch.mock.calls.filter(([j]) => j.type === 'TARGET_ACHIEVED')).toHaveLength(1);
        });

        it('sends one summary when a period ends', async () => {
            const dispatch = vi.spyOn(NotificationsService, 'dispatch').mockImplementation(() => {});
            const { owner, workspace } = await business();
            await targets().create(workspace.id, owner.id, { ...base, name: 'Last week', amount: '500', period: period(10, -3) });

            await targets().sendAlerts();
            await targets().sendAlerts();
            const ended = dispatch.mock.calls.filter(([j]) => j.type === 'TARGET_ENDED');
            expect(ended).toHaveLength(1);
            expect(ended[0][0].body).toContain('0%');
        });

        it('forgets earlier alerts when the goal itself changes', async () => {
            vi.spyOn(NotificationsService, 'dispatch').mockImplementation(() => {});
            const { owner, workspace, shop } = await business();
            await entry(shop.id, owner.id, { day: today(), amount: '100' });
            const t = await targets().create(workspace.id, owner.id, { ...base, name: 'T', amount: '50', period: period(0, 5) });
            await targets().sendAlerts();
            expect((await testPrisma.target.findUniqueOrThrow({ where: { id: t.id } })).achievedAt).not.toBeNull();

            await targets().update(workspace.id, t.id, owner.id, { amount: '1000' });
            const after = await testPrisma.target.findUniqueOrThrow({ where: { id: t.id } });
            expect(after.achievedAt).toBeNull();
        });
    });
});

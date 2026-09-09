/**
 * Fixture builders for integration tests.
 *
 * These write straight to the database rather than going through services, so a
 * test can set up state without depending on the code under test being correct.
 */
import { AccountClassification, WorkspaceRole, WorkspaceType } from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import { randomUUID } from 'node:crypto';
import { testPrisma } from './setup';
import { clockFor, toDateColumn } from '../core/time/workspace-clock';

export const CURRENCY = 'UGX';

export async function createUser(overrides: { email?: string } = {}) {
    return testPrisma.user.create({
        data: {
            email: overrides.email ?? `user-${randomUUID()}@test.local`,
            passwordHash: 'hashed-not-used-in-tests',
            firstName: 'Test',
            lastName: 'User',
            emailVerified: true,
        },
    });
}

/**
 * Switch manual contact entry on for the whole platform.
 *
 * It is a platform-wide switch rather than a per-workspace grant, so any test
 * that builds a contact through ContactsService needs this first. Deliberately
 * NOT on by default: the tests that assert the switch refuses would be
 * silently disarmed by a permissive default.
 */
export async function enableManualContacts() {
    return testPrisma.platformSetting.upsert({
        where: { key: 'manual_contacts_enabled' },
        update: { value: true },
        create: { key: 'manual_contacts_enabled', value: true },
    });
}

export async function createWorkspace(
    ownerId: string,
    overrides: {
        name?: string;
        timezone?: string;
        enforceClockWindows?: boolean;
        attendanceClockInStart?: string | null;
        attendanceClockInEnd?: string | null;
        attendanceClockOutStart?: string | null;
        attendanceLatitude?: number | null;
        attendanceLongitude?: number | null;
        attendanceRadiusMeters?: number | null;
    } = {},
) {
    return testPrisma.workspace.create({
        data: {
            name: overrides.name ?? `Workspace ${randomUUID().slice(0, 8)}`,
            type: WorkspaceType.BUSINESS,
            ownerId,
            defaultCurrency: CURRENCY,
            timezone: overrides.timezone ?? 'Africa/Kampala',
            enforceClockWindows: overrides.enforceClockWindows ?? false,
            attendanceClockInStart: overrides.attendanceClockInStart ?? null,
            attendanceClockInEnd: overrides.attendanceClockInEnd ?? null,
            attendanceClockOutStart: overrides.attendanceClockOutStart ?? null,
            attendanceLatitude: overrides.attendanceLatitude ?? null,
            attendanceLongitude: overrides.attendanceLongitude ?? null,
            attendanceRadiusMeters: overrides.attendanceRadiusMeters ?? null,
        },
    });
}

/** Give a user an explicit membership row. Owners do not need one. */
export async function addWorkspaceMember(
    workspaceId: string,
    userId: string,
    role: WorkspaceRole = WorkspaceRole.MEMBER,
) {
    return testPrisma.workspaceMember.create({
        data: { workspaceId, userId, role },
    });
}

/**
 * An open work session, written directly.
 *
 * `businessDate` is derived through the workspace's own clock rather than from
 * the UTC date. Defaulting it to `clockIn.toISOString().slice(0, 10)` is the
 * very bug the business-date column exists to fix — near midnight it would
 * write yesterday's date for a +03:00 workspace and quietly skew any test that
 * depends on the day.
 */
export async function createOpenWorkSession(
    workspaceId: string,
    userId: string,
    overrides: { clockIn?: Date; businessDate?: string } = {},
) {
    const clockIn = overrides.clockIn ?? new Date();
    const businessDate =
        overrides.businessDate ??
        (await clockFor(testPrisma, workspaceId)).businessDate(clockIn);

    const session = await testPrisma.workSession.create({
        data: {
            workspaceId,
            userId,
            clockIn,
            businessDate: toDateColumn(businessDate),
            // An open session always has a presence state — the
            // work_sessions_presence_matches_state CHECK makes it structural,
            // so a fixture that omits it is not a valid row.
            presenceStatus: 'AVAILABLE',
            presenceChangedAt: clockIn,
        },
    });

    await testPrisma.workSessionPresence.create({
        data: {
            sessionId: session.id,
            workspaceId,
            userId,
            status: 'AVAILABLE',
            startedAt: clockIn,
        },
    });

    return session;
}

export async function createCashbook(
    workspaceId: string,
    _createdById: string,
    overrides: { name?: string; allowBackdate?: boolean; currency?: string } = {},
) {
    return testPrisma.cashbook.create({
        data: {
            workspaceId,
            name: overrides.name ?? `Cashbook ${randomUUID().slice(0, 8)}`,
            // Overridable so cross-currency refusals can actually be tested.
            // It silently ignored the override before, which made such a test
            // pass for the wrong reason: both books were the same currency.
            currency: overrides.currency ?? CURRENCY,
            allowBackdate: overrides.allowBackdate ?? true,
        },
    });
}

export async function createAccount(
    workspaceId: string,
    overrides: {
        name?: string;
        balance?: string;
        allowNegative?: boolean;
        classification?: AccountClassification;
    } = {},
) {
    const accountType = await testPrisma.accountType.create({
        data: {
            workspaceId,
            name: `Type ${randomUUID().slice(0, 8)}`,
            classification: overrides.classification ?? AccountClassification.ASSET,
        },
    });

    return testPrisma.account.create({
        data: {
            workspaceId,
            accountTypeId: accountType.id,
            name: overrides.name ?? `Wallet ${randomUUID().slice(0, 8)}`,
            currency: CURRENCY,
            balance: new Decimal(overrides.balance ?? '0'),
            allowNegative: overrides.allowNegative ?? false,
        },
    });
}

export async function createInventoryItem(
    workspaceId: string,
    overrides: { name?: string; quantityOnHand?: number; averageCost?: string } = {},
) {
    const item = await testPrisma.inventoryItem.create({
        data: {
            workspaceId,
            name: overrides.name ?? `Item ${randomUUID().slice(0, 8)}`,
            unit: 'pcs',
            currency: CURRENCY,
        },
    });

    await testPrisma.inventoryStock.create({
        data: {
            itemId: item.id,
            quantityOnHand: overrides.quantityOnHand ?? 0,
            averageCost: new Decimal(overrides.averageCost ?? '0'),
        },
    });

    return item;
}

export async function getStock(itemId: string) {
    return testPrisma.inventoryStock.findUniqueOrThrow({ where: { itemId } });
}

/** A workspace + cashbook + two wallets, the shape most financial tests need. */
export async function createFinancialFixture() {
    const user = await createUser();
    const workspace = await createWorkspace(user.id);
    const cashbook = await createCashbook(workspace.id, user.id);
    const walletA = await createAccount(workspace.id, { name: 'Wallet A', balance: '10000' });
    const walletB = await createAccount(workspace.id, { name: 'Wallet B', balance: '10000' });

    return { user, workspace, cashbook, walletA, walletB };
}

export async function getCashbook(id: string) {
    return testPrisma.cashbook.findUniqueOrThrow({ where: { id } });
}

export async function getAccount(id: string) {
    return testPrisma.account.findUniqueOrThrow({ where: { id } });
}

export const isoDate = (d = new Date()) => d.toISOString();

export async function createProject(
    workspaceId: string,
    createdById: string,
    overrides: { name?: string; status?: 'ACTIVE' | 'COMPLETED' | 'ARCHIVED' } = {},
) {
    return testPrisma.project.create({
        data: {
            workspaceId,
            createdById,
            name: overrides.name ?? `Project ${randomUUID().slice(0, 8)}`,
            status: overrides.status ?? 'ACTIVE',
            currency: CURRENCY,
        },
    });
}

export async function addProjectMember(
    projectId: string,
    userId: string,
    role: 'PROJECT_MANAGER' | 'CONTRIBUTOR' | 'VIEWER' = 'CONTRIBUTOR',
) {
    return testPrisma.projectMember.create({ data: { projectId, userId, role } });
}

export async function createTask(
    workspaceId: string,
    createdById: string,
    overrides: { title?: string; projectId?: string; status?: 'TODO' | 'IN_PROGRESS' | 'BLOCKED' | 'IN_REVIEW' | 'DONE' } = {},
) {
    return testPrisma.task.create({
        data: {
            workspaceId,
            createdById,
            projectId: overrides.projectId ?? null,
            title: overrides.title ?? `Task ${randomUUID().slice(0, 8)}`,
            status: overrides.status ?? 'TODO',
        },
    });
}

export async function assignTask(taskId: string, userId: string, assignedBy: string) {
    return testPrisma.taskAssignment.create({ data: { taskId, userId, assignedBy } });
}

export async function getTask(id: string) {
    return testPrisma.task.findUniqueOrThrow({ where: { id } });
}

export async function getWorkSession(id: string) {
    return testPrisma.workSession.findUniqueOrThrow({ where: { id } });
}

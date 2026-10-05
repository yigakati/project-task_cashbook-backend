/**
 * Workspace-level authorization.
 *
 * Until now, workspace authorization was ~30 hard-coded `WorkspaceRole[]` arrays
 * inline in route files, with no matrix anywhere — which is how MEMBER ended up
 * able to read full inventory valuation and COGS while being unable to do far
 * less sensitive things. This mirrors the structure of CASHBOOK_PERMISSION_MATRIX
 * so both layers read the same way.
 */
import { WorkspaceRole } from './index';

export enum WorkspacePermission {
    // ─── Workspace itself ───
    VIEW_WORKSPACE = 'VIEW_WORKSPACE',
    UPDATE_WORKSPACE = 'UPDATE_WORKSPACE',
    DELETE_WORKSPACE = 'DELETE_WORKSPACE',

    // ─── Members ───
    VIEW_MEMBERS = 'VIEW_MEMBERS',
    MANAGE_MEMBERS = 'MANAGE_MEMBERS',
    /** Narrower grant: may invite/manage SUB_ACCOUNTANTs and nobody else. */
    MANAGE_SUB_ACCOUNTANTS = 'MANAGE_SUB_ACCOUNTANTS',
    IMPORT_MEMBERS = 'IMPORT_MEMBERS',

    // ─── Cashbooks ───
    CREATE_CASHBOOK = 'CREATE_CASHBOOK',
    /** Implicit access to every book without an explicit CashbookMember row. */
    ACCESS_ALL_CASHBOOKS = 'ACCESS_ALL_CASHBOOKS',

    // ─── Wallets and the chart of accounts ───
    /**
     * See which wallets exist — id, name, type, currency.
     *
     * Held by everyone, including a plain MEMBER, because an entry may link to a
     * wallet: recording one needs the picker, and reading one back needs the
     * name. Deliberately does NOT include balances.
     */
    VIEW_WALLETS = 'VIEW_WALLETS',
    /**
     * See wallet balances, statements, transfers and net worth — the
     * organisation's cash position. Finance roles only.
     */
    VIEW_WALLET_BALANCES = 'VIEW_WALLET_BALANCES',
    MANAGE_WALLETS = 'MANAGE_WALLETS',
    VIEW_CHART_OF_ACCOUNTS = 'VIEW_CHART_OF_ACCOUNTS',
    MANAGE_CHART_OF_ACCOUNTS = 'MANAGE_CHART_OF_ACCOUNTS',

    // ─── Ledger ───
    VIEW_LEDGER = 'VIEW_LEDGER',
    POST_MANUAL_JOURNAL = 'POST_MANUAL_JOURNAL',
    CLOSE_PERIOD = 'CLOSE_PERIOD',
    VIEW_FINANCIAL_REPORTS = 'VIEW_FINANCIAL_REPORTS',
    /**
     * Set, change and archive targets — the business's own, and those given to
     * individual members. Seeing a business-wide target needs
     * ACCESS_ALL_CASHBOOKS instead, because its total spans every book.
     */
    MANAGE_TARGETS = 'MANAGE_TARGETS',

    // ─── Operational modules ───
    VIEW_INVENTORY = 'VIEW_INVENTORY',
    MANAGE_INVENTORY = 'MANAGE_INVENTORY',
    VIEW_INVOICING = 'VIEW_INVOICING',
    MANAGE_INVOICING = 'MANAGE_INVOICING',
    VIEW_CATALOG = 'VIEW_CATALOG',
    MANAGE_CATALOG = 'MANAGE_CATALOG',

    // ─── Shared reference data ───
    MANAGE_REFERENCE_DATA = 'MANAGE_REFERENCE_DATA',

    // ─── Audit ───
    VIEW_AUDIT_LOG = 'VIEW_AUDIT_LOG',

    // ─── Non-financial collaboration (everyone) ───
    USE_PROJECTS = 'USE_PROJECTS',
    USE_TASKS = 'USE_TASKS',
    USE_TIME_TRACKING = 'USE_TIME_TRACKING',

    // ─── Project delivery ───
    /** Create, edit, archive and delete projects; manage project membership. */
    MANAGE_PROJECTS = 'MANAGE_PROJECTS',
    /** Edit or delete any task in the workspace, not only your own. */
    MANAGE_TASKS = 'MANAGE_TASKS',
    /** Put someone on a task, or take them off it. */
    ASSIGN_TASKS = 'ASSIGN_TASKS',
    /** Decide requests to take on a task, and end-of-task reports. */
    APPROVE_TASK_WORK = 'APPROVE_TASK_WORK',
    /** Decide expense claims, which posts to a cashbook on approval. */
    APPROVE_EXPENSE_CLAIM = 'APPROVE_EXPENSE_CLAIM',

    // ─── People operations ───
    /** Attendance settings, schedules, holidays and sites. */
    MANAGE_ATTENDANCE = 'MANAGE_ATTENDANCE',
    /** See everyone's sessions, hours and attendance analytics. */
    VIEW_ALL_ATTENDANCE = 'VIEW_ALL_ATTENDANCE',
    APPROVE_LEAVE = 'APPROVE_LEAVE',
    APPROVE_OVERTIME = 'APPROVE_OVERTIME',
    APPROVE_WORK_REPORT = 'APPROVE_WORK_REPORT',
    /** End someone else's stuck session. */
    FORCE_CLOSE_SESSION = 'FORCE_CLOSE_SESSION',
    /**
     * Cancel a late/early/missed-clock-out flag with a reason.
     *
     * Owner and admin only, deliberately: HR configures the policy and PMs run
     * the work, but erasing the record of a breach is an accountability
     * decision that should not sit with the person the policy is about.
     */
    WAIVE_ATTENDANCE_FLAG = 'WAIVE_ATTENDANCE_FLAG',

    // ─── Shared between delivery and people ops ───
    /** Who is working on what right now, and who is on leave. */
    VIEW_WORKER_MONITORING = 'VIEW_WORKER_MONITORING',
    /** Record time against someone else's name. */
    LOG_TIME_ON_BEHALF = 'LOG_TIME_ON_BEHALF',
    /** Edit or delete a time entry belonging to someone else. */
    EDIT_OTHERS_TIME = 'EDIT_OTHERS_TIME',

    // ─── Ticketing ───
    //
    // Gated twice over: the org must have the TICKETING feature unlocked by a
    // superadmin, AND the caller must hold the permission. See
    // src/core/authz/ticketing-access.ts, which is also where the TICKETING
    // staff tag is turned into the three desk permissions — the matrix below is
    // keyed by role alone and must stay that way.
    /** See the portal and the current day's sales. */
    VIEW_TICKETING = 'VIEW_TICKETING',
    /** Ring up a sale, which posts a cashbook entry. */
    SELL_TICKETS = 'SELL_TICKETS',
    /**
     * Reverse a sale. Held alone this only reaches your OWN sale on the current
     * open day — the narrowing is in the service, because it depends on the row.
     * MANAGE_TICKETING widens it to any sale on any open day.
     */
    VOID_TICKET_SALE = 'VOID_TICKET_SALE',
    /**
     * Configure the desk: sessions, price tiers, offers, settings, opening and
     * closing days — and assigning the TICKETING staff tag, which is why this
     * cannot sit with plain MANAGE_MEMBERS.
     */
    MANAGE_TICKETING = 'MANAGE_TICKETING',
    /** Close a shift, count the drawer, reconcile a day. */
    RECONCILE_TICKET_SHIFT = 'RECONCILE_TICKET_SHIFT',
    /** Issue and edit loyalty memberships and their tiers. */
    MANAGE_MEMBERSHIPS = 'MANAGE_MEMBERSHIPS',
    /** Ticket volumes, revenue, discounts given, attendant performance. */
    VIEW_TICKET_ANALYTICS = 'VIEW_TICKET_ANALYTICS',

    // ─── API Integration ───
    /** Create, list, rotate and revoke workspace API keys. */
    MANAGE_API_KEYS = 'MANAGE_API_KEYS',
    /** View API integration docs, book IDs and code snippets. */
    VIEW_INTEGRATION_DOCS = 'VIEW_INTEGRATION_DOCS',
}

const P = WorkspacePermission;

/** Available to every member, including plain MEMBERs. */
const COLLABORATION: WorkspacePermission[] = [
    P.VIEW_WORKSPACE,
    P.VIEW_MEMBERS,
    P.USE_PROJECTS,
    P.USE_TASKS,
    P.USE_TIME_TRACKING,
    // Wallet identity, not balances. A member assigned to a book has to be able
    // to attach an entry to "Stanbic Current" and read it back afterwards.
    P.VIEW_WALLETS,
];

/**
 * Running projects and the work inside them.
 *
 * Deliberately contains nothing financial. A project manager who needs to see a
 * book gets an explicit CashbookMember row, the same as anybody else.
 */
const PROJECT_DELIVERY: WorkspacePermission[] = [
    P.MANAGE_PROJECTS,
    P.MANAGE_TASKS,
    P.ASSIGN_TASKS,
    P.APPROVE_TASK_WORK,
    P.APPROVE_EXPENSE_CLAIM,
    P.VIEW_WORKER_MONITORING,
    P.LOG_TIME_ON_BEHALF,
    P.EDIT_OTHERS_TIME,
];

/**
 * People operations: attendance policy, leave, overtime, work reports.
 *
 * Also deliberately non-financial. Note WAIVE_ATTENDANCE_FLAG is absent — see
 * its docstring.
 */
const PEOPLE_OPS: WorkspacePermission[] = [
    P.MANAGE_ATTENDANCE,
    P.VIEW_ALL_ATTENDANCE,
    P.APPROVE_LEAVE,
    P.APPROVE_OVERTIME,
    P.APPROVE_WORK_REPORT,
    P.FORCE_CLOSE_SESSION,
    P.VIEW_WORKER_MONITORING,
    P.LOG_TIME_ON_BEHALF,
    P.EDIT_OTHERS_TIME,
];

/**
 * The accounting surface: dashboard, wallets, chart of accounts, inventory,
 * rentals, invoices, products, and the reports page.
 */
const ACCOUNTING: WorkspacePermission[] = [
    P.VIEW_WALLET_BALANCES,
    P.MANAGE_WALLETS,
    P.VIEW_CHART_OF_ACCOUNTS,
    P.VIEW_LEDGER,
    P.VIEW_FINANCIAL_REPORTS,
    P.VIEW_INVENTORY,
    P.MANAGE_INVENTORY,
    P.VIEW_INVOICING,
    P.MANAGE_INVOICING,
    P.VIEW_CATALOG,
    P.MANAGE_CATALOG,
    P.MANAGE_REFERENCE_DATA,
    P.CREATE_CASHBOOK,
    P.POST_MANUAL_JOURNAL,
];

/**
 * The whole ticketing surface, for whoever runs the venue.
 *
 * A ticket attendant holds none of this by role — they are a plain MEMBER with
 * the TICKETING staff tag, which grants exactly VIEW_TICKETING, SELL_TICKETS
 * and VOID_TICKET_SALE and nothing else. See ticketing-access.ts.
 */
const TICKETING_ADMIN: WorkspacePermission[] = [
    P.VIEW_TICKETING,
    P.SELL_TICKETS,
    P.VOID_TICKET_SALE,
    P.MANAGE_TICKETING,
    P.RECONCILE_TICKET_SHIFT,
    P.MANAGE_MEMBERSHIPS,
    P.VIEW_TICKET_ANALYTICS,
];

export const WORKSPACE_PERMISSION_MATRIX: Record<WorkspaceRole, Set<WorkspacePermission>> = {
    [WorkspaceRole.OWNER]: new Set(Object.values(WorkspacePermission)),

    [WorkspaceRole.ADMIN]: new Set([
        ...COLLABORATION,
        ...ACCOUNTING,
        ...PROJECT_DELIVERY,
        ...PEOPLE_OPS,
        ...TICKETING_ADMIN,
        P.UPDATE_WORKSPACE,
        P.MANAGE_MEMBERS,
        P.MANAGE_SUB_ACCOUNTANTS,
        P.ACCESS_ALL_CASHBOOKS,
        P.MANAGE_TARGETS,
        P.MANAGE_CHART_OF_ACCOUNTS,
        P.CLOSE_PERIOD,
        P.VIEW_AUDIT_LOG,
        P.WAIVE_ATTENDANCE_FLAG,
        // Not DELETE_WORKSPACE, not IMPORT_MEMBERS.
    ]),

    /**
     * Runs the operation day to day.
     *
     * Reaches as far into the books as an admin — every cashbook, the wallets,
     * invoicing, reports — and owns the ticketing surface outright. What is
     * withheld is everything that changes what the organisation IS or what its
     * books MEAN, and each omission is deliberate:
     *
     *   UPDATE_WORKSPACE / DELETE_WORKSPACE  the org's identity and existence
     *   MANAGE_CHART_OF_ACCOUNTS             what the accounts mean
     *   CLOSE_PERIOD / POST_MANUAL_JOURNAL   the accountant's lock and pen
     *   MANAGE_SUB_ACCOUNTANTS               appointing finance staff
     *   IMPORT_MEMBERS                       bulk-onboarding without review
     *
     * MANAGE_MEMBERS is held, but assignableRoles(GENERAL_MANAGER) stops at
     * PROJECT_MANAGER — they staff the operation, they do not mint peers or
     * accountants, and members.service checks the target's current role too, so
     * they cannot demote an admin by "assigning" them something lower.
     */
    [WorkspaceRole.GENERAL_MANAGER]: new Set([
        ...COLLABORATION,
        // The accounting surface MINUS the accountant's own pen. POST_MANUAL_JOURNAL
        // is part of the ACCOUNTING bundle, so it has to be subtracted rather than
        // simply left out — spreading the bundle and trusting the omission is how
        // this role would silently gain the ability to write the books by hand.
        ...ACCOUNTING.filter((p) => p !== P.POST_MANUAL_JOURNAL),
        ...PROJECT_DELIVERY,
        ...PEOPLE_OPS,
        ...TICKETING_ADMIN,
        P.MANAGE_MEMBERS,
        P.ACCESS_ALL_CASHBOOKS,
        P.VIEW_AUDIT_LOG,
        P.WAIVE_ATTENDANCE_FLAG,
        P.MANAGE_TARGETS,
    ]),

    /**
     * Runs delivery. Sees no money at all: not the dashboard, not wallets, not
     * invoicing, not the ledger. Approving an expense claim posts to a book, so
     * that grant is checked against an explicit CashbookMember row at the point
     * of posting rather than being implied here.
     */
    [WorkspaceRole.PROJECT_MANAGER]: new Set([
        ...COLLABORATION,
        ...PROJECT_DELIVERY,
        // Deliberately absent: ACCESS_ALL_CASHBOOKS, so the book picker on an
        // expense approval shows only the books they were actually granted.
    ]),

    /**
     * Runs people operations. Also sees no money.
     *
     * Holds MANAGE_MEMBERS so they can onboard and offboard staff, but
     * assignableRoles(HR) is [MEMBER] — they cannot mint an admin, an
     * accountant, another HR or a project manager, and members.service checks
     * the TARGET's current role against that same list, so they cannot demote
     * an existing admin by "assigning" them a lower one either.
     */
    [WorkspaceRole.HR]: new Set([
        ...COLLABORATION,
        ...PEOPLE_OPS,
        P.MANAGE_MEMBERS,
    ]),

    [WorkspaceRole.ACCOUNTANT]: new Set([
        ...COLLABORATION,
        ...ACCOUNTING,
        P.ACCESS_ALL_CASHBOOKS,
        P.MANAGE_CHART_OF_ACCOUNTS,
        P.CLOSE_PERIOD,
        P.VIEW_AUDIT_LOG,
        // Can add sub-accountants, and only sub-accountants — enforced in
        // members.service, which checks the target role as well as this grant.
        P.MANAGE_SUB_ACCOUNTANTS,
        // Reads the desk, sells nothing. Ticket takings are theirs to reconcile
        // and report on; ringing up admissions is not an accounting job.
        P.VIEW_TICKETING,
        P.VIEW_TICKET_ANALYTICS,
    ]),

    [WorkspaceRole.SUB_ACCOUNTANT]: new Set([
        ...COLLABORATION,
        ...ACCOUNTING,
        P.VIEW_TICKETING,
        P.VIEW_TICKET_ANALYTICS,
        // Deliberately absent: ACCESS_ALL_CASHBOOKS. A sub-accountant reaches
        // only the books they have an explicit CashbookMember row for.
        // Also absent: member management, period close, chart-of-accounts edits.
    ]),

    [WorkspaceRole.MEMBER]: new Set([
        ...COLLABORATION,
        // No org-financial access whatsoever. Books require an explicit grant.
    ]),

    /**
     * Developer / integration role.
     *
     * Has zero financial access (no dashboards, no wallets, no ledger). Can:
     *   - List, create, rotate and revoke workspace API keys.
     *   - View book IDs for cashbooks they have been explicitly granted.
     *   - Access integration documentation and code snippets.
     *
     * The intent is that developers building integrations see exactly what they
     * need to wire up the API and nothing more — they do not become accountants
     * by virtue of being technical.
     */
    [WorkspaceRole.DEVELOPER]: new Set([
        ...COLLABORATION,
        P.MANAGE_API_KEYS,
        P.VIEW_INTEGRATION_DOCS,
        // No ACCESS_ALL_CASHBOOKS — they only see books with an explicit grant,
        // and bookRef on those books for use in integration snippets.
    ]),
};

export function hasWorkspacePermission(
    role: WorkspaceRole | null | undefined,
    permission: WorkspacePermission,
): boolean {
    if (!role) return false;
    return WORKSPACE_PERMISSION_MATRIX[role]?.has(permission) ?? false;
}

/**
 * Roles a caller may assign. ACCOUNTANT is restricted to SUB_ACCOUNTANT so an
 * accountant cannot promote anyone to their own level or above.
 */
export function assignableRoles(actor: WorkspaceRole): WorkspaceRole[] {
    switch (actor) {
        case WorkspaceRole.OWNER:
            return [
                WorkspaceRole.ADMIN,
                WorkspaceRole.GENERAL_MANAGER,
                WorkspaceRole.ACCOUNTANT,
                WorkspaceRole.SUB_ACCOUNTANT,
                WorkspaceRole.PROJECT_MANAGER,
                WorkspaceRole.HR,
                WorkspaceRole.MEMBER,
                WorkspaceRole.DEVELOPER,
            ];
        case WorkspaceRole.ADMIN:
            return [
                WorkspaceRole.GENERAL_MANAGER,
                WorkspaceRole.ACCOUNTANT,
                WorkspaceRole.SUB_ACCOUNTANT,
                WorkspaceRole.PROJECT_MANAGER,
                WorkspaceRole.HR,
                WorkspaceRole.MEMBER,
                WorkspaceRole.DEVELOPER,
            ];
        case WorkspaceRole.GENERAL_MANAGER:
            // Staffs the operation. Cannot mint a peer, an admin, or anyone who
            // touches the chart of accounts — so no GENERAL_MANAGER, no
            // ACCOUNTANT and no SUB_ACCOUNTANT in this list.
            return [
                WorkspaceRole.PROJECT_MANAGER,
                WorkspaceRole.HR,
                WorkspaceRole.MEMBER,
                WorkspaceRole.DEVELOPER,
            ];
        case WorkspaceRole.ACCOUNTANT:
            // Both directions between member and sub-accountant: an accountant
            // brings help in and takes it back out. Still cannot touch an admin
            // or another accountant, because neither is in this list — and the
            // caller checks the target's CURRENT role against it too.
            return [WorkspaceRole.SUB_ACCOUNTANT, WorkspaceRole.MEMBER];
        case WorkspaceRole.HR:
            // Onboarding and offboarding only. MEMBER is the ceiling, so HR
            // cannot grant itself company money by routing through a role that
            // has it.
            return [WorkspaceRole.MEMBER];
        default:
            // PROJECT_MANAGER, SUB_ACCOUNTANT, DEVELOPER and MEMBER assign nobody.
            return [];
    }
}

/** Roles that see the financial surfaces, for frontend nav gating. */
export const FINANCE_ROLES: WorkspaceRole[] = [
    WorkspaceRole.OWNER,
    WorkspaceRole.ADMIN,
    WorkspaceRole.GENERAL_MANAGER,
    WorkspaceRole.ACCOUNTANT,
    WorkspaceRole.SUB_ACCOUNTANT,
];

import { CashbookRole } from './index';

// ─── Cashbook Permission Actions ───────────────────────
export enum CashbookPermission {
    // Cashbook management
    VIEW_CASHBOOK = 'VIEW_CASHBOOK',
    UPDATE_CASHBOOK = 'UPDATE_CASHBOOK',
    DELETE_CASHBOOK = 'DELETE_CASHBOOK',
    MANAGE_SETTINGS = 'MANAGE_SETTINGS',

    // Member management
    VIEW_MEMBERS = 'VIEW_MEMBERS',
    ADD_MEMBER = 'ADD_MEMBER',
    REMOVE_MEMBER = 'REMOVE_MEMBER',
    CHANGE_MEMBER_ROLE = 'CHANGE_MEMBER_ROLE',

    // Entries
    VIEW_ENTRIES = 'VIEW_ENTRIES',
    CREATE_ENTRY = 'CREATE_ENTRY',
    UPDATE_ENTRY = 'UPDATE_ENTRY',
    DELETE_ENTRY = 'DELETE_ENTRY',
    APPROVE_DELETE = 'APPROVE_DELETE',

    // Categories
    VIEW_CATEGORIES = 'VIEW_CATEGORIES',
    MANAGE_CATEGORIES = 'MANAGE_CATEGORIES',

    // Contacts
    VIEW_CONTACTS = 'VIEW_CONTACTS',
    MANAGE_CONTACTS = 'MANAGE_CONTACTS',

    // Payment Modes
    VIEW_PAYMENT_MODES = 'VIEW_PAYMENT_MODES',
    MANAGE_PAYMENT_MODES = 'MANAGE_PAYMENT_MODES',

    // Attachments
    VIEW_ATTACHMENTS = 'VIEW_ATTACHMENTS',
    UPLOAD_ATTACHMENT = 'UPLOAD_ATTACHMENT',
    DELETE_ATTACHMENT = 'DELETE_ATTACHMENT',

    // Obligations
    VIEW_OBLIGATIONS = 'VIEW_OBLIGATIONS',
    MANAGE_OBLIGATIONS = 'MANAGE_OBLIGATIONS',

    // Reports
    GENERATE_REPORT = 'GENERATE_REPORT',

    // Audit
    VIEW_AUDIT_LOG = 'VIEW_AUDIT_LOG',
}

// ─── Role → Permission Matrix ──────────────────────────
export const CASHBOOK_PERMISSION_MATRIX: Record<CashbookRole, Set<CashbookPermission>> = {
    [CashbookRole.PRIMARY_ADMIN]: new Set(Object.values(CashbookPermission)),

    [CashbookRole.ADMIN]: new Set([
        CashbookPermission.VIEW_CASHBOOK,
        CashbookPermission.UPDATE_CASHBOOK,
        CashbookPermission.MANAGE_SETTINGS,
        CashbookPermission.VIEW_MEMBERS,
        CashbookPermission.ADD_MEMBER,
        CashbookPermission.REMOVE_MEMBER,
        CashbookPermission.CHANGE_MEMBER_ROLE,
        CashbookPermission.VIEW_ENTRIES,
        CashbookPermission.CREATE_ENTRY,
        CashbookPermission.UPDATE_ENTRY,
        CashbookPermission.DELETE_ENTRY,
        CashbookPermission.APPROVE_DELETE,
        CashbookPermission.VIEW_CATEGORIES,
        CashbookPermission.MANAGE_CATEGORIES,
        CashbookPermission.VIEW_CONTACTS,
        CashbookPermission.MANAGE_CONTACTS,
        CashbookPermission.VIEW_PAYMENT_MODES,
        CashbookPermission.MANAGE_PAYMENT_MODES,
        CashbookPermission.VIEW_ATTACHMENTS,
        CashbookPermission.UPLOAD_ATTACHMENT,
        CashbookPermission.DELETE_ATTACHMENT,
        CashbookPermission.VIEW_OBLIGATIONS,
        CashbookPermission.MANAGE_OBLIGATIONS,
        CashbookPermission.GENERATE_REPORT,
        CashbookPermission.VIEW_AUDIT_LOG,
    ]),

    [CashbookRole.BOOK_ADMIN]: new Set([
        CashbookPermission.VIEW_CASHBOOK,
        CashbookPermission.UPDATE_CASHBOOK,
        CashbookPermission.VIEW_MEMBERS,
        CashbookPermission.VIEW_ENTRIES,
        CashbookPermission.CREATE_ENTRY,
        CashbookPermission.UPDATE_ENTRY,
        CashbookPermission.DELETE_ENTRY,
        CashbookPermission.APPROVE_DELETE,
        CashbookPermission.VIEW_CATEGORIES,
        CashbookPermission.MANAGE_CATEGORIES,
        CashbookPermission.VIEW_CONTACTS,
        CashbookPermission.MANAGE_CONTACTS,
        CashbookPermission.VIEW_PAYMENT_MODES,
        CashbookPermission.MANAGE_PAYMENT_MODES,
        CashbookPermission.VIEW_ATTACHMENTS,
        CashbookPermission.UPLOAD_ATTACHMENT,
        CashbookPermission.DELETE_ATTACHMENT,
        CashbookPermission.VIEW_OBLIGATIONS,
        CashbookPermission.MANAGE_OBLIGATIONS,
        CashbookPermission.GENERATE_REPORT,
        CashbookPermission.VIEW_AUDIT_LOG,
    ]),

    [CashbookRole.DATA_OPERATOR]: new Set([
        CashbookPermission.VIEW_CASHBOOK,
        CashbookPermission.VIEW_MEMBERS,
        CashbookPermission.VIEW_ENTRIES,
        CashbookPermission.CREATE_ENTRY,
        CashbookPermission.UPDATE_ENTRY,
        CashbookPermission.VIEW_CATEGORIES,
        CashbookPermission.VIEW_CONTACTS,
        CashbookPermission.VIEW_PAYMENT_MODES,
        CashbookPermission.VIEW_ATTACHMENTS,
        CashbookPermission.UPLOAD_ATTACHMENT,
        CashbookPermission.VIEW_OBLIGATIONS,
        CashbookPermission.GENERATE_REPORT,
    ]),

    [CashbookRole.VIEWER]: new Set([
        CashbookPermission.VIEW_CASHBOOK,
        CashbookPermission.VIEW_MEMBERS,
        CashbookPermission.VIEW_ENTRIES,
        CashbookPermission.VIEW_CATEGORIES,
        CashbookPermission.VIEW_CONTACTS,
        CashbookPermission.VIEW_PAYMENT_MODES,
        CashbookPermission.VIEW_ATTACHMENTS,
        CashbookPermission.VIEW_OBLIGATIONS,
        CashbookPermission.GENERATE_REPORT,
    ]),
};

export function hasPermission(role: CashbookRole, permission: CashbookPermission): boolean {
    return CASHBOOK_PERMISSION_MATRIX[role]?.has(permission) ?? false;
}

import { Request } from 'express';

// ─── Auth Types ────────────────────────────────────────
export interface JwtPayload {
    userId: string;
    email: string;
    isSuperAdmin: boolean;
    jti?: string;
}

export interface AuthenticatedRequest extends Request {
    user: JwtPayload;
}

// ─── Pagination ────────────────────────────────────────
export interface PaginationParams {
    page: number;
    limit: number;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
}

export interface PaginatedResponse<T> {
    data: T[];
    pagination: {
        page: number;
        limit: number;
        total: number;
        totalPages: number;
        hasNext: boolean;
        hasPrevious: boolean;
    };
}

// ─── API Response ──────────────────────────────────────
export interface ApiResponse<T = any> {
    success: boolean;
    message: string;
    data?: T;
    errors?: Record<string, string[]>;
}

// ─── Workspace Types ───────────────────────────────────
export enum WorkspaceType {
    PERSONAL = 'PERSONAL',
    BUSINESS = 'BUSINESS',
}

export enum WorkspaceRole {
    OWNER = 'OWNER',
    ADMIN = 'ADMIN',
    MEMBER = 'MEMBER',
}

// ─── Cashbook Types ────────────────────────────────────
export enum CashbookRole {
    PRIMARY_ADMIN = 'PRIMARY_ADMIN',
    ADMIN = 'ADMIN',
    BOOK_ADMIN = 'BOOK_ADMIN',
    DATA_OPERATOR = 'DATA_OPERATOR',
    VIEWER = 'VIEWER',
}

export enum EntryType {
    INCOME = 'INCOME',
    EXPENSE = 'EXPENSE',
}

export enum DeleteRequestStatus {
    PENDING = 'PENDING',
    APPROVED = 'APPROVED',
    REJECTED = 'REJECTED',
}

// ─── Audit Types ───────────────────────────────────────
export enum AuditAction {
    // Auth
    USER_REGISTERED = 'USER_REGISTERED',
    USER_LOGGED_IN = 'USER_LOGGED_IN',
    USER_LOGGED_OUT = 'USER_LOGGED_OUT',
    TOKEN_REFRESHED = 'TOKEN_REFRESHED',
    ALL_SESSIONS_REVOKED = 'ALL_SESSIONS_REVOKED',
    SUSPICIOUS_LOGIN = 'SUSPICIOUS_LOGIN',
    EMAIL_VERIFIED = 'EMAIL_VERIFIED',
    PASSWORD_RESET_REQUESTED = 'PASSWORD_RESET_REQUESTED',
    PASSWORD_RESET_COMPLETED = 'PASSWORD_RESET_COMPLETED',

    // Google OAuth
    GOOGLE_LOGIN_SUCCESS = 'GOOGLE_LOGIN_SUCCESS',
    GOOGLE_LOGIN_FAILED = 'GOOGLE_LOGIN_FAILED',
    GOOGLE_ACCOUNT_LINKED = 'GOOGLE_ACCOUNT_LINKED',
    GOOGLE_ACCOUNT_CREATED = 'GOOGLE_ACCOUNT_CREATED',

    // Workspace
    WORKSPACE_CREATED = 'WORKSPACE_CREATED',
    WORKSPACE_UPDATED = 'WORKSPACE_UPDATED',
    WORKSPACE_DELETED = 'WORKSPACE_DELETED',
    MEMBER_INVITED = 'MEMBER_INVITED',
    MEMBER_REMOVED = 'MEMBER_REMOVED',
    MEMBER_ROLE_CHANGED = 'MEMBER_ROLE_CHANGED',

    // Cashbook
    CASHBOOK_CREATED = 'CASHBOOK_CREATED',
    CASHBOOK_UPDATED = 'CASHBOOK_UPDATED',
    CASHBOOK_DELETED = 'CASHBOOK_DELETED',
    CASHBOOK_MEMBER_ADDED = 'CASHBOOK_MEMBER_ADDED',
    CASHBOOK_MEMBER_REMOVED = 'CASHBOOK_MEMBER_REMOVED',
    CASHBOOK_MEMBER_ROLE_CHANGED = 'CASHBOOK_MEMBER_ROLE_CHANGED',

    // Entry
    ENTRY_CREATED = 'ENTRY_CREATED',
    ENTRY_UPDATED = 'ENTRY_UPDATED',
    ENTRY_DELETED = 'ENTRY_DELETED',
    ENTRY_DELETE_REQUESTED = 'ENTRY_DELETE_REQUESTED',
    ENTRY_DELETE_APPROVED = 'ENTRY_DELETE_APPROVED',
    ENTRY_DELETE_REJECTED = 'ENTRY_DELETE_REJECTED',

    // Category
    CATEGORY_CREATED = 'CATEGORY_CREATED',
    CATEGORY_UPDATED = 'CATEGORY_UPDATED',
    CATEGORY_DELETED = 'CATEGORY_DELETED',

    // Contact
    CONTACT_CREATED = 'CONTACT_CREATED',
    CONTACT_UPDATED = 'CONTACT_UPDATED',
    CONTACT_DELETED = 'CONTACT_DELETED',

    // Payment Mode
    PAYMENT_MODE_CREATED = 'PAYMENT_MODE_CREATED',
    PAYMENT_MODE_UPDATED = 'PAYMENT_MODE_UPDATED',
    PAYMENT_MODE_DELETED = 'PAYMENT_MODE_DELETED',

    // Attachment
    ATTACHMENT_UPLOADED = 'ATTACHMENT_UPLOADED',
    ATTACHMENT_DELETED = 'ATTACHMENT_DELETED',

    // Report
    REPORT_REQUESTED = 'REPORT_REQUESTED',
    REPORT_GENERATED = 'REPORT_GENERATED',
    REPORT_FAILED = 'REPORT_FAILED',

    // Admin
    ADMIN_USER_SUSPENDED = 'ADMIN_USER_SUSPENDED',
    ADMIN_USER_ACTIVATED = 'ADMIN_USER_ACTIVATED',
    ADMIN_WORKSPACE_ACTION = 'ADMIN_WORKSPACE_ACTION',

    // Permission
    PERMISSION_DENIED = 'PERMISSION_DENIED',

    // Accounts
    ACCOUNT_TYPE_CREATED = 'ACCOUNT_TYPE_CREATED',
    ACCOUNT_TYPE_UPDATED = 'ACCOUNT_TYPE_UPDATED',
    ACCOUNT_TYPE_DELETED = 'ACCOUNT_TYPE_DELETED',
    ACCOUNT_CATEGORY_CREATED = 'ACCOUNT_CATEGORY_CREATED',
    ACCOUNT_CATEGORY_UPDATED = 'ACCOUNT_CATEGORY_UPDATED',
    ACCOUNT_CATEGORY_DELETED = 'ACCOUNT_CATEGORY_DELETED',
    ACCOUNT_CREATED = 'ACCOUNT_CREATED',
    ACCOUNT_UPDATED = 'ACCOUNT_UPDATED',
    ACCOUNT_ARCHIVED = 'ACCOUNT_ARCHIVED',
    ACCOUNT_UNARCHIVED = 'ACCOUNT_UNARCHIVED',
    ACCOUNT_DELETED = 'ACCOUNT_DELETED',

    // Direct Account Transactions
    ACCOUNT_TRANSACTION_DIRECT_CREATED = 'ACCOUNT_TRANSACTION_DIRECT_CREATED',
    ACCOUNT_TRANSACTION_DIRECT_UPDATED = 'ACCOUNT_TRANSACTION_DIRECT_UPDATED',
    ACCOUNT_TRANSACTION_DIRECT_DELETED = 'ACCOUNT_TRANSACTION_DIRECT_DELETED',
}

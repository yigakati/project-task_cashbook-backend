import { StatusCodes } from 'http-status-codes';
import { formatBytes } from '../../utils/format-bytes';

export class AppError extends Error {
    public readonly statusCode: number;
    public readonly isOperational: boolean;
    public readonly code: string;

    constructor(
        message: string,
        statusCode: number = StatusCodes.INTERNAL_SERVER_ERROR,
        code: string = 'INTERNAL_ERROR',
        isOperational = true
    ) {
        super(message);
        this.statusCode = statusCode;
        this.isOperational = isOperational;
        this.code = code;
        Object.setPrototypeOf(this, new.target.prototype);
        Error.captureStackTrace(this, this.constructor);
    }
}

export class ValidationError extends AppError {
    public readonly errors: Record<string, string[]>;

    constructor(message: string, errors: Record<string, string[]> = {}) {
        super(message, StatusCodes.BAD_REQUEST, 'VALIDATION_ERROR');
        this.errors = errors;
    }
}

export class AuthenticationError extends AppError {
    constructor(message = 'Authentication required') {
        super(message, StatusCodes.UNAUTHORIZED, 'AUTHENTICATION_ERROR');
    }
}

/**
 * Thrown when a user attempts to log in but has not yet verified their email.
 * Uses a distinct `code` so the client can redirect to /verify-email instead
 * of showing a generic "wrong credentials" error. The user's email is included
 * so the client can pre-populate the verify-email page without a second lookup.
 */
export class EmailNotVerifiedError extends AppError {
    public readonly email: string;

    constructor(email: string) {
        super(
            'Please verify your email before logging in.',
            StatusCodes.UNAUTHORIZED,
            'EMAIL_NOT_VERIFIED',
        );
        this.email = email;
    }
}

/**
 * A workspace was asked to hand its details to someone before it had stated
 * any. Carries which workspace and which fields are missing so the client can
 * put the form in front of the user and retry, rather than dead-ending on a
 * message they cannot act on.
 */
export class WorkspaceProfileIncompleteError extends AppError {
    public readonly workspaceId: string;
    public readonly missing: string[];

    constructor(workspaceId: string, missing: string[]) {
        super(
            'Add your workspace contact details before sharing them.',
            StatusCodes.CONFLICT,
            'WORKSPACE_PROFILE_INCOMPLETE',
        );
        this.workspaceId = workspaceId;
        this.missing = missing;
    }
}

export class AuthorizationError extends AppError {
    constructor(message = 'Insufficient permissions') {
        super(message, StatusCodes.FORBIDDEN, 'AUTHORIZATION_ERROR');
    }
}

export class NotFoundError extends AppError {
    constructor(resource = 'Resource') {
        super(`${resource} not found`, StatusCodes.NOT_FOUND, 'NOT_FOUND');
    }
}

export class ConflictError extends AppError {
    constructor(message = 'Resource already exists') {
        super(message, StatusCodes.CONFLICT, 'CONFLICT');
    }
}

export class RateLimitError extends AppError {
    constructor(message = 'Too many requests, please try again later') {
        super(message, StatusCodes.TOO_MANY_REQUESTS, 'RATE_LIMIT');
    }
}

/**
 * An upload that would take a workspace past its storage allowance.
 *
 * Carries the numbers so the client can show how full the workspace is, not
 * just that something failed.
 */
export class StorageQuotaExceededError extends AppError {
    public readonly usedBytes: number;
    public readonly limitBytes: number;

    constructor(usedBytes: number, limitBytes: number, incomingBytes: number) {
        super(
            `This workspace has used ${formatBytes(usedBytes)} of its ${formatBytes(limitBytes)} storage, `
            + `so this ${formatBytes(incomingBytes)} file won't fit. Remove files you no longer need, `
            + 'or ask an owner or admin to request more space under Business Settings → Storage.',
            StatusCodes.FORBIDDEN,
            'STORAGE_QUOTA_EXCEEDED',
        );
        this.usedBytes = usedBytes;
        this.limitBytes = limitBytes;
    }
}

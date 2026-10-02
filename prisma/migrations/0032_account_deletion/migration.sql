-- Migration: account_deletion
--
-- Self-service account deletion (in the app and on the web) with a grace
-- period, plus the public contact form's message store.
--
--   1. users.deleted_at — the tombstone marker for an anonymised account
--   2. account_deletion_requests — one row per request, with its lifecycle
--   3. contact_messages — what the public contact form sends

-- ─── 1. Tombstone marker ────────────────────────────────────────────────────
ALTER TABLE "users" ADD COLUMN "deleted_at" TIMESTAMP(3);

-- ─── 2. Deletion requests ───────────────────────────────────────────────────
CREATE TYPE "AccountDeletionStatus" AS ENUM (
    'PENDING_VERIFICATION', 'SCHEDULED', 'PROCESSING', 'BLOCKED',
    'CANCELLED', 'EXPIRED', 'COMPLETED', 'FAILED'
);
CREATE TYPE "AccountDeletionSource" AS ENUM ('IN_APP', 'WEB', 'ADMIN');

CREATE TABLE "account_deletion_requests" (
    "id"                      UUID NOT NULL,
    "user_id"                 UUID NOT NULL,
    "source"                  "AccountDeletionSource" NOT NULL,
    "status"                  "AccountDeletionStatus" NOT NULL,
    "reason"                  TEXT,
    "contact_email"           TEXT,
    "verification_token_hash" TEXT,
    "verification_expires_at" TIMESTAMP(3),
    "scheduled_for"           TIMESTAMP(3),
    "verified_at"             TIMESTAMP(3),
    "cancelled_at"            TIMESTAMP(3),
    "completed_at"            TIMESTAMP(3),
    "handled_by_id"           UUID,
    "admin_note"              TEXT,
    "blockers"                JSONB,
    "summary"                 JSONB,
    "failure_reason"          TEXT,
    "attempts"                INTEGER NOT NULL DEFAULT 0,
    "created_at"              TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at"              TIMESTAMP(3) NOT NULL,

    CONSTRAINT "account_deletion_requests_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "account_deletion_requests_verification_token_hash_key"
    ON "account_deletion_requests"("verification_token_hash");
CREATE INDEX "account_deletion_requests_status_scheduled_for_idx"
    ON "account_deletion_requests"("status", "scheduled_for");
CREATE INDEX "account_deletion_requests_user_id_idx"
    ON "account_deletion_requests"("user_id");

-- One open request per person. Enforced here rather than by a read-then-write
-- in the service, which two requests arriving together would both pass.
CREATE UNIQUE INDEX "account_deletion_requests_one_open_per_user"
    ON "account_deletion_requests"("user_id")
    WHERE "status" IN ('PENDING_VERIFICATION', 'SCHEDULED', 'PROCESSING', 'BLOCKED');

ALTER TABLE "account_deletion_requests"
    ADD CONSTRAINT "account_deletion_requests_user_id_fkey"
    FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "account_deletion_requests"
    ADD CONSTRAINT "account_deletion_requests_handled_by_id_fkey"
    FOREIGN KEY ("handled_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- ─── 3. Contact form messages ───────────────────────────────────────────────
CREATE TYPE "ContactMessageStatus" AS ENUM ('OPEN', 'RESOLVED');

CREATE TABLE "contact_messages" (
    "id"              UUID NOT NULL,
    "name"            TEXT NOT NULL,
    "email"           TEXT NOT NULL,
    "category"        TEXT NOT NULL,
    "subject"         TEXT NOT NULL,
    "message"         TEXT NOT NULL,
    "status"          "ContactMessageStatus" NOT NULL DEFAULT 'OPEN',
    "resolved_at"     TIMESTAMP(3),
    "resolved_by_id"  UUID,
    "resolution_note" TEXT,
    "created_at"      TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at"      TIMESTAMP(3) NOT NULL,

    CONSTRAINT "contact_messages_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "contact_messages_status_created_at_idx" ON "contact_messages"("status", "created_at");

ALTER TABLE "contact_messages"
    ADD CONSTRAINT "contact_messages_resolved_by_id_fkey"
    FOREIGN KEY ("resolved_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

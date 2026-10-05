-- Migration: targets
--
-- Goals over a period ("50M this year") and the daily amount needed to reach
-- them. Progress is never stored: it is computed from posted entries, so it
-- can't drift from the books.
--
--   1. targets, and target_cashbooks for targets limited to some books
--   2. notification types for behind-pace, achieved and period-ended alerts

-- ─── 1. Targets ─────────────────────────────────────────────────────────────
CREATE TYPE "TargetMetric" AS ENUM ('MONEY_IN', 'NET');
CREATE TYPE "TargetRecurrence" AS ENUM ('NONE', 'MONTHLY', 'QUARTERLY', 'YEARLY');

CREATE TABLE "targets" (
    "id"                     UUID NOT NULL,
    "workspace_id"           UUID NOT NULL,
    "name"                   TEXT NOT NULL,
    "metric"                 "TargetMetric" NOT NULL DEFAULT 'MONEY_IN',
    "amount"                 DECIMAL(20,4) NOT NULL,
    "currency"               TEXT NOT NULL,
    "start_date"             DATE NOT NULL,
    "end_date"               DATE NOT NULL,
    "working_days"           INTEGER[],
    "assignee_id"            UUID,
    "recurrence"             "TargetRecurrence" NOT NULL DEFAULT 'NONE',
    "previous_id"            UUID,
    "alerts_enabled"         BOOLEAN NOT NULL DEFAULT true,
    "email_alerts"           BOOLEAN NOT NULL DEFAULT false,
    "last_behind_alert_week" TEXT,
    "achieved_at"            TIMESTAMP(3),
    "ended_notified_at"      TIMESTAMP(3),
    "archived_at"            TIMESTAMP(3),
    "created_by_id"          UUID NOT NULL,
    "created_at"             TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at"             TIMESTAMP(3) NOT NULL,

    CONSTRAINT "targets_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "targets_amount_positive" CHECK ("amount" > 0),
    CONSTRAINT "targets_period_ordered" CHECK ("end_date" >= "start_date"),
    -- At least one weekday, each an ISO weekday. The service enforces the
    -- same; this keeps a hand-written row from producing a target with no days.
    CONSTRAINT "targets_working_days_valid" CHECK (
        cardinality("working_days") BETWEEN 1 AND 7
        AND "working_days" <@ ARRAY[1,2,3,4,5,6,7]
    )
);

CREATE UNIQUE INDEX "targets_previous_id_key" ON "targets"("previous_id");
CREATE INDEX "targets_workspace_id_archived_at_idx" ON "targets"("workspace_id", "archived_at");
CREATE INDEX "targets_assignee_id_idx" ON "targets"("assignee_id");
CREATE INDEX "targets_recurrence_end_date_idx" ON "targets"("recurrence", "end_date");

ALTER TABLE "targets"
    ADD CONSTRAINT "targets_workspace_id_fkey"
    FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "targets"
    ADD CONSTRAINT "targets_assignee_id_fkey"
    FOREIGN KEY ("assignee_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "targets"
    ADD CONSTRAINT "targets_created_by_id_fkey"
    FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "targets"
    ADD CONSTRAINT "targets_previous_id_fkey"
    FOREIGN KEY ("previous_id") REFERENCES "targets"("id") ON DELETE SET NULL ON UPDATE CASCADE;

CREATE TABLE "target_cashbooks" (
    "target_id"   UUID NOT NULL,
    "cashbook_id" UUID NOT NULL,

    CONSTRAINT "target_cashbooks_pkey" PRIMARY KEY ("target_id", "cashbook_id")
);
CREATE INDEX "target_cashbooks_cashbook_id_idx" ON "target_cashbooks"("cashbook_id");

ALTER TABLE "target_cashbooks"
    ADD CONSTRAINT "target_cashbooks_target_id_fkey"
    FOREIGN KEY ("target_id") REFERENCES "targets"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "target_cashbooks"
    ADD CONSTRAINT "target_cashbooks_cashbook_id_fkey"
    FOREIGN KEY ("cashbook_id") REFERENCES "cashbooks"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- ─── 2. Notifications ───────────────────────────────────────────────────────
ALTER TYPE "NotificationType" ADD VALUE IF NOT EXISTS 'TARGET_BEHIND';
ALTER TYPE "NotificationType" ADD VALUE IF NOT EXISTS 'TARGET_ACHIEVED';
ALTER TYPE "NotificationType" ADD VALUE IF NOT EXISTS 'TARGET_ENDED';
ALTER TYPE "NotificationEntityType" ADD VALUE IF NOT EXISTS 'TARGET';

-- Migration: target sources, opening amounts, simpler repeats, reminders
--
--   1. A target counts either the books (as before) or money recorded by hand
--      against it (target_contributions), with additions and withdrawals.
--   2. An opening amount: money already raised before tracking began.
--   3. Repeating is on/off; how often follows from the period's own length,
--      so a year-long target can no longer "repeat monthly".
--   4. An opt-in evening reminder for hand-recorded targets.

-- ─── 1. Source, and hand-recorded contributions ─────────────────────────────
CREATE TYPE "TargetSource" AS ENUM ('BOOKS', 'MANUAL');
CREATE TYPE "TargetContributionKind" AS ENUM ('ADDITION', 'WITHDRAWAL');

ALTER TABLE "targets" ADD COLUMN "source" "TargetSource" NOT NULL DEFAULT 'BOOKS';

CREATE TABLE "target_contributions" (
    "id"             UUID NOT NULL,
    "target_id"      UUID NOT NULL,
    "date"           DATE NOT NULL,
    "kind"           "TargetContributionKind" NOT NULL DEFAULT 'ADDITION',
    "amount"         DECIMAL(20,4) NOT NULL,
    "note"           VARCHAR(280),
    "recorded_by_id" UUID NOT NULL,
    "created_at"     TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at"     TIMESTAMP(3) NOT NULL,

    CONSTRAINT "target_contributions_pkey" PRIMARY KEY ("id"),
    -- The kind carries the sign; the amount is always positive.
    CONSTRAINT "target_contributions_amount_positive" CHECK ("amount" > 0)
);
CREATE INDEX "target_contributions_target_id_date_idx" ON "target_contributions"("target_id", "date");
CREATE INDEX "target_contributions_recorded_by_id_idx" ON "target_contributions"("recorded_by_id");

ALTER TABLE "target_contributions"
    ADD CONSTRAINT "target_contributions_target_id_fkey"
    FOREIGN KEY ("target_id") REFERENCES "targets"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "target_contributions"
    ADD CONSTRAINT "target_contributions_recorded_by_id_fkey"
    FOREIGN KEY ("recorded_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- ─── 2. Opening amount ──────────────────────────────────────────────────────
ALTER TABLE "targets"
    ADD COLUMN "opening_amount" DECIMAL(20,4) NOT NULL DEFAULT 0,
    ADD COLUMN "opening_date"   DATE;

ALTER TABLE "targets"
    ADD CONSTRAINT "targets_opening_valid" CHECK (
        "opening_amount" >= 0
        AND ("opening_date" IS NULL OR "opening_date" BETWEEN "start_date" AND "end_date")
    );

-- ─── 3. Repeats ─────────────────────────────────────────────────────────────
ALTER TABLE "targets" ADD COLUMN "repeats" BOOLEAN NOT NULL DEFAULT false;
UPDATE "targets" SET "repeats" = true WHERE "recurrence" <> 'NONE';

DROP INDEX "targets_recurrence_end_date_idx";
ALTER TABLE "targets" DROP COLUMN "recurrence";
DROP TYPE "TargetRecurrence";
CREATE INDEX "targets_repeats_end_date_idx" ON "targets"("repeats", "end_date");

-- ─── 4. Reminders ───────────────────────────────────────────────────────────
ALTER TABLE "targets"
    ADD COLUMN "remind_to_record"   BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN "last_reminder_date" DATE;

ALTER TABLE "targets"
    ADD CONSTRAINT "targets_reminder_manual_only" CHECK ("source" = 'MANUAL' OR NOT "remind_to_record");

ALTER TYPE "NotificationType" ADD VALUE 'TARGET_REMINDER';

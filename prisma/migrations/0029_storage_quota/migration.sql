-- Migration: storage_quota
--
-- Every workspace gets a file storage allowance (1 GB by default). Nothing new
-- is stored: usage is counted from the files that already exist — entry, task,
-- report and expense-claim attachments, plus the invoice logo. What this adds
-- is the ceiling, and a way to ask a superadmin to raise it.
--
--   1. attachments.workspace_id — which workspace a file counts against,
--      backfilled from whichever record owns it
--   2. invoice_settings.logo_key / logo_size — the logo is a stored file too
--   3. workspaces.storage_quota_bytes — per-workspace override (NULL = default)
--   4. storage_quota_requests — asking for more, one pending per workspace
--   5. seed default_storage_quota_bytes = 1 GiB
--   6. notification enum values

-- ─── 1. Attachments know their workspace ────────────────────────────────────
ALTER TABLE "attachments" ADD COLUMN "workspace_id" UUID;

UPDATE "attachments" a SET "workspace_id" = c."workspace_id"
FROM "cashbooks" c
WHERE a."cashbook_id" = c."id" AND a."workspace_id" IS NULL;

UPDATE "attachments" a SET "workspace_id" = t."workspace_id"
FROM "tasks" t
WHERE a."task_id" = t."id" AND a."workspace_id" IS NULL;

UPDATE "attachments" a SET "workspace_id" = r."workspace_id"
FROM "task_reports" r
WHERE a."task_report_id" = r."id" AND a."workspace_id" IS NULL;

UPDATE "attachments" a SET "workspace_id" = e."workspace_id"
FROM "task_expense_claims" e
WHERE a."expense_claim_id" = e."id" AND a."workspace_id" IS NULL;

-- Cascade matches the owners: a deleted workspace takes its files with it.
ALTER TABLE "attachments"
    ADD CONSTRAINT "attachments_workspace_id_fkey"
    FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- The quota check is SUM(file_size) over this.
CREATE INDEX "attachments_workspace_id_is_deleted_idx" ON "attachments"("workspace_id", "is_deleted");

-- ─── 2. The logo is a stored file ───────────────────────────────────────────
ALTER TABLE "invoice_settings"
    ADD COLUMN "logo_key"  TEXT,
    ADD COLUMN "logo_size" INTEGER;

-- Logos already in our bucket: recover the key from the URL so they can be
-- replaced and deleted properly. Their size is read from the bucket the first
-- time the storage page is opened. Logos typed in as external links are left
-- alone; the PDF no longer fetches them and shows the platform logo instead.
--
-- Matched only against this workspace's own key pattern (logos/<id>-<ms>.png).
-- The URL used to be free text, so a looser match would let a typed address
-- name another workspace's object — and removing the logo deletes its key.
UPDATE "invoice_settings"
SET "logo_key" = substring("logo_url" FROM '(logos/[0-9a-f-]{36}-[0-9]+\.png)$')
WHERE "logo_key" IS NULL
  AND "logo_url" ~ ('/logos/' || "workspace_id"::text || '-[0-9]+\.png$');

-- ─── 3. Per-workspace allowance ─────────────────────────────────────────────
ALTER TABLE "workspaces" ADD COLUMN "storage_quota_bytes" BIGINT;

-- ─── 4. Requests for more ───────────────────────────────────────────────────
CREATE TYPE "StorageRequestStatus" AS ENUM ('PENDING', 'APPROVED', 'DECLINED', 'CANCELLED');

CREATE TABLE "storage_quota_requests" (
    "id"              UUID NOT NULL,
    "workspace_id"    UUID NOT NULL,
    "requested_by_id" UUID NOT NULL,
    "requested_bytes" BIGINT NOT NULL,
    "reason"          TEXT,
    "status"          "StorageRequestStatus" NOT NULL DEFAULT 'PENDING',
    "granted_bytes"   BIGINT,
    "decided_by_id"   UUID,
    "decision_note"   TEXT,
    "decided_at"      TIMESTAMP(3),
    "created_at"      TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at"      TIMESTAMP(3) NOT NULL,

    CONSTRAINT "storage_quota_requests_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "storage_quota_requests_requested_bytes_positive" CHECK ("requested_bytes" > 0),
    CONSTRAINT "storage_quota_requests_granted_bytes_positive" CHECK ("granted_bytes" IS NULL OR "granted_bytes" > 0)
);

CREATE INDEX "storage_quota_requests_workspace_id_status_idx" ON "storage_quota_requests"("workspace_id", "status");
CREATE INDEX "storage_quota_requests_status_created_at_idx" ON "storage_quota_requests"("status", "created_at");

-- One open request per workspace. Enforced here rather than by a read-then-
-- write in the service, which two clicks arriving together would both pass.
CREATE UNIQUE INDEX "storage_quota_requests_one_pending_per_workspace"
    ON "storage_quota_requests"("workspace_id") WHERE "status" = 'PENDING';

ALTER TABLE "storage_quota_requests"
    ADD CONSTRAINT "storage_quota_requests_workspace_id_fkey"
    FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "storage_quota_requests"
    ADD CONSTRAINT "storage_quota_requests_requested_by_id_fkey"
    FOREIGN KEY ("requested_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "storage_quota_requests"
    ADD CONSTRAINT "storage_quota_requests_decided_by_id_fkey"
    FOREIGN KEY ("decided_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- ─── 5. The default allowance: 1 GiB ────────────────────────────────────────
INSERT INTO "platform_settings" ("key", "value", "updated_at")
VALUES ('default_storage_quota_bytes', '1073741824'::jsonb, NOW())
ON CONFLICT ("key") DO NOTHING;

-- ─── 6. Notifications ───────────────────────────────────────────────────────
ALTER TYPE "NotificationType" ADD VALUE IF NOT EXISTS 'STORAGE_REQUEST_DECIDED';
ALTER TYPE "NotificationEntityType" ADD VALUE IF NOT EXISTS 'STORAGE_QUOTA_REQUEST';

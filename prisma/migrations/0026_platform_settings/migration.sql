-- Migration: platform_settings
--
-- Manual contact entry moves from a per-workspace grant to a single
-- platform-wide switch. Granting it to one organisation while refusing the
-- next was arbitrary: whether details may be typed in by hand is a statement
-- about how the product works, not about who is trustworthy.
--
--   1. platform_settings — key/value switches, superadmin-owned
--   2. seed manual_contacts_enabled = false (off for everyone, as before)
--   3. drop the now-meaningless MANUAL_CONTACTS grants
--   4. remove MANUAL_CONTACTS from FeatureKey

-- ─── 1. The settings table ──────────────────────────────────────────────────
CREATE TABLE "platform_settings" (
    "key"           TEXT NOT NULL,
    "value"         JSONB NOT NULL,
    "updated_by_id" UUID,
    "updated_at"    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT "platform_settings_pkey" PRIMARY KEY ("key"),
    CONSTRAINT "platform_settings_updated_by_fk" FOREIGN KEY ("updated_by_id") REFERENCES "users"("id") ON DELETE SET NULL
);

-- ─── 2. Off for everyone, matching the behaviour being replaced ─────────────
INSERT INTO "platform_settings" ("key", "value", "updated_at")
VALUES ('manual_contacts_enabled', 'false'::jsonb, NOW())
ON CONFLICT ("key") DO NOTHING;

-- ─── 3. Retire the per-workspace grants ─────────────────────────────────────
DELETE FROM "workspace_features" WHERE "feature" = 'MANUAL_CONTACTS';

-- ─── 4. Rebuild FeatureKey without it ───────────────────────────────────────
-- Postgres cannot drop a value from an enum, so the type is replaced. Safe
-- only because step 3 removed every row that referenced the value.
ALTER TYPE "FeatureKey" RENAME TO "FeatureKey_old";

CREATE TYPE "FeatureKey" AS ENUM ('TICKETING');

ALTER TABLE "workspace_features"
    ALTER COLUMN "feature" TYPE "FeatureKey"
    USING ("feature"::text::"FeatureKey");

DROP TYPE "FeatureKey_old";

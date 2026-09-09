-- Migration: referrals_and_contact_gating
--
--   1. MANUAL_CONTACTS feature key — manual contact entry becomes a grant
--   2. contact_link_requests keyed on an EMAIL, so someone can be invited
--      before they have an account at all
--   3. referral agents and their referrals
--
-- Note on 1: this deliberately does NOT backfill a grant for existing
-- workspaces. Manual entry is off until a superadmin turns it on, which is the
-- chosen behaviour — every workspace loses the Add Contact button until then.

-- ─── 1. Feature key ─────────────────────────────────────────────────────────
ALTER TYPE "FeatureKey" ADD VALUE IF NOT EXISTS 'MANUAL_CONTACTS';

-- ─── 2. Requests aimed at an address, not only at an account ────────────────
ALTER TABLE "contact_link_requests"
    ADD COLUMN IF NOT EXISTS "recipient_email" TEXT;

-- Existing rows were all aimed at a real account; take the address from it.
UPDATE "contact_link_requests" r
SET "recipient_email" = lower(u."email")
FROM "users" u
WHERE u."id" = r."recipient_user_id"
  AND r."recipient_email" IS NULL;

-- Any row whose user vanished has nothing left to aim at; there is no useful
-- address to invent for it, so it cannot stay pending.
UPDATE "contact_link_requests"
SET "status" = 'CANCELLED', "responded_at" = NOW()
WHERE "recipient_email" IS NULL AND "status" = 'PENDING';

DELETE FROM "contact_link_requests" WHERE "recipient_email" IS NULL;

ALTER TABLE "contact_link_requests"
    ALTER COLUMN "recipient_email" SET NOT NULL,
    ALTER COLUMN "recipient_user_id" DROP NOT NULL;

CREATE INDEX IF NOT EXISTS "contact_link_requests_recipient_email_status_idx"
    ON "contact_link_requests"("recipient_email", "status");

-- The "one request in flight per pair" guard now keys on the address rather
-- than the account, so it holds for someone who has not signed up yet too.
DROP INDEX IF EXISTS "contact_link_requests_one_pending_per_pair";

CREATE UNIQUE INDEX "contact_link_requests_one_pending_per_pair"
    ON "contact_link_requests"("requester_workspace_id", "recipient_email")
    WHERE "status" = 'PENDING';

-- ─── 3. Referrals ───────────────────────────────────────────────────────────
CREATE TYPE "ReferralSource" AS ENUM ('LINK', 'CODE');
CREATE TYPE "ReferralStatus" AS ENUM ('SIGNED_UP', 'VERIFIED');

CREATE TABLE "referral_agents" (
    "id"              UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id"         UUID NOT NULL,
    "code"            TEXT NOT NULL,
    "is_active"       BOOLEAN NOT NULL DEFAULT true,
    "appointed_by_id" UUID NOT NULL,
    "appointed_at"    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "revoked_at"      TIMESTAMPTZ,
    "notes"           TEXT,

    CONSTRAINT "referral_agents_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "referral_agents_user_fk"         FOREIGN KEY ("user_id")         REFERENCES "users"("id") ON DELETE CASCADE,
    CONSTRAINT "referral_agents_appointed_by_fk" FOREIGN KEY ("appointed_by_id") REFERENCES "users"("id")
);

CREATE UNIQUE INDEX "referral_agents_user_id_key" ON "referral_agents"("user_id");
CREATE UNIQUE INDEX "referral_agents_code_key"    ON "referral_agents"("code");
CREATE INDEX        "referral_agents_is_active_idx" ON "referral_agents"("is_active");

CREATE TABLE "referrals" (
    "id"               UUID NOT NULL DEFAULT gen_random_uuid(),
    "agent_id"         UUID NOT NULL,
    "referred_user_id" UUID NOT NULL,
    "code"             TEXT NOT NULL,
    "source"           "ReferralSource" NOT NULL,
    "signup_method"    "AuthProvider" NOT NULL,
    "status"           "ReferralStatus" NOT NULL DEFAULT 'SIGNED_UP',
    "attributed_at"    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "verified_at"      TIMESTAMPTZ,

    CONSTRAINT "referrals_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "referrals_agent_fk"         FOREIGN KEY ("agent_id")         REFERENCES "referral_agents"("id") ON DELETE CASCADE,
    CONSTRAINT "referrals_referred_user_fk" FOREIGN KEY ("referred_user_id") REFERENCES "users"("id") ON DELETE CASCADE
);

-- One attribution per person, ever. First touch wins; a second signup path can
-- never double-credit the same account.
CREATE UNIQUE INDEX "referrals_referred_user_id_key" ON "referrals"("referred_user_id");
CREATE INDEX        "referrals_agent_status_idx"     ON "referrals"("agent_id", "status");
CREATE INDEX        "referrals_attributed_at_idx"    ON "referrals"("attributed_at");

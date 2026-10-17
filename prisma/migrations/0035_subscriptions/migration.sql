-- Migration: subscriptions
--
--   1. user_subscriptions: one row per account that has ever chosen a plan.
--      No row means Free, so every existing account is on the free plan
--      without a backfill. What each plan means (limits, prices) lives in
--      src/core/billing/plans.ts.
--   2. subscription_payments: one row per attempt to pay. Settled once by the
--      provider's confirmation, which is what activates a plan.
--
-- Nothing is written to either while payments are off. No full phone
-- numbers are kept — only a masked one to recognise a payment by.

-- ─── 1. Subscriptions ───────────────────────────────────────────────────────
CREATE TYPE "SubscriptionPlan" AS ENUM ('FREE', 'STARTER', 'GROWTH', 'ENTERPRISE');
CREATE TYPE "SubscriptionStatus" AS ENUM ('ACTIVE', 'CANCELLED');

CREATE TABLE "user_subscriptions" (
    "id"                   UUID NOT NULL,
    "user_id"              UUID NOT NULL,
    "plan"                 "SubscriptionPlan" NOT NULL DEFAULT 'FREE',
    "status"               "SubscriptionStatus" NOT NULL DEFAULT 'ACTIVE',
    "extra_storage_gb"     DECIMAL(6,1) NOT NULL DEFAULT 0,
    "current_period_start" TIMESTAMP(3),
    "current_period_end"   TIMESTAMP(3),
    "created_at"           TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at"           TIMESTAMP(3) NOT NULL,

    CONSTRAINT "user_subscriptions_pkey" PRIMARY KEY ("id"),
    -- Whole half-gigabyte steps, never negative.
    CONSTRAINT "user_subscriptions_extra_storage_valid" CHECK ("extra_storage_gb" >= 0 AND MOD("extra_storage_gb" * 2, 1) = 0)
);

CREATE UNIQUE INDEX "user_subscriptions_user_id_key" ON "user_subscriptions"("user_id");

ALTER TABLE "user_subscriptions"
    ADD CONSTRAINT "user_subscriptions_user_id_fkey"
    FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- ─── 2. Payments ────────────────────────────────────────────────────────────
CREATE TYPE "SubscriptionPaymentStatus" AS ENUM ('PENDING', 'SUCCEEDED', 'FAILED');

CREATE TABLE "subscription_payments" (
    "id"                 UUID NOT NULL,
    "user_id"            UUID NOT NULL,
    "reference"          TEXT NOT NULL,
    "provider"           TEXT NOT NULL,
    "provider_reference" TEXT,
    "plan"               "SubscriptionPlan" NOT NULL,
    "extra_storage_gb"   DECIMAL(6,1) NOT NULL DEFAULT 0,
    "amount_ugx"         INTEGER NOT NULL,
    "phone_masked"       TEXT NOT NULL,
    "status"             "SubscriptionPaymentStatus" NOT NULL DEFAULT 'PENDING',
    "failure_reason"     TEXT,
    "settled_at"         TIMESTAMP(3),
    "created_at"         TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at"         TIMESTAMP(3) NOT NULL,

    CONSTRAINT "subscription_payments_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "subscription_payments_amount_positive" CHECK ("amount_ugx" > 0),
    CONSTRAINT "subscription_payments_extra_storage_valid" CHECK ("extra_storage_gb" >= 0)
);

CREATE UNIQUE INDEX "subscription_payments_reference_key" ON "subscription_payments"("reference");
CREATE INDEX "subscription_payments_user_id_created_at_idx" ON "subscription_payments"("user_id", "created_at");

ALTER TABLE "subscription_payments"
    ADD CONSTRAINT "subscription_payments_user_id_fkey"
    FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

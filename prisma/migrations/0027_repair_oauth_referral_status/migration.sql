-- Migration: repair_oauth_referral_status
--
-- Referrals from Google/OC signups were stranded at SIGNED_UP.
--
-- Only `verifyEmail` promoted a referral to VERIFIED, and a social signup
-- never reaches it: those accounts are created with `emailVerified = true`
-- because the provider already proved the address. The referral therefore sat
-- at SIGNED_UP forever, displayed as "pending" with nothing anywhere that
-- could ever resolve it.
--
-- The code now records the status from the account's real state at signup.
-- This repairs the rows written before that.

UPDATE "referrals" r
SET "status"      = 'VERIFIED',
    "verified_at" = COALESCE(r."verified_at", r."attributed_at")
FROM "users" u
WHERE u."id" = r."referred_user_id"
  AND r."status" = 'SIGNED_UP'
  AND u."email_verified" = true;

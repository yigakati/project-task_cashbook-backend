-- Migration: linked_identities
-- Replaces the single provider/providerId slot on `users` as the source of
-- truth for "which OAuth accounts can sign this user in". `users.provider`/
-- `provider_id` are left in place unmodified — an immutable record of how the
-- account was first created — but login resolution now goes through this
-- table, which supports any number of linked providers per user.

CREATE TABLE "linked_identities" (
    "id"          UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id"     UUID NOT NULL,
    "provider"    "AuthProvider" NOT NULL,
    "provider_id" TEXT NOT NULL,
    "email"       TEXT NOT NULL,
    "linked_at"   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT "linked_identities_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "linked_identities_user_fk" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE
);

CREATE UNIQUE INDEX "linked_identities_provider_provider_id_key" ON "linked_identities"("provider", "provider_id");
CREATE INDEX "linked_identities_user_id_idx" ON "linked_identities"("user_id");

-- Backfill: every user already signed up through an OAuth provider gets a
-- matching identity row, so existing Google/OC users keep working under the
-- new lookup path instead of silently losing the ability to log in.
INSERT INTO "linked_identities" ("id", "user_id", "provider", "provider_id", "email", "linked_at")
SELECT gen_random_uuid(), "id", "provider", "provider_id", "email", "created_at"
FROM "users"
WHERE "provider" != 'LOCAL' AND "provider_id" IS NOT NULL;

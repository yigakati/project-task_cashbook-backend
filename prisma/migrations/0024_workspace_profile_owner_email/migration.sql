-- Migration: workspace_profile_owner_email
--
-- Seed each workspace's contact email from its owner's account email.
--
-- 0023 created a profile per workspace but only filled in the display name,
-- which left every one of them one field short of being shareable — so the
-- very first thing anyone accepting a contact request would hit is a form
-- asking for an address the app already had on file.
--
-- This is a one-time copy, not a link. Once set, the value belongs to the
-- workspace: editing it later (to billing@, accounts@, whatever the org
-- actually uses) is a normal edit, and it does not track the owner's account
-- email afterwards.

UPDATE "workspace_profiles" wp
SET "email" = u."email",
    "updated_at" = NOW()
FROM "workspaces" w
JOIN "users" u ON u."id" = w."owner_id"
WHERE wp."workspace_id" = w."id"
  AND (wp."email" IS NULL OR btrim(wp."email") = '')
  AND u."email" IS NOT NULL
  AND btrim(u."email") <> '';

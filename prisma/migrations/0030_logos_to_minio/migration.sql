-- Migration: logos_to_minio
--
-- Invoice logos move from Cloudflare R2 to MinIO, the object store attachments
-- already use. R2 is removed from the codebase entirely — it was a second
-- store, configured separately, and an unconfigured one failed as an opaque
-- 500 on every logo upload.
--
--   1. Logos still pointing at R2 are cleared. Their bytes are in a bucket
--      this deployment no longer talks to, so the row would reference nothing.
--      The workspace re-uploads; until it does, the app already says invoices
--      carry the platform logo.
--   2. logo_url is dropped. A logo's URL is now derived from its object key at
--      read time, so no row carries a hostname that a domain change strands.

UPDATE "invoice_settings"
SET "logo_key" = NULL, "logo_size" = NULL
WHERE "logo_key" IS NOT NULL OR "logo_size" IS NOT NULL;

ALTER TABLE "invoice_settings" DROP COLUMN "logo_url";

-- Migration: cashbook_archive
--
-- A book with entries can no longer be deleted, only archived. Archiving keeps
-- every entry, takes the book out of the active list and refuses new entries,
-- and can be undone. Deletion stays available only for a book that never
-- recorded anything.
--
-- Mirrors accounts, which already work this way via archived_at.

ALTER TABLE "cashbooks" ADD COLUMN "archived_at" TIMESTAMP(3);

-- Listing a workspace's active books is the common read.
CREATE INDEX "cashbooks_workspace_id_archived_at_idx" ON "cashbooks"("workspace_id", "archived_at");

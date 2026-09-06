-- Migration: item categories
--
-- The workspace's inventory item-category vocabulary, mirroring units of
-- measure: items keep `category` as free text, and this table curates the
-- names the item form suggests from. The name is the join — a rename
-- propagates to items server-side; a category in use cannot be deleted.

CREATE TABLE "item_categories" (
    "id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "item_categories_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "item_categories_workspace_id_name_key" ON "item_categories"("workspace_id", "name");
CREATE INDEX "item_categories_workspace_id_idx" ON "item_categories"("workspace_id");

ALTER TABLE "item_categories"
    ADD CONSTRAINT "item_categories_workspace_id_fkey"
    FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE ON UPDATE CASCADE;

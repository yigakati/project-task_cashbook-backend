-- Migration: units_of_measure
--
-- Workspace-scoped unit-of-measure vocabulary for inventory items. Items keep
-- referencing units by name (the existing free-text `unit` column), so this is
-- purely additive: no backfill is forced, and the curated list this table
-- holds is what the UI suggests from and manages.

CREATE TABLE "units_of_measure" (
    "id"          UUID NOT NULL DEFAULT gen_random_uuid(),
    "workspace_id" UUID NOT NULL,
    "name"        TEXT NOT NULL,
    "created_at"  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at"  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT "units_of_measure_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "units_of_measure_workspace_fk" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE,
    -- One name, one meaning per workspace: "pcs" and "PCS" cannot coexist as
    -- separate units because the name IS the join key items use.
    CONSTRAINT "units_of_measure_workspace_name_key" UNIQUE ("workspace_id", "name")
);

CREATE INDEX "units_of_measure_workspace_id_idx" ON "units_of_measure"("workspace_id");

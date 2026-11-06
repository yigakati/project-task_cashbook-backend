ALTER TABLE invoice_settings
    ADD COLUMN customization JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE invoices ADD COLUMN payment_terms TEXT;
ALTER TABLE invoice_items ADD COLUMN position INTEGER NOT NULL DEFAULT 0;
-- Preserve the previous, deterministic display order for existing invoices.
WITH ordered AS (
    SELECT id, ROW_NUMBER() OVER (PARTITION BY invoice_id ORDER BY id) - 1 AS position
    FROM invoice_items
)
UPDATE invoice_items SET position = ordered.position FROM ordered WHERE invoice_items.id = ordered.id;

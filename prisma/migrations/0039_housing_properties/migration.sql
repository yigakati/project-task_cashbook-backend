BEGIN;

CREATE TABLE housing_properties (
    id UUID PRIMARY KEY,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE ON UPDATE CASCADE,
    name TEXT NOT NULL,
    address TEXT,
    description TEXT,
    currency TEXT NOT NULL,
    default_kind "HousingUnitKind" NOT NULL DEFAULT 'APARTMENT',
    default_monthly_rent DECIMAL(20, 4) NOT NULL,
    unit_label_prefix TEXT NOT NULL DEFAULT 'Unit ',
    unit_number_start INTEGER NOT NULL DEFAULT 1,
    archived_at TIMESTAMP(3),
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP(3) NOT NULL,
    CONSTRAINT housing_property_terms CHECK (
        length(btrim(name)) BETWEEN 1 AND 120
        AND default_monthly_rent > 0
        AND length(unit_label_prefix) <= 100
        AND unit_number_start BETWEEN 1 AND 1000000
    ),
    UNIQUE (id, workspace_id),
    UNIQUE (id, workspace_id, currency)
);

CREATE UNIQUE INDEX housing_properties_workspace_name_key
    ON housing_properties(workspace_id, lower(btrim(name)));
CREATE INDEX housing_properties_workspace_id_archived_at_idx
    ON housing_properties(workspace_id, archived_at);

ALTER TABLE housing_units ADD COLUMN property_id UUID;

-- Missing names/addresses are ambiguous: never guess that those units share a
-- property. Exact named/addressed groups also remain separated by currency.
CREATE TEMP TABLE housing_property_backfill ON COMMIT DROP AS
SELECT id AS unit_id, workspace_id,
    CASE WHEN nullif(btrim(property_name), '') IS NOT NULL
              AND nullif(btrim(address), '') IS NOT NULL
         THEN jsonb_build_array(workspace_id, btrim(property_name), btrim(address), currency)::text
         ELSE 'unit:' || id::text
    END AS group_key
FROM housing_units;

DO $$
DECLARE
    conflict RECORD;
    property_group RECORD;
    first_unit housing_units%ROWTYPE;
    new_property_id UUID;
    proposed_name TEXT;
    base_name TEXT;
    suffix INTEGER;
BEGIN
    SELECT b.workspace_id, b.group_key, lower(btrim(u.name)) AS label
    INTO conflict
    FROM housing_property_backfill b
    JOIN housing_units u ON u.id = b.unit_id
    GROUP BY b.workspace_id, b.group_key, lower(btrim(u.name))
    HAVING count(*) > 1
    LIMIT 1;

    IF FOUND THEN
        RAISE EXCEPTION 'Housing migration: duplicate unit label "%" in workspace %. Resolve case/whitespace label conflicts in the named property before retrying; no units have been changed.',
            conflict.label, conflict.workspace_id;
    END IF;

    IF EXISTS (
        SELECT 1 FROM housing_tenancies t JOIN housing_units u ON u.id = t.unit_id
        WHERE t.workspace_id <> u.workspace_id
    ) THEN
        RAISE EXCEPTION 'Housing migration: a tenancy belongs to a different workspace from its unit. Correct the relationship before retrying.';
    END IF;

    FOR property_group IN
        SELECT group_key FROM housing_property_backfill GROUP BY group_key ORDER BY group_key
    LOOP
        SELECT u.* INTO first_unit
        FROM housing_units u JOIN housing_property_backfill b ON b.unit_id = u.id
        WHERE b.group_key = property_group.group_key
        ORDER BY u.created_at, u.id LIMIT 1;

        base_name := coalesce(nullif(btrim(first_unit.property_name), ''), btrim(first_unit.name));
        proposed_name := left(base_name, 120);
        suffix := 1;
        WHILE EXISTS (
            SELECT 1 FROM housing_properties
            WHERE workspace_id = first_unit.workspace_id AND lower(btrim(name)) = lower(proposed_name)
        ) LOOP
            suffix := suffix + 1;
            proposed_name := left(base_name, 110) || ' (' || suffix || ')';
        END LOOP;

        new_property_id := gen_random_uuid();
        INSERT INTO housing_properties (
            id, workspace_id, name, address, currency, default_kind,
            default_monthly_rent, created_at, updated_at
        ) VALUES (
            new_property_id, first_unit.workspace_id, proposed_name,
            first_unit.address, first_unit.currency, first_unit.kind,
            first_unit.monthly_rent, first_unit.created_at, CURRENT_TIMESTAMP
        );

        UPDATE housing_units SET property_id = new_property_id
        WHERE id IN (SELECT unit_id FROM housing_property_backfill WHERE group_key = property_group.group_key);
    END LOOP;
END $$;

ALTER TABLE housing_units ALTER COLUMN property_id SET NOT NULL;
ALTER TABLE housing_units ADD CONSTRAINT housing_units_property_workspace_currency_fkey
    FOREIGN KEY (property_id, workspace_id, currency)
    REFERENCES housing_properties(id, workspace_id, currency) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE housing_units ADD CONSTRAINT housing_unit_label CHECK (length(btrim(name)) BETWEEN 1 AND 120);
CREATE UNIQUE INDEX housing_units_id_workspace_id_key ON housing_units(id, workspace_id);
CREATE UNIQUE INDEX housing_units_property_label_key ON housing_units(property_id, lower(btrim(name)));
CREATE INDEX housing_units_property_id_archived_at_idx ON housing_units(property_id, archived_at);
DROP INDEX housing_units_workspace_id_name_key;

ALTER TABLE housing_tenancies DROP CONSTRAINT housing_tenancies_unit_id_fkey;
ALTER TABLE housing_tenancies ADD CONSTRAINT housing_tenancies_unit_workspace_fkey
    FOREIGN KEY (unit_id, workspace_id) REFERENCES housing_units(id, workspace_id) ON DELETE CASCADE ON UPDATE CASCADE;

-- All legacy addresses/names have been copied to their property; unit IDs and
-- every dependent tenancy, receipt, allocation, issue and photo stay intact.
ALTER TABLE housing_units DROP COLUMN property_name, DROP COLUMN address;

CREATE TABLE housing_provisioning_requests (
    id UUID PRIMARY KEY,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE ON UPDATE CASCADE,
    user_id UUID NOT NULL,
    property_id UUID NOT NULL,
    request_id UUID NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('CREATE_PROPERTY', 'ADD_UNITS')),
    request_hash TEXT NOT NULL,
    result JSONB NOT NULL,
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (property_id, workspace_id) REFERENCES housing_properties(id, workspace_id) ON DELETE CASCADE ON UPDATE CASCADE,
    UNIQUE (workspace_id, user_id, request_id)
);
CREATE INDEX housing_provisioning_requests_property_id_idx ON housing_provisioning_requests(property_id);

COMMIT;

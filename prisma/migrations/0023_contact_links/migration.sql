-- Migration: contact_links
--
-- Recording a counterparty by asking them, instead of typing their details in.
-- Adds:
--   1. workspace_profiles      — a workspace's own identity + billing details
--   2. contact_link_requests   — the request, addressed to a USER
--   3. contact_links           — the accepted connection between two workspaces
--   4. contacts.linked_*       — a contact that IS such a connection
--   5. invoices.bill_to_snapshot — freeze who an invoice was billed to
--
-- Everything here is additive. Contacts that exist today keep working
-- unchanged: the linked_* columns are null for them, and every consumer keeps
-- reading the same name/email/phone/company columns it always did.

-- ─── 1. Enums ───────────────────────────────────────────────────────────────
CREATE TYPE "ContactLinkRequestStatus" AS ENUM ('PENDING', 'ACCEPTED', 'DECLINED', 'CANCELLED', 'EXPIRED');
CREATE TYPE "ContactLinkState" AS ENUM ('ACTIVE', 'REVOKED');

ALTER TYPE "NotificationType" ADD VALUE IF NOT EXISTS 'CONTACT_LINK_RECEIVED';
ALTER TYPE "NotificationType" ADD VALUE IF NOT EXISTS 'CONTACT_LINK_DECIDED';
ALTER TYPE "NotificationEntityType" ADD VALUE IF NOT EXISTS 'CONTACT_LINK_REQUEST';

-- ─── 2. workspace_profiles ──────────────────────────────────────────────────
CREATE TABLE "workspace_profiles" (
    "id"              UUID NOT NULL DEFAULT gen_random_uuid(),
    "workspace_id"    UUID NOT NULL,
    "display_name"    TEXT NOT NULL,
    "legal_name"      TEXT,
    "email"           TEXT,
    "phone"           TEXT,
    "website"         TEXT,
    "tax_id"          TEXT,
    "registration_no" TEXT,
    "address_line1"   TEXT,
    "address_line2"   TEXT,
    "city"            TEXT,
    "state"           TEXT,
    "postal_code"     TEXT,
    "country"         TEXT,
    "billing_email"   TEXT,
    "payment_details" JSONB,
    "created_at"      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at"      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT "workspace_profiles_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "workspace_profiles_workspace_fk" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE
);

CREATE UNIQUE INDEX "workspace_profiles_workspace_id_key" ON "workspace_profiles"("workspace_id");

-- Seed a profile for every existing workspace from the name it already has, so
-- nobody starts from a blank form and the "is this filled in?" gate has
-- something truthful to read. Everything else stays null until they fill it.
INSERT INTO "workspace_profiles" ("id", "workspace_id", "display_name", "created_at", "updated_at")
SELECT gen_random_uuid(), "id", "name", NOW(), NOW()
FROM "workspaces";

-- ─── 3. contact_link_requests ───────────────────────────────────────────────
CREATE TABLE "contact_link_requests" (
    "id"                     UUID NOT NULL DEFAULT gen_random_uuid(),
    "status"                 "ContactLinkRequestStatus" NOT NULL DEFAULT 'PENDING',
    "requester_user_id"      UUID NOT NULL,
    "requester_workspace_id" UUID NOT NULL,
    "requested_type"         "ContactType" NOT NULL DEFAULT 'CUSTOMER',
    "requester_contact_id"   UUID,
    "recipient_user_id"      UUID NOT NULL,
    "recipient_workspace_id" UUID,
    "recipient_type"         "ContactType",
    "message"                TEXT,
    "declined_reason"        TEXT,
    "responded_at"           TIMESTAMPTZ,
    "expires_at"             TIMESTAMPTZ NOT NULL,
    "created_at"             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at"             TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT "contact_link_requests_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "contact_link_requests_requester_user_fk"  FOREIGN KEY ("requester_user_id")      REFERENCES "users"("id"),
    CONSTRAINT "contact_link_requests_recipient_user_fk"  FOREIGN KEY ("recipient_user_id")      REFERENCES "users"("id"),
    CONSTRAINT "contact_link_requests_requester_ws_fk"    FOREIGN KEY ("requester_workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE,
    CONSTRAINT "contact_link_requests_recipient_ws_fk"    FOREIGN KEY ("recipient_workspace_id") REFERENCES "workspaces"("id") ON DELETE SET NULL
);

CREATE INDEX "contact_link_requests_recipient_status_idx"  ON "contact_link_requests"("recipient_user_id", "status");
CREATE INDEX "contact_link_requests_requester_status_idx"  ON "contact_link_requests"("requester_workspace_id", "status");
CREATE INDEX "contact_link_requests_status_idx"            ON "contact_link_requests"("status");

-- At most ONE request in flight from a given workspace to a given person.
-- Partial, so the same pair may connect again after a decline or a revoke —
-- this stops nagging duplicates, not second chances. Prisma cannot express a
-- partial unique index in schema.prisma, so it lives here and is enforced by
-- the database regardless of what any caller does.
CREATE UNIQUE INDEX "contact_link_requests_one_pending_per_pair"
    ON "contact_link_requests"("requester_workspace_id", "recipient_user_id")
    WHERE "status" = 'PENDING';

-- ─── 4. contact_links ───────────────────────────────────────────────────────
CREATE TABLE "contact_links" (
    "id"                      UUID NOT NULL DEFAULT gen_random_uuid(),
    "state"                   "ContactLinkState" NOT NULL DEFAULT 'ACTIVE',
    "workspace_a_id"          UUID NOT NULL,
    "workspace_b_id"          UUID NOT NULL,
    "request_id"              UUID,
    "revoked_by_workspace_id" UUID,
    "revoked_at"              TIMESTAMPTZ,
    "created_at"              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at"              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT "contact_links_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "contact_links_workspace_a_fk" FOREIGN KEY ("workspace_a_id") REFERENCES "workspaces"("id") ON DELETE CASCADE,
    CONSTRAINT "contact_links_workspace_b_fk" FOREIGN KEY ("workspace_b_id") REFERENCES "workspaces"("id") ON DELETE CASCADE,
    CONSTRAINT "contact_links_request_fk"     FOREIGN KEY ("request_id")     REFERENCES "contact_link_requests"("id") ON DELETE SET NULL,
    -- The pair is stored with the smaller uuid first; this makes the unique
    -- index below able to reject the same pair arriving in either order.
    CONSTRAINT "contact_links_canonical_order" CHECK ("workspace_a_id" < "workspace_b_id")
);

CREATE UNIQUE INDEX "contact_links_pair_key"    ON "contact_links"("workspace_a_id", "workspace_b_id");
CREATE UNIQUE INDEX "contact_links_request_key" ON "contact_links"("request_id");
CREATE INDEX        "contact_links_state_idx"   ON "contact_links"("state");

-- ─── 5. contacts: the linked-contact columns ────────────────────────────────
ALTER TABLE "contacts"
    ADD COLUMN IF NOT EXISTS "linked_workspace_id" UUID,
    ADD COLUMN IF NOT EXISTS "contact_link_id"     UUID,
    ADD COLUMN IF NOT EXISTS "linked_snapshot"     JSONB,
    ADD COLUMN IF NOT EXISTS "linked_synced_at"    TIMESTAMPTZ;

ALTER TABLE "contacts"
    ADD CONSTRAINT "contacts_linked_workspace_fk" FOREIGN KEY ("linked_workspace_id") REFERENCES "workspaces"("id") ON DELETE SET NULL,
    ADD CONSTRAINT "contacts_contact_link_fk"     FOREIGN KEY ("contact_link_id")     REFERENCES "contact_links"("id") ON DELETE SET NULL;

-- One contact per connected workspace. NULLs are not compared by Postgres, so
-- the many unlinked contacts every workspace already has are unaffected — but
-- accepting the same connection twice can only ever resolve to one row.
CREATE UNIQUE INDEX "contacts_workspace_linked_workspace_key"
    ON "contacts"("workspace_id", "linked_workspace_id");

CREATE INDEX "contacts_contact_link_id_idx" ON "contacts"("contact_link_id");

-- ─── 6. invoices.bill_to_snapshot ───────────────────────────────────────────
ALTER TABLE "invoices"
    ADD COLUMN IF NOT EXISTS "bill_to_snapshot" JSONB;

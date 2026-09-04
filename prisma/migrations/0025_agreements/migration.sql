-- Migration: agreements
--
-- Cross-workspace stock transfers and rental agreements: two user-to-user
-- flows where the app is the shared proof. Both follow the Peer Links shape —
-- proposal, person-scoped inbox, acceptance into a workspace of the
-- recipient's choosing — but move stock instead of money.

CREATE TYPE "StockTransferStatus" AS ENUM ('PENDING', 'ACCEPTED', 'DECLINED', 'CANCELLED');
CREATE TYPE "RentalAgreementStatus" AS ENUM ('PENDING', 'ACCEPTED', 'DECLINED', 'CANCELLED');

-- ─── stock_transfers ───────────────────────────────────

CREATE TABLE "stock_transfers" (
    "id"                    UUID NOT NULL DEFAULT gen_random_uuid(),
    "status"                "StockTransferStatus" NOT NULL DEFAULT 'PENDING',
    "sender_user_id"        UUID NOT NULL,
    "sender_workspace_id"   UUID NOT NULL,
    "sender_item_id"        UUID NOT NULL,
    "quantity"              INTEGER NOT NULL,
    "proposed_unit_cost"    DECIMAL(20, 4) NOT NULL,
    "recipient_user_id"     UUID,
    "recipient_workspace_id" UUID,
    "recipient_item_id"     UUID,
    "notes"                 TEXT,
    "responded_at"          TIMESTAMPTZ,
    "created_at"            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at"            TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT "stock_transfers_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "stock_transfers_sender_user_fk" FOREIGN KEY ("sender_user_id") REFERENCES "users"("id"),
    CONSTRAINT "stock_transfers_sender_workspace_fk" FOREIGN KEY ("sender_workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE,
    CONSTRAINT "stock_transfers_sender_item_fk" FOREIGN KEY ("sender_item_id") REFERENCES "inventory_items"("id") ON DELETE CASCADE,
    CONSTRAINT "stock_transfers_recipient_workspace_fk" FOREIGN KEY ("recipient_workspace_id") REFERENCES "workspaces"("id") ON DELETE SET NULL,
    CONSTRAINT "stock_transfers_recipient_item_fk" FOREIGN KEY ("recipient_item_id") REFERENCES "inventory_items"("id") ON DELETE SET NULL,
    CONSTRAINT "stock_transfers_positive_qty" CHECK ("quantity" > 0)
);

CREATE INDEX "stock_transfers_status_idx" ON "stock_transfers"("status");
CREATE INDEX "stock_transfers_sender_user_id_idx" ON "stock_transfers"("sender_user_id");
CREATE INDEX "stock_transfers_recipient_user_id_idx" ON "stock_transfers"("recipient_user_id");

-- ─── rental_agreements ─────────────────────────────────

CREATE TABLE "rental_agreements" (
    "id"                    UUID NOT NULL DEFAULT gen_random_uuid(),
    "status"                "RentalAgreementStatus" NOT NULL DEFAULT 'PENDING',
    "lender_user_id"        UUID NOT NULL,
    "lender_workspace_id"   UUID NOT NULL,
    "lender_item_id"        UUID NOT NULL,
    "quantity"              INTEGER NOT NULL,
    "period_unit"           "RentalPeriodUnit" NOT NULL,
    "period_count"          INTEGER NOT NULL DEFAULT 1,
    "start_date"            TIMESTAMPTZ NOT NULL,
    "end_date"              TIMESTAMPTZ,
    "rate"                  DECIMAL(20, 4),
    "borrower_user_id"      UUID NOT NULL,
    "borrower_workspace_id" UUID,
    "rental_id"             UUID,
    "notes"                 TEXT,
    "responded_at"          TIMESTAMPTZ,
    "created_at"            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at"            TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT "rental_agreements_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "rental_agreements_lender_user_fk" FOREIGN KEY ("lender_user_id") REFERENCES "users"("id"),
    CONSTRAINT "rental_agreements_borrower_user_fk" FOREIGN KEY ("borrower_user_id") REFERENCES "users"("id"),
    CONSTRAINT "rental_agreements_lender_workspace_fk" FOREIGN KEY ("lender_workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE,
    CONSTRAINT "rental_agreements_lender_item_fk" FOREIGN KEY ("lender_item_id") REFERENCES "inventory_items"("id") ON DELETE CASCADE,
    CONSTRAINT "rental_agreements_borrower_workspace_fk" FOREIGN KEY ("borrower_workspace_id") REFERENCES "workspaces"("id") ON DELETE SET NULL,
    CONSTRAINT "rental_agreements_rental_fk" FOREIGN KEY ("rental_id") REFERENCES "inventory_rentals"("id") ON DELETE SET NULL,
    CONSTRAINT "rental_agreements_positive_qty" CHECK ("quantity" > 0),
    CONSTRAINT "rental_agreements_distinct_parties" CHECK ("lender_user_id" <> "borrower_user_id")
);

-- One rental belongs to at most one agreement.
CREATE UNIQUE INDEX "rental_agreements_rental_id_key" ON "rental_agreements"("rental_id");
CREATE INDEX "rental_agreements_status_idx" ON "rental_agreements"("status");
CREATE INDEX "rental_agreements_lender_user_id_idx" ON "rental_agreements"("lender_user_id");
CREATE INDEX "rental_agreements_borrower_user_id_idx" ON "rental_agreements"("borrower_user_id");

-- ─── reservations ──────────────────────────────────────

ALTER TABLE "inventory_stock" ADD COLUMN "quantity_reserved" INTEGER NOT NULL DEFAULT 0;

-- ─── Notifications ─────────────────────────────────────

ALTER TYPE "NotificationType" ADD VALUE 'STOCK_TRANSFER_RECEIVED';
ALTER TYPE "NotificationType" ADD VALUE 'STOCK_TRANSFER_DECIDED';
ALTER TYPE "NotificationType" ADD VALUE 'RENTAL_AGREEMENT_RECEIVED';
ALTER TYPE "NotificationType" ADD VALUE 'RENTAL_AGREEMENT_DECIDED';
ALTER TYPE "NotificationEntityType" ADD VALUE 'STOCK_TRANSFER';
ALTER TYPE "NotificationEntityType" ADD VALUE 'RENTAL_AGREEMENT';
ALTER TYPE "InventoryReferenceType" ADD VALUE 'STOCK_TRANSFER';

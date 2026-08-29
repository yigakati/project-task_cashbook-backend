-- Migration: peer_links
--
-- Peer-to-peer obligation agreements ("Peer Links"): one user proposes a loan
-- from one of their books, the counterparty accepts into one of their own
-- books, and the platform records the mirrored obligations (lender's
-- RECEIVABLE, borrower's PAYABLE) as shared proof of the loan.
--
-- Cross-confirmed settlement: a payment recorded on either side opens a
-- PENDING settlement the counterparty must confirm (by recording or matching
-- the mirrored payment) or reject. No book is ever written to by the other
-- party's action.

-- ─── Enums ─────────────────────────────────────────────

CREATE TYPE "PeerLinkStatus" AS ENUM ('PENDING', 'ACCEPTED', 'DECLINED', 'CANCELLED');
CREATE TYPE "PeerLinkDirection" AS ENUM ('LENDING', 'BORROWING');
CREATE TYPE "PeerLinkSettlementStatus" AS ENUM ('PENDING', 'CONFIRMED', 'REJECTED', 'CANCELLED');

-- ─── peer_links ────────────────────────────────────────

CREATE TABLE "peer_links" (
    "id"                        UUID NOT NULL DEFAULT gen_random_uuid(),
    "status"                    "PeerLinkStatus" NOT NULL DEFAULT 'PENDING',
    "direction"                 "PeerLinkDirection" NOT NULL,
    "initiator_user_id"         UUID NOT NULL,
    "initiator_workspace_id"    UUID NOT NULL,
    "initiator_cashbook_id"     UUID NOT NULL,
    "counterparty_user_id"      UUID NOT NULL,
    "counterparty_workspace_id" UUID,
    "counterparty_cashbook_id"  UUID,
    "title"                     TEXT NOT NULL,
    "description"               TEXT,
    "currency"                  TEXT NOT NULL,
    "principal_amount"          DECIMAL(20, 4) NOT NULL,
    "interest_amount"           DECIMAL(20, 4) NOT NULL DEFAULT 0,
    "interest_rate"             DECIMAL(9, 4),
    "total_amount"              DECIMAL(20, 4) NOT NULL,
    "due_date"                  TIMESTAMPTZ,
    "declined_reason"           TEXT,
    "responded_at"              TIMESTAMPTZ,
    "created_at"                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at"                TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT "peer_links_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "peer_links_initiator_user_fk" FOREIGN KEY ("initiator_user_id") REFERENCES "users"("id"),
    CONSTRAINT "peer_links_counterparty_user_fk" FOREIGN KEY ("counterparty_user_id") REFERENCES "users"("id"),
    CONSTRAINT "peer_links_initiator_workspace_fk" FOREIGN KEY ("initiator_workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE,
    CONSTRAINT "peer_links_counterparty_workspace_fk" FOREIGN KEY ("counterparty_workspace_id") REFERENCES "workspaces"("id") ON DELETE SET NULL,
    CONSTRAINT "peer_links_initiator_cashbook_fk" FOREIGN KEY ("initiator_cashbook_id") REFERENCES "cashbooks"("id") ON DELETE CASCADE,
    CONSTRAINT "peer_links_counterparty_cashbook_fk" FOREIGN KEY ("counterparty_cashbook_id") REFERENCES "cashbooks"("id") ON DELETE SET NULL,
    -- The two parties must be different users: a self-loan records nothing and
    -- would let anyone mint "proof" of a loan nobody ever made.
    CONSTRAINT "peer_links_distinct_parties" CHECK ("initiator_user_id" <> "counterparty_user_id"),
    -- total is principal + interest, mirroring obligations_total_is_principal_plus_interest.
    CONSTRAINT "peer_links_total_is_principal_plus_interest" CHECK ("total_amount" = "principal_amount" + "interest_amount" AND "interest_amount" >= 0)
);

CREATE INDEX "peer_links_status_idx" ON "peer_links"("status");
CREATE INDEX "peer_links_initiator_user_id_idx" ON "peer_links"("initiator_user_id");
CREATE INDEX "peer_links_counterparty_user_id_idx" ON "peer_links"("counterparty_user_id");

-- ─── peer_link_settlements ─────────────────────────────

CREATE TABLE "peer_link_settlements" (
    "id"                  UUID NOT NULL DEFAULT gen_random_uuid(),
    "peer_link_id"        UUID NOT NULL,
    "status"              "PeerLinkSettlementStatus" NOT NULL DEFAULT 'PENDING',
    "entry_id"            UUID NOT NULL,
    "obligation_id"       UUID NOT NULL,
    "recorded_by_user_id" UUID NOT NULL,
    "amount"              DECIMAL(20, 4) NOT NULL,
    "entry_date"          TIMESTAMPTZ NOT NULL,
    "matched_entry_id"    UUID,
    "responded_at"        TIMESTAMPTZ,
    "response_reason"     TEXT,
    "created_at"          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at"          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT "peer_link_settlements_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "peer_link_settlements_peer_link_fk" FOREIGN KEY ("peer_link_id") REFERENCES "peer_links"("id") ON DELETE CASCADE,
    CONSTRAINT "peer_link_settlements_entry_fk" FOREIGN KEY ("entry_id") REFERENCES "entries"("id"),
    CONSTRAINT "peer_link_settlements_matched_entry_fk" FOREIGN KEY ("matched_entry_id") REFERENCES "entries"("id") ON DELETE SET NULL,
    CONSTRAINT "peer_link_settlements_recorder_fk" FOREIGN KEY ("recorded_by_user_id") REFERENCES "users"("id"),
    -- One settlement row per recording entry: retried/parallel payment paths
    -- cannot manufacture a second confirmation demand from one payment.
    CONSTRAINT "peer_link_settlements_entry_id_key" UNIQUE ("entry_id"),
    -- One counterparty entry confirms at most one settlement. Plain UNIQUE:
    -- NULLs (unconfirmed) stay distinct, so many pending rows coexist.
    CONSTRAINT "peer_link_settlements_matched_entry_id_key" UNIQUE ("matched_entry_id")
);

CREATE INDEX "peer_link_settlements_peer_link_id_idx" ON "peer_link_settlements"("peer_link_id");
CREATE INDEX "peer_link_settlements_status_idx" ON "peer_link_settlements"("status");
CREATE INDEX "peer_link_settlements_entry_id_idx" ON "peer_link_settlements"("entry_id");
CREATE INDEX "peer_link_settlements_matched_entry_id_idx" ON "peer_link_settlements"("matched_entry_id");

-- ─── cashbook_obligations.peer_link_id ─────────────────

ALTER TABLE "cashbook_obligations" ADD COLUMN "peer_link_id" UUID;

ALTER TABLE "cashbook_obligations"
    ADD CONSTRAINT "cashbook_obligations_peer_link_fk"
    FOREIGN KEY ("peer_link_id") REFERENCES "peer_links"("id") ON DELETE SET NULL;

CREATE INDEX "cashbook_obligations_peer_link_id_idx" ON "cashbook_obligations"("peer_link_id");

-- At most one obligation per book per peer link side. A link's two mirrored
-- obligations live in different books, so (peer_link_id, cashbook_id) is the
-- natural uniqueness that also makes double-accept structurally impossible
-- even if the status guard were somehow bypassed.
CREATE UNIQUE INDEX "cashbook_obligations_peer_link_cashbook_key"
    ON "cashbook_obligations"("peer_link_id", "cashbook_id")
    WHERE "peer_link_id" IS NOT NULL;

-- ─── Notifications ─────────────────────────────────────

ALTER TYPE "NotificationType" ADD VALUE 'PEER_LINK_RECEIVED';
ALTER TYPE "NotificationType" ADD VALUE 'PEER_LINK_DECIDED';
ALTER TYPE "NotificationType" ADD VALUE 'PEER_LINK_PAYMENT_RECORDED';
ALTER TYPE "NotificationType" ADD VALUE 'PEER_LINK_SETTLEMENT_DECIDED';
ALTER TYPE "NotificationEntityType" ADD VALUE 'PEER_LINK';
ALTER TYPE "NotificationEntityType" ADD VALUE 'PEER_LINK_SETTLEMENT';

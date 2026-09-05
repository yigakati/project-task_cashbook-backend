-- Migration: stock requests
--
-- Reworks stock transfers from sender-initiated to REQUEST-driven:
-- the requester asks a vendor for stock (PENDING); the vendor accepts and
-- releases it (SENT — stock leaves their workspace); the requester confirms
-- receipt into a chosen workspace (COMPLETED — stock arrives). Roles keep
-- the historical column names: "sender" = vendor (stock-out on send),
-- "recipient" = requester (stock-in on receive).

ALTER TYPE "StockTransferStatus" ADD VALUE IF NOT EXISTS 'SENT';
ALTER TYPE "StockTransferStatus" ADD VALUE IF NOT EXISTS 'COMPLETED';

ALTER TABLE "stock_transfers" ADD COLUMN "expense_entry_id" UUID;
ALTER TABLE "stock_transfers" ADD COLUMN "income_entry_id" UUID;
ALTER TABLE "stock_transfers" ADD COLUMN "sent_at" TIMESTAMPTZ;
ALTER TABLE "stock_transfers" ADD COLUMN "received_at" TIMESTAMPTZ;

ALTER TABLE "stock_transfers"
    ADD CONSTRAINT "stock_transfers_expense_entry_fk"
    FOREIGN KEY ("expense_entry_id") REFERENCES "entries"("id") ON DELETE SET NULL;
ALTER TABLE "stock_transfers"
    ADD CONSTRAINT "stock_transfers_income_entry_fk"
    FOREIGN KEY ("income_entry_id") REFERENCES "entries"("id") ON DELETE SET NULL;

-- One entry per side, ever.
CREATE UNIQUE INDEX IF NOT EXISTS "stock_transfers_expense_entry_id_key" ON "stock_transfers"("expense_entry_id");
CREATE UNIQUE INDEX IF NOT EXISTS "stock_transfers_income_entry_id_key" ON "stock_transfers"("income_entry_id");

-- The vendor's workspace/item are only known when they send; a request
-- starts without them.
ALTER TABLE "stock_transfers" ALTER COLUMN "sender_workspace_id" DROP NOT NULL;
ALTER TABLE "stock_transfers" ALTER COLUMN "sender_item_id" DROP NOT NULL;

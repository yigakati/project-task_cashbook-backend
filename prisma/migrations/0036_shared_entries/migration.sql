CREATE TYPE "SharedEntryStatus" AS ENUM ('PENDING', 'ACCEPTED', 'DECLINED', 'CANCELLED');

CREATE TABLE "shared_entries" (
    "id" UUID NOT NULL,
    "source_entry_id" UUID,
    "recipient_user_id" UUID NOT NULL,
    "status" "SharedEntryStatus" NOT NULL DEFAULT 'PENDING',
    "source_version" INTEGER NOT NULL,
    "source_contact_id" UUID NOT NULL,
    "source_workspace_id" UUID NOT NULL,
    "sender_name" TEXT NOT NULL,
    "type" "EntryType" NOT NULL,
    "amount" DECIMAL(20,4) NOT NULL,
    "currency" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "entry_date" TIMESTAMP(3) NOT NULL,
    "accepted_entry_id" UUID,
    "response_reason" TEXT,
    "responded_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "shared_entries_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "shared_entries_source_entry_id_fkey" FOREIGN KEY ("source_entry_id") REFERENCES "entries"("id") ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT "shared_entries_recipient_user_id_fkey" FOREIGN KEY ("recipient_user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "shared_entries_accepted_entry_id_fkey" FOREIGN KEY ("accepted_entry_id") REFERENCES "entries"("id") ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT "shared_entries_acceptance_check" CHECK ("status" = 'ACCEPTED' OR "accepted_entry_id" IS NULL),
    CONSTRAINT "shared_entries_amount_check" CHECK ("amount" > 0)
);
CREATE UNIQUE INDEX "shared_entries_source_entry_id_recipient_user_id_key" ON "shared_entries"("source_entry_id", "recipient_user_id");
CREATE UNIQUE INDEX "shared_entries_accepted_entry_id_key" ON "shared_entries"("accepted_entry_id");
CREATE INDEX "shared_entries_recipient_user_id_status_created_at_idx" ON "shared_entries"("recipient_user_id", "status", "created_at");

-- Migration: agreement one-time entries
--
-- The rental contract's money legs are one-time by design: the borrower
-- records the cost once, the lender records the income once. These columns
-- capture which entry each side recorded, so the buttons disappear (and the
-- API refuses) once done — an accepted contract can never be double-billed.

ALTER TABLE "rental_agreements" ADD COLUMN "expense_entry_id" UUID;
ALTER TABLE "rental_agreements" ADD COLUMN "income_entry_id" UUID;

ALTER TABLE "rental_agreements"
    ADD CONSTRAINT "rental_agreements_expense_entry_fk"
    FOREIGN KEY ("expense_entry_id") REFERENCES "entries"("id") ON DELETE SET NULL;

ALTER TABLE "rental_agreements"
    ADD CONSTRAINT "rental_agreements_income_entry_fk"
    FOREIGN KEY ("income_entry_id") REFERENCES "entries"("id") ON DELETE SET NULL;

-- One entry per side, ever.
CREATE UNIQUE INDEX "rental_agreements_expense_entry_id_key" ON "rental_agreements"("expense_entry_id");
CREATE UNIQUE INDEX "rental_agreements_income_entry_id_key" ON "rental_agreements"("income_entry_id");

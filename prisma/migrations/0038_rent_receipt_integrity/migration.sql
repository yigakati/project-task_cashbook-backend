-- Deferred checks validate the completed receipt/allocation transaction.
CREATE FUNCTION check_rent_payment_integrity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE payment_id_to_check uuid; payment_row rent_payments%ROWTYPE; allocated numeric;
BEGIN
  IF TG_TABLE_NAME = 'rent_payments' THEN payment_id_to_check := NEW.id;
  ELSE payment_id_to_check := CASE WHEN TG_OP = 'DELETE' THEN OLD.payment_id ELSE NEW.payment_id END; END IF;
  SELECT * INTO payment_row FROM rent_payments WHERE id = payment_id_to_check;
  IF NOT FOUND THEN RETURN NULL; END IF; -- legal workspace purge
  SELECT coalesce(sum(amount), 0) INTO allocated FROM rent_allocations WHERE payment_id = payment_id_to_check;
  IF allocated <> payment_row.amount OR EXISTS (
    SELECT 1 FROM rent_allocations a JOIN rent_periods p ON p.id = a.period_id
    WHERE a.payment_id = payment_id_to_check AND p.tenancy_id <> payment_row.tenancy_id
  ) THEN RAISE EXCEPTION 'Rent payment allocations must equal the receipt and belong to its tenancy' USING ERRCODE = '23514'; END IF;
  IF payment_row.entry_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM entries e JOIN cashbooks b ON b.id = e.cashbook_id JOIN housing_tenancies t ON t.id = payment_row.tenancy_id
    WHERE e.id = payment_row.entry_id AND e.type = 'INCOME' AND e.amount = payment_row.amount
      AND b.workspace_id = t.workspace_id AND b.currency = t.currency AND e.obligation_id IS NULL
  ) THEN RAISE EXCEPTION 'Rent payment must reference its matching income receipt' USING ERRCODE = '23514'; END IF;
  RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER rent_payment_integrity AFTER INSERT OR UPDATE ON rent_payments
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_rent_payment_integrity();
CREATE CONSTRAINT TRIGGER rent_allocation_integrity AFTER INSERT OR UPDATE OR DELETE ON rent_allocations
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_rent_payment_integrity();

CREATE FUNCTION protect_rent_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS (SELECT 1 FROM rent_payments WHERE entry_id = OLD.id) AND (
   NEW.amount IS DISTINCT FROM OLD.amount OR NEW.type IS DISTINCT FROM OLD.type OR
   NEW.contact_id IS DISTINCT FROM OLD.contact_id OR NEW.obligation_id IS DISTINCT FROM OLD.obligation_id OR
   (NEW.cashbook_id IS DISTINCT FROM OLD.cashbook_id AND EXISTS (
     SELECT 1 FROM cashbooks old_book, cashbooks new_book WHERE old_book.id = OLD.cashbook_id AND new_book.id = NEW.cashbook_id
       AND (old_book.workspace_id <> new_book.workspace_id OR old_book.currency <> new_book.currency)
   ))
 ) THEN RAISE EXCEPTION 'Reverse the rent receipt and record a replacement payment' USING ERRCODE = '23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER rent_receipt_immutable BEFORE UPDATE ON entries FOR EACH ROW EXECUTE FUNCTION protect_rent_receipt();

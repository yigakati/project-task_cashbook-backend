ALTER TABLE "invoice_settings"
    ADD COLUMN "artwork_key" TEXT,
    ADD COLUMN "artwork_size" INTEGER;
ALTER TABLE "invoice_settings" ADD CONSTRAINT "invoice_artwork_size_valid"
    CHECK ("artwork_size" IS NULL OR "artwork_size" >= 0);

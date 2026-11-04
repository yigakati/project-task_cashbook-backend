ALTER TYPE "AuthProvider" ADD VALUE 'APPLE';
CREATE TABLE "apple_credentials" (
    "identity_id" UUID NOT NULL,
    "client_id" TEXT NOT NULL,
    "encrypted_refresh_token" TEXT NOT NULL,
    "updated_at" TIMESTAMP(3) NOT NULL,
    PRIMARY KEY ("identity_id", "client_id"),
    CONSTRAINT "apple_credentials_identity_id_fkey" FOREIGN KEY ("identity_id")
        REFERENCES "linked_identities"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE "auth_challenges" (
    "id" UUID NOT NULL PRIMARY KEY,
    "kind" TEXT NOT NULL,
    "client" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "verifier_hash" TEXT NOT NULL,
    "user_id" UUID,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "consumed_at" TIMESTAMP(3),
    "result_user_id" UUID,
    "result_code_hash" TEXT,
    "referral_code" TEXT,
    "referral_source" TEXT
);
CREATE INDEX "auth_challenges_expires_at_idx" ON "auth_challenges"("expires_at");

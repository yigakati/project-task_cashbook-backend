-- CreateEnum
CREATE TYPE "HousingUnitKind" AS ENUM ('ROOM', 'APARTMENT', 'HOUSE');

-- CreateEnum
CREATE TYPE "HousingTenancyStatus" AS ENUM ('ACTIVE', 'ENDED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "TenantInvitationStatus" AS ENUM ('PENDING', 'ACCEPTED', 'DECLINED');

-- CreateEnum
CREATE TYPE "RentalIssueKind" AS ENUM ('MAINTENANCE', 'PAYMENT_DISPUTE', 'CONCERN');

-- CreateEnum
CREATE TYPE "RentalIssueStatus" AS ENUM ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED');

-- CreateEnum
CREATE TYPE "RentalIssuePriority" AS ENUM ('LOW', 'NORMAL', 'URGENT');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "NotificationType" ADD VALUE 'HOUSING_INVITATION';
ALTER TYPE "NotificationType" ADD VALUE 'HOUSING_UPDATED';
ALTER TYPE "NotificationType" ADD VALUE 'RENT_DUE';
ALTER TYPE "NotificationType" ADD VALUE 'RENTAL_ISSUE_UPDATED';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "NotificationEntityType" ADD VALUE 'HOUSING_TENANCY';
ALTER TYPE "NotificationEntityType" ADD VALUE 'RENTAL_ISSUE';

-- AlterTable
ALTER TABLE "attachments" ADD COLUMN     "housing_unit_id" UUID;

-- CreateTable
CREATE TABLE "housing_units" (
    "id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "property_name" TEXT,
    "address" TEXT,
    "description" TEXT,
    "kind" "HousingUnitKind" NOT NULL DEFAULT 'APARTMENT',
    "currency" TEXT NOT NULL,
    "monthly_rent" DECIMAL(20,4) NOT NULL,
    "archived_at" TIMESTAMP(3),
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "housing_units_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "housing_tenancies" (
    "id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "unit_id" UUID NOT NULL,
    "tenant_name" TEXT NOT NULL,
    "contact_id" UUID,
    "tenant_user_id" UUID,
    "invitation_status" "TenantInvitationStatus",
    "status" "HousingTenancyStatus" NOT NULL DEFAULT 'ACTIVE',
    "start_date" DATE NOT NULL,
    "end_date" DATE,
    "actual_end_date" DATE,
    "monthly_rent" DECIMAL(20,4) NOT NULL,
    "first_period_amount" DECIMAL(20,4),
    "final_period_amount" DECIMAL(20,4),
    "due_day" INTEGER NOT NULL,
    "currency" TEXT NOT NULL,
    "notes" TEXT,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_by_id" UUID NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "housing_tenancies_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "rent_periods" (
    "id" UUID NOT NULL,
    "tenancy_id" UUID NOT NULL,
    "start_date" DATE NOT NULL,
    "end_date" DATE NOT NULL,
    "due_date" DATE NOT NULL,
    "amount" DECIMAL(20,4) NOT NULL,
    "cancelled_at" TIMESTAMP(3),
    "adjustment_reason" TEXT,
    "version" INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT "rent_periods_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "rent_payments" (
    "id" UUID NOT NULL,
    "tenancy_id" UUID NOT NULL,
    "entry_id" UUID,
    "request_id" UUID NOT NULL,
    "request_hash" TEXT NOT NULL,
    "amount" DECIMAL(20,4) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "rent_payments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "rent_allocations" (
    "id" UUID NOT NULL,
    "payment_id" UUID NOT NULL,
    "period_id" UUID NOT NULL,
    "amount" DECIMAL(20,4) NOT NULL,

    CONSTRAINT "rent_allocations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "rental_issues" (
    "id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "tenancy_id" UUID,
    "rental_id" UUID,
    "created_by_id" UUID NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "kind" "RentalIssueKind" NOT NULL,
    "priority" "RentalIssuePriority" NOT NULL DEFAULT 'NORMAL',
    "status" "RentalIssueStatus" NOT NULL DEFAULT 'OPEN',
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "rental_issues_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "rental_issue_messages" (
    "id" UUID NOT NULL,
    "issue_id" UUID NOT NULL,
    "author_id" UUID NOT NULL,
    "author_side" TEXT NOT NULL,
    "body" TEXT NOT NULL,
    "status" "RentalIssueStatus",
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "rental_issue_messages_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "housing_units_workspace_id_archived_at_idx" ON "housing_units"("workspace_id", "archived_at");

-- CreateIndex
CREATE UNIQUE INDEX "housing_units_workspace_id_name_key" ON "housing_units"("workspace_id", "name");

-- CreateIndex
CREATE INDEX "housing_tenancies_workspace_id_status_idx" ON "housing_tenancies"("workspace_id", "status");

-- CreateIndex
CREATE INDEX "housing_tenancies_tenant_user_id_invitation_status_idx" ON "housing_tenancies"("tenant_user_id", "invitation_status");

-- CreateIndex
CREATE INDEX "housing_tenancies_unit_id_start_date_idx" ON "housing_tenancies"("unit_id", "start_date");

-- CreateIndex
CREATE INDEX "rent_periods_due_date_cancelled_at_idx" ON "rent_periods"("due_date", "cancelled_at");

-- CreateIndex
CREATE UNIQUE INDEX "rent_periods_tenancy_id_start_date_key" ON "rent_periods"("tenancy_id", "start_date");

-- CreateIndex
CREATE UNIQUE INDEX "rent_payments_entry_id_key" ON "rent_payments"("entry_id");

-- CreateIndex
CREATE UNIQUE INDEX "rent_payments_tenancy_id_request_id_key" ON "rent_payments"("tenancy_id", "request_id");

-- CreateIndex
CREATE INDEX "rent_allocations_period_id_idx" ON "rent_allocations"("period_id");

-- CreateIndex
CREATE UNIQUE INDEX "rent_allocations_payment_id_period_id_key" ON "rent_allocations"("payment_id", "period_id");

-- CreateIndex
CREATE INDEX "rental_issues_tenancy_id_created_at_idx" ON "rental_issues"("tenancy_id", "created_at");

-- CreateIndex
CREATE INDEX "rental_issues_rental_id_created_at_idx" ON "rental_issues"("rental_id", "created_at");

-- CreateIndex
CREATE INDEX "rental_issues_workspace_id_status_idx" ON "rental_issues"("workspace_id", "status");

-- CreateIndex
CREATE INDEX "rental_issue_messages_issue_id_created_at_idx" ON "rental_issue_messages"("issue_id", "created_at");

-- AddForeignKey
ALTER TABLE "attachments" ADD CONSTRAINT "attachments_housing_unit_id_fkey" FOREIGN KEY ("housing_unit_id") REFERENCES "housing_units"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "housing_units" ADD CONSTRAINT "housing_units_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "housing_tenancies" ADD CONSTRAINT "housing_tenancies_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "housing_tenancies" ADD CONSTRAINT "housing_tenancies_unit_id_fkey" FOREIGN KEY ("unit_id") REFERENCES "housing_units"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "housing_tenancies" ADD CONSTRAINT "housing_tenancies_contact_id_fkey" FOREIGN KEY ("contact_id") REFERENCES "contacts"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "housing_tenancies" ADD CONSTRAINT "housing_tenancies_tenant_user_id_fkey" FOREIGN KEY ("tenant_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "rent_periods" ADD CONSTRAINT "rent_periods_tenancy_id_fkey" FOREIGN KEY ("tenancy_id") REFERENCES "housing_tenancies"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "rent_payments" ADD CONSTRAINT "rent_payments_tenancy_id_fkey" FOREIGN KEY ("tenancy_id") REFERENCES "housing_tenancies"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "rent_payments" ADD CONSTRAINT "rent_payments_entry_id_fkey" FOREIGN KEY ("entry_id") REFERENCES "entries"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "rent_allocations" ADD CONSTRAINT "rent_allocations_payment_id_fkey" FOREIGN KEY ("payment_id") REFERENCES "rent_payments"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "rent_allocations" ADD CONSTRAINT "rent_allocations_period_id_fkey" FOREIGN KEY ("period_id") REFERENCES "rent_periods"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "rental_issues" ADD CONSTRAINT "rental_issues_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "rental_issues" ADD CONSTRAINT "rental_issues_tenancy_id_fkey" FOREIGN KEY ("tenancy_id") REFERENCES "housing_tenancies"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "rental_issues" ADD CONSTRAINT "rental_issues_rental_id_fkey" FOREIGN KEY ("rental_id") REFERENCES "inventory_rentals"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "rental_issue_messages" ADD CONSTRAINT "rental_issue_messages_issue_id_fkey" FOREIGN KEY ("issue_id") REFERENCES "rental_issues"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Additive: existing rentals, attachment owners and financial rows are unchanged.
ALTER TABLE attachments DROP CONSTRAINT attachments_exactly_one_owner;
ALTER TABLE attachments ADD CONSTRAINT attachments_exactly_one_owner
 CHECK (num_nonnulls(cashbook_id, task_id, task_report_id, expense_claim_id, housing_unit_id) = 1);
CREATE UNIQUE INDEX housing_tenancies_one_active_unit ON housing_tenancies(unit_id) WHERE status = 'ACTIVE';
ALTER TABLE housing_units ADD CONSTRAINT housing_units_positive_rent CHECK(monthly_rent > 0);
ALTER TABLE housing_tenancies ADD CONSTRAINT housing_tenancy_terms CHECK (
 monthly_rent > 0 AND due_day BETWEEN 1 AND 31 AND (end_date IS NULL OR end_date > start_date)
 AND (actual_end_date IS NULL OR actual_end_date >= start_date)
 AND (first_period_amount IS NULL OR first_period_amount >= 0)
 AND (final_period_amount IS NULL OR final_period_amount >= 0));
ALTER TABLE rent_periods ADD CONSTRAINT rent_period_terms CHECK(end_date > start_date AND amount >= 0);
ALTER TABLE rent_payments ADD CONSTRAINT rent_payment_positive CHECK(amount > 0);
ALTER TABLE rent_allocations ADD CONSTRAINT rent_allocation_positive CHECK(amount > 0);
ALTER TABLE rental_issues ADD CONSTRAINT rental_issue_one_owner CHECK(num_nonnulls(tenancy_id, rental_id) = 1);
ALTER TABLE rental_issue_messages ADD CONSTRAINT rental_message_side CHECK(author_side IN ('LANDLORD', 'TENANT'));

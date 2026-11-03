# Housing tenancies and rental concerns

Housing extends Rentals with rooms, apartments and complete houses in a workspace.
Inventory checkout/return, stock movements, rental agreements and rental invoicing
retain their existing behavior. The shared concern workflow also works with those
inventory rentals. No existing rental is migrated into a housing unit.

## Implemented workflow

1. A workspace owner or a role with `MANAGE_INVENTORY` creates a property, reviews
   its units, then saves them together. Properties have distinct names within a
   workspace, an optional address/description, shared rent/type defaults, and
   numbering preferences. Register 1–500 units per submission, then add further
   batches from the property page. A standalone house is a property with one unit.
   Blocks and floors can be expressed through labels such as `Block A / Floor 2 / 03`.
   The three-step form supports pasted custom labels and per-unit rent/type overrides.
   Missing labels receive `Unit 01`, `Unit 02`, etc., with editable prefix/start.
   Custom labels are reserved before generating blanks; further batches skip all
   existing labels, including archived ones. Names and labels are trimmed and unique
   without regard to case, within the workspace and property respectively.
   Property currency is captured at creation; later batches keep it even when the
   workspace currency changes. Updating defaults affects new units only. Existing
   advertised rents and agreed tenancy amounts require their own explicit changes.
2. Assign a named tenant with move-in, optional planned move-out, monthly rent and
   due day. An offline tenant needs no account and no contact, so this does not
   bypass the platform's existing manual-contact creation rules. Attach an
   existing customer contact for shared payments and app invitations.
3. A verified matching contact or an active contact connection can receive an
   invitation. The invitation freezes the recipient's user ID. The tenant
   reviews and accepts in **My tenancies** before seeing charges, payments and
   concerns. Acceptance does not make the tenant a workspace member or create a
   financial entry. Declining app access does not erase the landlord's occupancy
   record. An offline tenant can be linked later using **Link / invite tenant**;
   earlier receipts are not automatically resent.
4. Monthly periods follow the original move-in anniversary. January 31 progresses
   to February 28/29 and then March 31. Dates use half-open intervals `[start,end)`:
   the move-out date is the first day the tenant no longer occupies the unit.
   Due day is clamped to the last day of short months; a due date before a period
   starts is moved to that period's start. Every due date remains adjustable.
5. The initial schedule covers twelve periods, bounded by any planned end. An
   hourly scheduler catches up missed periods and extends open tenancies through
   the following month. Managers can extend the schedule up to two years ahead
   for advance payments. All generation is idempotent and preserves adjustments.
   A shortened final period requires its agreed amount; no automatic proration,
   fees, penalties, tax or deposit calculation is applied. First-period amounts
   and individual period charges/due dates can be adjusted with a reason.
6. Record a manually received payment by choosing a permitted active book and
   account in the tenancy currency and allocating amounts to one or several rent
   periods. Partial and advance payments are supported. The entry, balanced
   journal, wallet projection, payment allocations, audit and shared-entry offer
   commit together. A durable request UUID prevents repeat posting, including
   retries with a different HTTP idempotency key. Changed reuse of that UUID is
   rejected. The UI retains interrupted submissions in tab session storage so a
   reopened form retries the same payment.
7. The landlord's income creates the existing **Shared entries** expense offer
   for an eligible contact. The tenant chooses their own workspace, book and
   account when accepting it. Sender fees and private attachments are not copied.
   This preserves recipient consent and avoids choosing someone else's accounts.
   Tenant financial entries remain independent after acceptance.
8. The Properties landing page shows searchable properties and unit counts. Each
   property page contains its units, assignment actions and tenancy history.
   The workspace overview shows registered, assigned and unassigned units, plus
   overdue rent by currency. Tenancy details show all scheduled periods and
   paginated receipts. A receipt's source book is linked only when the caller has
   permission to post there. Tenant views omit landlord contact IDs, private notes,
   book/account choices, and source receipt IDs.
9. Record actual move-out to free the unit. Unpaid past rent remains collectible;
   future unpaid periods are cancelled. The app refuses to discard payments on
   future periods or reduce a charge below received payments. Planned expiry
   alone never marks an occupied unit vacant. A recorded holdover uses the agreed
   monthly rate for additional complete months and an explicit final partial
   amount; the original planned end and actual move-out are both retained.
   Cancelling a scheduled tenancy uses its move-in date as the end, with no paid
   future periods. Another tenancy can then start without losing history.
10. Tenants and managers can raise maintenance requests, payment disputes and
    other concerns. Each has a priority, status and append-only response history.
    Managers can mark work in progress or resolved; tenants can close or reopen
    their concerns. Replies use a reviewed version so simultaneous changes do not
    overwrite one another. This is an issue thread, not the deferred chat/meeting
    feature. Connected customers and accepted borrowers can use the same workflow
    for existing inventory rentals, without changing rental/return processing.

## Financial and permission rules

- Rent schedules are an operational register, not automatic ledger receivables.
  Only received payments post cash-basis income. This avoids double-booking rent
  through both a schedule and an obligation/invoice. Do not also record the same
  payment manually as a separate cashbook entry.
- Allocation totals must equal the receipt; every allocation belongs to that
  tenancy. Database constraints back these rules. Receipt amount, direction,
  contact and obligation cannot be changed after allocation. Correct a mistaken
  receipt by reversing it through the existing cashbook permission/review flow,
  then recording its replacement from the tenancy.
- Reversal restores outstanding rent because balances sum only posted receipts.
  It cancels pending shared offers through the existing lifecycle. An already
  accepted tenant entry is retained and receives the existing reversal warning.
  Reversing an actual, valid receipt is **not** a substitute for a real refund.
- Book roles take precedence over implicit workspace access. Currency, backdate,
  archive, account and closed fiscal-period checks remain in the normal entry
  service. Tenants see only their assigned tenancy and its issues. Staff contacts
  are not inferred to be tenants. Inactive/deleted accounts cannot access the new
  surfaces. Workspace purges preserve the other party's accepted financial entry.
- Only one active or scheduled tenancy can hold a unit at a time. Property → unit →
  tenancy locks and
  a partial unique index prevent concurrent double-assignment. Date checks also
  prevent overlap with ended history. Future reservations alongside a current
  tenancy are deliberately outside this version.
- Accepted tenant identity is separate from the mutable contact. A contact edit
  cannot replace an accepted tenant; a different occupant needs a new tenancy.
  A payment is refused if the contact now points to another app user. Contact
  disconnection stops shared delivery using the existing contact rules; it does
  not erase an already accepted tenancy. An archived contact does not prevent
  recording arrears: its new receipt omits the inactive contact and is not shared.

## Photos and notifications

Unit images use the existing private MinIO bucket and attachment storage quota.
JPEG/PNG/WebP content is decoded with a pixel limit, orientation corrected,
metadata removed and re-encoded to WebP. Maximum: 12 photos per unit and 10 MB per
upload. Presigned URLs require unit or accepted-tenancy access. Soft deletion
frees the workspace allowance; rejected uploads are cleaned up. Unit photos appear
in the existing Storage panel with property and unit context. There are no publicly readable listing endpoints.

In-app notifications cover invitations, invitation decisions, payments, charge
adjustments, move-out and issue updates. Rent reminders run three days before a
charge is due, on its due date and weekly while overdue. Paid/cancelled periods
are skipped. Workspace-local calendar dates govern due checks. Deterministic
notification keys prevent duplicate delivery across scheduler retries/replicas.
Tenants' notifications live in their own accessible workspace, not the landlord's;
notification links resolve the correct personal or management view. No email,
SMS or push delivery was introduced.

## API

All paths require authenticated app sessions and begin with `/api/v1`.
Pagination uses `page` and `limit` (maximum 100).

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/workspaces/:workspaceId/housing/summary` | Vacancy/assignment and overdue totals |
| GET, POST | `/workspaces/:workspaceId/housing/properties` | Search/list properties or atomically create property + units |
| POST | `/workspaces/:workspaceId/housing/properties/preview` | Resolve and validate labels/defaults without saving |
| GET, PATCH | `/workspaces/:workspaceId/housing/properties/:propertyId` | Detail/counts or edit/archive/restore with `expectedVersion` |
| POST | `/workspaces/:workspaceId/housing/properties/:propertyId/units/preview` | Review another batch against existing labels |
| POST | `/workspaces/:workspaceId/housing/properties/:propertyId/units` | Atomically add the reviewed batch |
| GET, POST | `/workspaces/:workspaceId/housing/units` | Search/list or add one named unit to an explicit property |
| PATCH | `/workspaces/:workspaceId/housing/units/:id` | Edit, archive or restore, with `expectedVersion` |
| POST | `/workspaces/:workspaceId/housing/units/:id/photos` | Multipart image field `file` |
| GET, DELETE | `/workspaces/:workspaceId/housing/units/:id/photos/:photoId` | Private photo URL or soft deletion |
| GET, POST | `/workspaces/:workspaceId/housing/tenancies` | History or assignment |
| GET | `/workspaces/:workspaceId/housing/tenancies/:id` | Terms, periods and paginated receipts |
| POST | `/workspaces/:workspaceId/housing/tenancies/:id/invite` | Link/invite an existing contact |
| POST | `/workspaces/:workspaceId/housing/tenancies/:id/end` | Actual move-out or cancellation |
| POST | `/workspaces/:workspaceId/housing/tenancies/:id/periods` | Generate through a date |
| PATCH | `/workspaces/:workspaceId/housing/tenancies/:id/periods/:periodId` | Charge/due-date adjustment with reason/version |
| GET | `/workspaces/:workspaceId/housing/tenancies/:id/payment-options` | Permitted books/accounts |
| POST | `/workspaces/:workspaceId/housing/tenancies/:id/payments` | Atomic receipt and allocations |
| GET | `/housing/tenancies` | Personal tenant inbox/history |
| GET | `/housing/tenancies/:id` | Tenant-safe detail |
| GET | `/housing/tenancies/:id/location` | Authorized notification destination |
| POST | `/housing/tenancies/:id/accept` or `/decline` | Tenant invitation decision |
| GET | `/housing/tenancies/:id/photos/:photoId` | Accepted tenant's private photo access |
| GET | `/rental-issues/rentals/mine` | Linked inventory rentals for tenant concerns |
| GET, POST | `/rental-issues` | List/create by exactly one `tenancyId` or `rentalId` |
| GET | `/rental-issues/:id` | Issue detail and paginated responses |
| POST | `/rental-issues/:id/messages` | Response and optional status, with `expectedVersion` |

Unit and management tenancy lists accept `propertyId`; the summary accepts the same
filter. Property and unit lists support `search` and `archived=true|false`. Counts
come from actual unit/tenancy records, not a mutable property capacity field.

Property preview example:

```json
{
  "name": "Sunrise",
  "address": "Ntinda",
  "defaultKind": "ROOM",
  "defaultMonthlyRent": "400000",
  "unitCount": 3,
  "unitLabelPrefix": "Unit ",
  "unitNumberStart": 1,
  "units": [{}, { "name": "Unit 01" }, { "name": "A1", "monthlyRent": "450000" }]
}
```

The response resolves labels to `Unit 02`, `Unit 01`, and `A1`, and includes currency
and `previewToken`. Submit the same input plus that token and a fresh UUID `requestId`
to create. For additional batches, the preview also supplies `expectedVersion`;
submit both to save. Changed defaults, labels, archive state, or inventory versions
produce an actionable 409 requiring review again, rather than silently relabeling.
A durable `HousingProvisioningRequest` stores the normalized payload hash and result
in the creation transaction. Identical retries return the original IDs; changing
an already committed request's payload fails. Retain the exact submitted request
through a timeout or server interruption. These provisioning endpoints use durable
transactional idempotency directly, without the generic HTTP response cache.

Standalone `POST /units` registration is no longer accepted. It requires `propertyId`
and `requestId`; existing unit IDs, tenancy URLs, photos and receipt contracts remain
stable. Labels can repeat in different properties. The tenant projection contains
only their property/unit identity and address, with no sibling units or defaults.

Archival retains names, unit IDs, photos and history. End/cancel all active or
scheduled assignments before archiving a unit or property. Restoring a property
preserves each unit's individual archive state. Historical arrears remain visible
and collectible. Renames are audited; new receipts, reminders, issues and storage
listings show property name plus unit label. Existing receipt descriptions are kept.

Payment example (send an `Idempotency-Key` too):

```json
{
  "requestId": "client-generated-uuid",
  "cashbookId": "landlord-book-uuid",
  "accountId": "landlord-account-uuid",
  "entryDate": "2026-10-28T09:00:00.000Z",
  "allocations": [
    { "periodId": "rent-period-uuid", "amount": "400000" }
  ]
}
```

Optional `categoryId` and `paymentModeId` follow existing workspace reference
validation. Amounts are decimal strings with at most four fractional digits;
monthly rent and payments must be positive. A fully waived period can have a zero
charge with an audited adjustment. Housing dates use `YYYY-MM-DD`.

Payment retries retain a durable financial `requestId` and the exact UTC payload
through network timeouts, server errors and `IDEMPOTENCY_IN_PROGRESS` responses.
A retry may use a new transport header key to bypass a stranded HTTP cache record;
the financial request ID does not change. Only a deliberately revised submission
after a definite rejection gets a new financial ID. Stored drafts are validated,
and unavailable session storage or cleanup failures cannot change a receipt result.

## Recommendations requiring a later product decision

1. **Deposits and refunds:** track security deposits as liabilities, with return,
   deductions, evidence and tenant acknowledgement. Add actual refund/credit
   allocation before supporting early move-out against valid advance payments.
   Treating a refundable deposit as ordinary rent income would misstate earnings.
2. **Renewals and rent changes:** effective-dated amendments, notice periods,
   tenant acknowledgement, and explicit settlement of final rent. Add scheduled
   future tenancies/reservations only with date-range exclusion and conflict
   handling; the current single-holder rule is intentionally simpler.
3. **Utilities and shared costs:** separately named recurring/one-off charges,
   meters, allocation rules and statements. Agree whether each charge is income,
   reimbursement or a liability before choosing ledger treatment.
4. **Receipts and reconciliation:** optional receipt sending through the existing
   receipt service, reference numbers, reconciliation with bank/mobile-money
   imports, and later payment-provider webhooks with independent idempotency.
5. **Maintenance operations:** photos/evidence for issues, responsible staff,
   work orders, response targets, costs and escalation. The issue IDs and history
   introduced here give that workflow a stable starting point.
6. **Tenant agreements and move-in/out inspections:** documents, inventory/condition
   checklists, co-tenants/guarantors, handover acknowledgement and audit exports.
7. **Reminder preferences:** tenant opt-in settings, grace periods, quiet hours,
   email/SMS/push options and consolidated arrears notices. Do not auto-apply late
   penalties without explicit terms and jurisdiction-specific review.
8. **Public listings:** add explicit publish/unpublish consent and a dedicated
   public projection over units. Derive availability from actual assignment and
   reservations; never expose tenant names, private address details, payment
   records or internal photos by default. The unit's stable ID, type, building,
   description, rent, currency, images and archive state are available to build on.
9. **Chat and meetings:** a separate participant-authorized conversation/call
   feature can reference tenancy IDs. Issue response history should remain
   searchable and separate from general conversations.

## Rollout and verification

Apply migrations `0037_housing_tenancies`, `0038_rent_receipt_integrity`, and
`0039_housing_properties` before starting the new backend, then deploy the frontend.
These migrations do not backfill rent, change existing balances, or publish units.

```sh
npm run prisma:migrate:prod
npm run prisma:generate
npm run build
```

Verification lives in `src/test/housing/` and the frontend's `PropertyWizard.test.tsx`,
`RentPaymentForm.test.tsx` and `RentalIssues.test.tsx`. It exercises real database
transactions and ledger posting, concurrent assignments/payments, recipient
consent, reversal, quota and image validation, old rental concerns, tenant/workspace
isolation, due schedules, calendar boundaries, stale versions, pagination and
legal workspace purge. Frontend tests cover exact decimal allocation, required
book/account choices, picker reset, failed loading, interrupted submission/reopen,
and concurrent issue replies. Existing regression suites are run separately.

Verified on 2026-11-02:

- Complete backend regression: **1,186 tests across 71 files**, including 19 property
  and migration cases and the existing 24 housing/financial integration cases.
- Complete frontend regression: **53 tests across 10 files** with
  `pnpm test --maxWorkers=1`. Serial execution avoids existing shared-entry test
  timeouts under concurrent build/browser load without extending their timeouts.
- Both TypeScript checks, both production builds, Prisma validation, scoped
  frontend lint, both housing format checks, and staged/unstaged/new-file
  whitespace checks passed.
- Browser smoke used a separate temporary database: ten mixed-label units,
  per-unit rent/type overrides, tenant assignment and return navigation, later
  batch additions, duplicate-label feedback, occupied-property archive rejection,
  workspace switching, keyboard controls, and the 390-pixel mobile layout.
- Mobile detail had no horizontal page overflow. The two-unit later batch skipped
  existing labels and left the property with 12 units, one assigned and 11 unassigned.
- Switching workspaces returns property details/batch registration to Properties;
  drafts for new properties reset with the active workspace. The second browser
  workspace showed no properties, units, or tenants from the first.

Only isolated test databases were migrated. The development database has not been
migrated as part of testing. The temporary browser server/database are removed
after smoke testing. Both Git indexes and applied migrations 0037/0038 are preserved.
No changes are staged or committed by this work.

### Property migration and rollout

Keep applied migrations `0037` and `0038` unchanged. Deploy `0039_housing_properties`,
then the backend, then the frontend. Coordinate the rollout so older clients do not
attempt standalone unit creation during the registration contract transition.

The migration works on empty and populated housing tables. It groups legacy units
only when their trimmed non-empty property name, address, workspace and currency
match exactly. Unnamed or ambiguous units get separate properties. Property-name
collisions receive deterministic numeric suffixes. Unit IDs, dependent tenancies,
photos and financial records are preserved. Case/whitespace label conflicts within
one group, or cross-workspace tenancy references, stop the migration transaction
with a remediation message. Resolve the reported legacy data conflicts and retry;
never edit already-applied migrations or silently relabel occupied units.

Formatting checks: `npm run format:housing:check` in the backend and
`pnpm format:housing:check` in the frontend. The scoped configuration uses four-space
backend and two-space frontend indentation; Prisma declarations retain its standard
aligned two-space layout.

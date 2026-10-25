# Shared cashbook entries

Recording a payment with an eligible contact creates an offer in that person's
**Shared entries** inbox. The sender records their own transaction immediately.
The recipient explicitly chooses their workspace, cashbook and account before
the opposite entry is posted. An expense becomes income, and income becomes an
expense. No balances change merely because an offer arrived.

## Existing flows and integration

- `EntriesService.createEntry` owns the financial transaction. Delivery is
  written inside that transaction, so a rolled-back entry cannot leave an offer.
- `SharedEntriesService.accept` calls `EntriesService.createEntryWithin` inside
  its own transaction. It therefore uses the existing journal, wallet projection,
  book totals, fiscal-period checks, account overdraft checks and audit records.
- Contacts can identify a platform user directly, through a contact connection,
  or through an exact verified email address. A connected business is addressed
  to the person who accepted/requested its connection, provided that person still
  belongs to the represented workspace. Billing addresses are not used to guess
  a connected business's recipient. Inactive users, self contacts and staff
  contacts do not receive these offers.
- Peer-linked loan payments retain the existing `PeerLinkSettlement` workflow.
  Imported entries never generate a return offer. API integrations and internal
  entry writers are not automatically enrolled by `createEntryWithin`.
- Normal entry creation/update rejects contacts, categories and payment modes
  that are inactive or belong to another workspace.

## Recipient choices

The inbox is person-scoped and accessible from the app header and each book's
entries toolbar. It is independent of the currently selected workspace.

Only active books in active workspaces with the same currency and the recipient's
entry-creation permission appear. Explicit book roles take precedence over
implicit organisation access. Personal workspaces remain owner-only. The sender's
workspace is excluded to avoid recording both sides in the same organisation.

The account must be active, in the chosen workspace and in the entry currency.
Recipients may choose their own category, payment mode, fee and, when permitted,
an existing payable/receivable. The original date is prefilled; choosing a different
record date keeps the original in the acceptance audit. Book backdate rules and
closed fiscal periods still apply.

Sender fees, attachments and inventory movements are not copied. A reciprocal
contact is reused when present in the chosen workspace. Otherwise the sender's
identity remains available in the sharing record and entry audit. Classification
IDs from the source workspace never cross into the destination entry.

## Lifecycle and concurrency

- A database unique constraint allows one offer per source entry and recipient,
  and one accepted entry per offer. Concurrent accepts and retries return the same
  recorded entry, including retries with a new HTTP idempotency key.
- Acceptance locks both cashbooks in a consistent order and checks the source
  version reviewed by the recipient. Source edits and reversals cannot slip
  between validation and posting. Entry creation and acceptance commit together.
- Pending snapshots follow source edits. A stale review returns HTTP 409 and
  must be reopened. Changing the source contact cancels the old pending delivery.
- Declined/cancelled offers do not reopen. Reversing a source cancels pending
  offers; disconnecting/removing a contact also cancels pending deliveries.
- Accepted copies are independent. Later source changes/reversals appear as
  warnings in the inbox and entry details; they never rewrite the recipient's
  financial records. Reversing an accepted copy does not enable re-import.
- Account deletion cancels pending deliveries. Legal workspace purges detach
  source/destination foreign keys without deleting the other party's records.
- Senders see delivery status only. Recipient workspace/book/account choices
  and decline notes are not returned to the sender. The recipient's recorded
  location is shown only while they retain permission to view that book.

## API

All paths below are under `/api/v1` and require authentication.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/shared-entries?status=PENDING&page=1&limit=20` | Paginated personal inbox; omit status for history |
| GET | `/shared-entries/count` | Pending badge count |
| GET | `/shared-entries/:id/destinations` | Permitted books across workspaces |
| GET | `/shared-entries/:id/options/:cashbookId` | Accounts and optional classifications/obligations |
| POST | `/shared-entries/:id/accept` | Record the opposite entry |
| POST | `/shared-entries/:id/decline` | Decline, with optional `reason` |
| GET | `/entries/:entryId/sharing/cashbook/:cashbookId` | Book-scoped delivery status/provenance |

Acceptance body:

```json
{
  "cashbookId": "destination-book-uuid",
  "accountId": "destination-account-uuid",
  "expectedVersion": 1
}
```

Optional acceptance fields: `entryDate` (ISO datetime), `categoryId`,
`paymentModeId`, `obligationId`, `chargeAmount` (decimal string). Amount, direction
and description come from the reviewed offer and cannot be supplied by the client.
Send an `Idempotency-Key` header for acceptance. Non-recipients receive 404 for
inbox actions. The normal book permissions govern the entry-sharing status route.

## Rollout and verification

Deploy migration `0036_shared_entries` before the new backend and frontend:

```sh
npm run prisma:migrate:prod
npm run prisma:generate
npm run build
```

The migration adds a table and constraints; it does not alter balances or deliver
historical entries. Existing entries can become eligible when edited with a
contact. No bulk backfill or external notification delivery is performed.

Backend integration coverage is in `src/test/entries/shared-entries.test.ts`.
Frontend interaction coverage is in
`src/components/entries/SharedEntryReview.test.tsx` in `INCHANGE_CLIENT`.
These exercise both directions, decimal money, permission boundaries, stale and
concurrent decisions, account/currency/archive/date restrictions, loan exclusion,
obligation settlement, disconnection, source purges, and picker reset/error states.

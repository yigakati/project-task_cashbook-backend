# Receipts when recording entries

Income linked to a contact offers **Save income**, **Save & send receipt**, and **Save & print receipt**. The send option appears only when the contact has a valid email. Receivable payments use the same choices. Expenses and income without a contact keep the normal save action. Existing entries can still be receipted from their detail panel.

The entry commits before any receipt request. Printing or emailing failure never rolls it back. The receipt dialog keeps the saved entry visible, reports errors, and retries only receipt loading or delivery. Creating an entry no longer implicitly emails receipts for obligation payments; API clients wanting delivery must call the receipt endpoint explicitly.

## Receipt identity and branding

Both the preview and emailed PDF use the same receipt projection. The issuer comes from the workspace business profile: display name (workspace name fallback), legal name, complete address, billing/contact email, phone, website, tax and registration numbers. The logo, notes, footer and accent come from invoice settings. Missing or unreadable logos fall back to the platform logo. PDFs bundle their logo and licensed fonts and do not depend on remote fallback downloads or host-installed fonts.

Amounts retain four-decimal accounting precision and dates use the workspace timezone. Walk-in sales omit obligation totals; receivable payments show the current total and outstanding balance. Receipt numbers and existing entry IDs retain their previous convention. These are payment acknowledgements, not tax invoices.

## API and access

- `GET /api/v1/entries/:entryId/receipt/cashbook/:cashbookId` returns the model, `entryVersion`, and `canEmail`.
- `POST /api/v1/entries/:entryId/receipt/send/cashbook/:cashbookId` accepts optional `{ "expectedVersion": 1, "email": "contact@example.test" }` and a UUID `Idempotency-Key`. The email field confirms the reviewed contact address; it cannot override the recipient.
- Both endpoints require existing entry-view permission and check the entry belongs to the authorized book. Deleted, reversed, outgoing and unlinked entries cannot be receipted. Related detail, audit, edit and reversal routes also check the supplied book.
- A changed version or recipient returns 409 and requires a fresh review. No valid contact email returns 400; unconfigured email returns 503. Successful send means acceptance by the configured email transport, not confirmed inbox delivery.

## Retries and recovery

The creation hook keeps the exact payload and request ID in session storage, scoped to user and book. Network failures and in-progress responses offer recovery of that submission. A known saved entry stores its ID so reopening resumes the receipt. After a definite rejection, deliberately changed input gets a new request ID. Stored drafts are validated; storage failure does not turn a committed entry into a failed payment.

HTTP idempotency records are retained for 24 hours. The UI refuses to replay an unresolved financial submission after 23 hours; reconcile it against existing entries first. Recovery is available in the same browser session, and other sessions can use the saved entry's detail panel. Storage disabled by the browser limits recovery to the mounted form.

Receipt sends reuse their request ID for retries and reopening with the same reviewed email/version. Concurrent sends with that ID execute once, and successful retries replay the original result. SMTP and the database cannot commit atomically: a connection loss after SMTP acceptance can leave delivery uncertain. A durable email outbox with a provider idempotency key is the next step if stronger delivery guarantees are needed. Never retry an entry creation merely to resend its receipt.

## Deployment and checks

No database migration is required. Deploy backend before frontend. Use `npm run build` so the PDF font assets and their SIL Open Font License are copied into `dist`; the existing Docker build includes them.

Backend: `npm run format:receipts:check`, `npm run typecheck`, `npm test`, `npm run build`, and Prisma validation. Frontend: `pnpm run format:receipts:check`, scoped ESLint, TypeScript, `pnpm test --maxWorkers=1`, and `pnpm run build`.

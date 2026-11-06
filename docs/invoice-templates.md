# Invoice templates and rollout

The workspace chooses one design for invoice details, draft previews, PDF downloads and email attachments. The catalogue includes Classic, Modern, Contemporary, Essential, Ledger, Letterhead, Executive, Editorial, Studio and Signature. The final four are premium designs, available free during the initial rollout.

## Subscription activation

`INVOICE_SUBSCRIPTIONS_ACTIVE=false` is the safe deployment default. All templates are selectable. Advanced layout controls are enabled only in backend development/test environments. Existing branding, logos, colour and default content remain free.

Set `INVOICE_SUBSCRIPTIONS_ACTIVE=true` when subscriptions launch. The workspace owner's active STARTER, GROWTH or ENTERPRISE subscription unlocks premium selection and advanced layout controls. Cancellation and expiry use the existing billing grace-period rules. A member's personal subscription cannot unlock somebody else's workspace. Development/test still enables all options. No frontend environment flag can bypass these checks.

Existing saved designs keep rendering after a downgrade; new premium selection/customization is blocked. This avoids changing documents on plan expiry. Advanced options are an allowlist: typography, spacing, table style, logo placement and A4/US Letter. Arbitrary HTML/CSS is rejected. Essential financial information cannot be hidden. Letterhead and Signature retain a centred logo.

## Content and history

Changes to the selected design, branding or business profile apply on the next view/export of existing invoices. Previously downloaded or emailed PDFs remain unchanged. Invoice notes, footer and payment terms are saved per invoice; defaults only fill newly created invoices. Explicit empty content stays empty. Existing bill-to snapshots are honoured instead of rewriting historical customer details. Logo storage/quota behavior is unchanged; the platform logo is bundled for offline server rendering.

Amounts in documents are formatted from decimal strings with up to four fractional digits. Tax and rental totals come from the server. Item order follows input order for new invoices; migration preserves the prior UUID order for old invoices. Long rows and terms paginate with repeated table headings and page numbers. PDF files embed the bundled Liberation Sans font (licence in entries/assets); serif headings use PDF standard Times.

## API and deployment

Deploy migration `0041_invoice_templates`, generate Prisma client, deploy backend, then frontend. Prior migrations are unchanged. No financial data is rewritten.

Under `/workspaces/:workspaceId/invoices`:

- `GET /settings/current`: settings, version, template catalogue and server access decisions.
- `PATCH /settings/current`: validated appearance/default-content patch. Send the returned version to detect concurrent edits (409). Older clients can omit it. Logo changes save separately; uploading a logo does not overwrite appearance edits.
- `POST /settings/preview`: fictional sample document with unsaved appearance/default-content values; no writes to accounting.
- `POST /settings/preview/pdf`: the corresponding sample PDF.
- `POST /preview/draft`: create-invoice-shaped input, returning server-calculated document data without persisting an invoice.
- `GET /:invoiceId/document`: presentation data for the invoice.
- `GET /:invoiceId/pdf`: ephemeral PDF download.

Read/preview/download endpoints require VIEW_INVOICING, draft preview and mutations require MANAGE_INVOICING. Every document resolves within the requested workspace. Document responses have `Cache-Control: no-store`.

The send response includes `emailDelivery`: `sent`, `failed`, `not_configured` or `no_email`. Issuance and optional payment finish before the PDF is generated. A delivery failure does not undo accounting; the UI offers the PDF for manual sharing. No real emails are sent by the automated tests.

## Verification

Run resource-heavy tasks sequentially, not concurrently:

```sh
npx vitest run --maxWorkers=1 --minWorkers=1 --poolOptions.threads.maxThreads=1
npm run build
npx prisma validate
npm run format:invoices:check
```

PDF tests use Poppler `pdftotext` to verify actual rendered content. Install `poppler-utils` in CI. Frontend tests use one worker. Browser printing is available; the PDF download is the paginated export for sharing and native iOS uses the existing share flow.

# Invoice templates and rollout

The workspace chooses one design for invoice details, draft previews, PDF downloads and email attachments. The catalogue includes Classic, Modern, Contemporary, Essential, Ledger, Letterhead, Executive, Editorial, Studio and Signature. The original collection remains compatible. Blueprint, Mineral, Noir Wave, Workshop, Navy Panel, Ribbon, Brandmark, Architecture, Prism, Aura, Botanical and Lattice add 12 distinct designs inspired by the supplied references. Blueprint and Navy Panel are professional designs; the other new designs are premium, free during the initial rollout. The artwork is original vector illustration, bundled as PNG for both renderers; screenshot branding and signatures are not copied.

## Subscription activation

`INVOICE_SUBSCRIPTIONS_ACTIVE=false` is the safe deployment default. All templates are selectable. Advanced layout controls are enabled only in backend development/test environments. Existing branding, logos, colour and default content remain free.

Set `INVOICE_SUBSCRIPTIONS_ACTIVE=true` when subscriptions launch. The workspace owner's active STARTER, GROWTH or ENTERPRISE subscription unlocks premium selection and advanced layout controls. Cancellation and expiry use the existing billing grace-period rules. A member's personal subscription cannot unlock somebody else's workspace. Development/test still enables all options. No frontend environment flag can bypass these checks.

Existing saved designs keep rendering after a downgrade; new premium selection/customization is blocked. This avoids changing documents on plan expiry. Advanced options are an allowlist: typography, spacing, table style, logo placement, A4/US Letter, theme artwork, decorative image placement and bounded watermark/background strength. Arbitrary HTML/CSS is rejected. Essential financial information cannot be hidden. Letterhead and Signature retain a centred logo.

## Content and history

Changes to the selected design, branding or business profile apply on the next view/export of existing invoices. Previously downloaded or emailed PDFs remain unchanged. Invoice notes, footer and payment terms are saved per invoice; defaults only fill newly created invoices. Explicit empty content stays empty. Existing bill-to snapshots are honoured instead of rewriting historical customer details. Logo storage/quota behavior is unchanged; the platform logo is bundled for offline server rendering.

Amounts in documents are formatted from decimal strings with up to four fractional digits. Tax and rental totals come from the server. Item order follows input order for new invoices; migration preserves the prior UUID order for old invoices. Long rows and terms paginate with repeated table headings and page numbers. PDF files embed the bundled Liberation Sans font (licence in entries/assets); serif headings use PDF standard Times.

## API and deployment

Deploy migrations `0041_invoice_templates` and `0042_invoice_artwork`, generate Prisma client, deploy backend, then frontend. Prior migrations are unchanged. No financial data is rewritten.

Under `/workspaces/:workspaceId/invoices`:

- `GET /settings/current`: settings, version, template catalogue and server access decisions.
- `PATCH /settings/current`: validated appearance/default-content patch. Send the returned version to detect concurrent edits (409). Older clients can omit it. Logo changes save separately; uploading a logo does not overwrite appearance edits.
- `POST /settings/preview`: fictional sample document with unsaved appearance/default-content values; no writes to accounting.
- `POST /settings/preview/pdf`: the corresponding sample PDF.
- `POST /preview/draft`: create-invoice-shaped input, returning server-calculated document data without persisting an invoice.
- `POST /preview/draft/pdf`: the same validated input and calculations rendered as a private PDF; does not save, issue or record payments.
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

PDF tests use Poppler `pdftotext` to verify actual rendered content. Install `poppler-utils` in CI. Frontend tests use one worker. Invoice Print loads the same authenticated PDF endpoint as Download. Every page is rendered and decoded before the print sheet opens; PDF page dimensions determine A4/Letter print sizing. A dedicated print dialog excludes app chrome and HTML previews from the print layout. Draft printing uses the exact reviewed input snapshot and never saves or issues the invoice. Closing or switching workspaces aborts pending loading; failures offer PDF retry/download. Downloads retain the original vector PDF, and native iOS uses the existing print/share bridge. Printer settings can still apply scaling or hardware margins; use the document paper size and actual-size printing.

## Decorative artwork

The theme catalogue uses bundled illustrations; Workshop and Architecture are industry illustrations, not stock photos. Advanced customization lets a business upload its own static PNG/JPEG/WebP banner, page background or watermark. Uploads are capped at 10 MB/20 megapixels, decoded and normalized with Sharp, stripped of metadata, and stored privately under `invoice-artwork/`. The current image is served through an opaque URL because invoices are shared outside the app; it should contain only artwork the business intends to publish. Remote URLs, SVG, animation and arbitrary CSS/HTML are refused. Faint backgrounds and a dark photo-header overlay preserve text contrast. No signature is implied: the screenshot signatures are intentionally omitted rather than fabricating an issuer's authorization.

`POST /settings/current/artwork` requires MANAGE_INVOICING and server customization access. Replacements are serialized by the workspace storage lock, recheck quotas, delete obsolete objects best-effort, and leave unsaved appearance edits intact. `PATCH /settings/current` with `artworkUrl: null` removes the image (including after plan downgrade). Storage overview and platform usage include artwork bytes; account deletion removes its objects. Generate bundled assets with `node scripts/build-invoice-theme-assets.cjs`; build copies them to `dist`.

Themes and photos never replace line-item text. Amounts, status, customer context and page numbers remain present, including continuation pages. Existing saved IDs remain supported. Deployment order: database migration, generated Prisma client/backend, frontend.

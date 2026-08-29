# Frontend Integration Guide: Contacts, Catalog & Invoicing

This guide details the updated integration patterns for the [Contacts](file:///home/r/Music/project-task_cashbook-backend/src/modules/contacts/contacts.service.ts#21-24), [Catalog](file:///home/r/Music/project-task_cashbook-backend/src/modules/catalog/catalog.service.ts#14-221), and [Invoicing](file:///home/r/Music/project-task_cashbook-backend/src/modules/invoicing/invoicing.service.ts#32-774) modules. These modules have been tightly integrated to automatically handle inventory lifecycle (stock-outs/returns), financial obligations, and professional PDF/Email generation.

---

## 1. Contacts & Customer Profiles (`/api/v1/workspaces/:workspaceId/contacts`)

The Contacts module tracks people and businesses. A Contact can be upgraded to a **Customer Profile** to track billing/shipping addresses, currencies, and tax IDs (essential for invoicing).

### Endpoints

- **`GET /:workspaceId/contacts`**
  - **Query (optional):** `?type=PERSONAL|CUSTOMER|VENDOR`
  - **Response:** Array of contacts.
- **`POST /:workspaceId/contacts`**
  - **Body:** `{ name: string, email?: string, phone?: string, company?: string, type?: "PERSONAL" | "CUSTOMER" | "VENDOR", notes?: string }`
- **`GET /:workspaceId/contacts/:contactId/profile`**
  - **Response:** Existing [CustomerProfile](file:///home/r/Music/project-task_cashbook-backend/src/modules/contacts/contacts.controller.ts#48-54) object, or `null`.
- **`POST /:workspaceId/contacts/:contactId/profile`**
  - **Description:** Upgrades a contact into a Customer. Automatically changes contact `type` to `CUSTOMER`.
  - **Body:**
    ```json
    {
      "billingAddress": { "line1": "123 Main St", "city": "Kampala", "country": "Uganda" },
      "shippingAddress": {},
      "currency": "UGX",
      "accountNumber": "ACC-001",
      "taxId": "TIN-123456789"
    }
    ```
- **`PATCH /:workspaceId/contacts/:contactId/profile`**
  - **Body:** Same as POST, but all fields optional/nullable.

> **Crucial Security Note:** All Contact and Customer Profile operations now strictly enforce workspace ownership. You cannot pass a `contactId` belonging to another workspace.

---

## 2. Catalog (`/api/v1/workspaces/:workspaceId/catalog`)

The Catalog manages Taxes and Products/Services. It represents your "price list".

### Important Concept: `inventoryItemId` linkage
To achieve automatic stock-outs when selling an item on an invoice, you must link a `PRODUCT` catalog item directly to a physical [InventoryItem](file:///home/r/Music/project-task_cashbook-backend/src/modules/inventory/inventory.dto.ts#137-138).

### Tax Endpoints
- **`GET /taxes`** / **`GET /taxes/:taxId`**
- **`POST /taxes`**
  - **Body:** `{ name: "VAT (18%)", rate: "18.0000", isCompound?: boolean, isRecoverable?: boolean }`
- **`PATCH /taxes/:taxId`**
  - **Body:** `{ name?, rate?, isActive? }`

### Products / Services Endpoints
- **`GET /products`**
  - **Query:** `?page=1&limit=20&type=PRODUCT|SERVICE&search=string&isActive=true|false`
- **`POST /products`** -> Create an item.
  - **Body:**
    ```json
    {
      "name": "Standard Router",
      "description": "5GHz Dual-band router",
      "price": "150000",
      "type": "PRODUCT",
      "isSellable": true,
      "isBuyable": false,
      "taxId": "uuid-optional",
      "inventoryItemId": "uuid-optional" // Required for physical goods if you want auto-stocking!
    }
    ```
- **`PATCH /products/:itemId`**
  - **Body:** Partial updates to the above.

---

## 3. Invoicing (`/api/v1/workspaces/:workspaceId/invoicing`)

The Invoicing engine automatically:
1. Resolves catalog items to inventory items.
2. Performs atomic stock-outs (FIFO/LIFO) when an invoice is sent.
3. Automatically generates an ephemeral PDF inside memory using beautiful templates.
4. Emails the PDF attached to a professional HTML email.

### Settings (`/settings/current`)
Manage how the invoice PDF looks.
- **`GET /settings/current`**
- **`PATCH /settings/current`**
  - **Body:**
    ```json
    {
      "logoUrl": "https://example.com/logo.png", // Falls back to platform logo if null/fails
      "accentColor": "#4F46E5",
      "template": "classic" | "modern" | "contemporary",
      "defaultTerms": "Payment due in 14 days...",
      "defaultNotes": "Thank you for your business!",
      "defaultFooter": "Company Reg: 123456"
    }
    ```

### Invoice CRUD
- **`GET /`**
  - **Query:** `?page=1&limit=20&status=DRAFT|SENT|PAID|OVERDUE&customerId=uuid`
- **`POST /`**
  - **Body:**
    ```json
    {
      "customerId": "uuid",
      "issueDate": "2025-03-26T10:00:00.000Z",
      "dueDate": "2025-04-26T10:00:00.000Z",
      "currency": "UGX",
      "discountAmount": "0.00",
      "notes": "Optional notes",
      "footer": "Optional footer override",
      "cashbookId": "uuid", // Required. The cashbook this invoice's payments will flow into.
      "items": [
        {
          "productServiceId": "uuid", // Pulls price, name, and underlying inventory mapping
          "quantity": "2.00",
          "unitPrice": "150000.00"
          // "inventoryItemId": "uuid" -> You can alternatively provide this DIRECTLY on the line item for ad-hoc free-text items
        }
      ]
    }
    ```

### Invoice Actions (State Changes)
- **`POST /:invoiceId/send`**
  - **Body:** `{ "cashbookId": "uuid" }`
  - **What happens:**
    1. Status becomes `SENT`.
    2. Accounts Receivable Obligation is created in Cashbook.
    3. **Stock-Out happens:** Any line item linked to `inventoryItemId` has its quantity reduced in Inventory automatically.
    4. PDF is generated in memory based on [Settings](file:///home/r/Music/project-task_cashbook-backend/src/modules/invoicing/pdf.generator.ts#50-58).
    5. An email with the PDF attached is sent to the customer.
- **`POST /:invoiceId/void`**
  - **What happens:**
    1. Status becomes `VOID`.
    2. Financial obligation is cancelled completely.
    3. **Stock-In happens:** All previously stocked-out inventory items are returned to inventory exactly as they left (maintaining exact COGS precision).

### Reporting
- **`GET /reports/overdue`** -> Lists all overdue invoices
- **`GET /reports/summary`** -> Overview of invoice totals
- **`GET /reports/customer-outstanding`** -> Outstanding balances grouped by customer

---

## 4. Peer Links (`/api/v1/peer-links` & `/api/v1/cashbooks/:cashbookId/peer-links`)

Peer Links are loan agreements between two **platform users**. The initiator proposes from one of their books; **nothing touches any book until the counterparty accepts and chooses one of their own books**. On acceptance, two mirrored obligations are created atomically — a RECEIVABLE on the lender's book, a PAYABLE on the borrower's — so the platform's audit trail is the shared proof of the loan.

Payments are **cross-confirmed**: recording a payment on either side opens a settlement the other party confirms (optionally by matching an entry they already recorded) or rejects. Neither book is ever written to by the other party's action.

### Propose (from a book you manage)
- **`POST /cashbooks/:cashbookId/peer-links`** (requires `MANAGE_OBLIGATIONS`, send an `Idempotency-Key` header)
  - **Body:**
    ```json
    {
      "direction": "LENDING",            // LENDING = I hold the receivable; BORROWING = I hold the payable
      "counterpartyEmail": "bob@example.com",
      "title": "Loan to Bob",
      "principalAmount": "100000",       // or "totalAmount" when no interest
      "interestRate": "10",              // flat, resolved once; or "interestAmount" — never both
      "dueDate": "2026-09-28T00:00:00.000Z",
      "description": "Optional"
    }
    ```
  - Creates a `PENDING` peer link and notifies the counterparty. Same email-resolution rules as obligations.

### Respond & manage (person-scoped — follows the user, not a workspace)
- **`GET /peer-links`** — your links, either side. **Query:** `?direction=incoming|outgoing&status=PENDING|ACCEPTED|DECLINED|CANCELLED&page=1&limit=20`
  - Response rows are **viewer-relative**: `viewerIsInitiator`, `viewerDirection` (LENDING/BORROWING from your perspective), `counterparty`, `myBook`, `theirBook`, `myObligationId`, `theirObligationId`.
- **`GET /peer-links/:peerLinkId`** — one link with full settlement history.
- **`GET /peer-links/:peerLinkId/acceptable-cashbooks`** — counterparty only: their currency-matched, active books (excludes the initiator's book). Returns `[]` (not an error) once the link is no longer pending — the picker just has nothing to offer.
- **`POST /peer-links/:peerLinkId/accept`** — counterparty only. **Body:** `{ "cashbookId": "uuid" }`
  - Validates: book is theirs to manage, same currency as the link, not the initiator's book. Creates both mirrored obligations (opening journals included), auto-creates a linked contact for the counterparty in each workspace, sets `ACCEPTED`. Idempotency-Key required.
- **`POST /peer-links/:peerLinkId/decline`** — counterparty only. **Body:** `{ "reason": "Optional" }`
- **`POST /peer-links/:peerLinkId/cancel`** — initiator only, PENDING only. Accepted links are settled or written off from the books, not cancelled here.
- **`GET /peer-links/users/lookup?email=`** — exact-match user lookup for the proposal form (no enumeration surface).

### Cross-confirmed settlements
- A payment = an ordinary Entry with `obligationId` on either side's obligation (`POST /entries/cashbook/:cashbookId`). This automatically creates a `PENDING` settlement and notifies the counterparty.
- **`POST /peer-links/settlements/:settlementId/decision`** — the party who did NOT record the payment. Idempotency-Key required. **Body:**
  ```json
  { "decision": "CONFIRM", "matchedEntryId": "uuid-of-your-own-payment-entry" }
  ```
  - `CONFIRM` alone acknowledges the payment. With `matchedEntryId` it also links the two mirrored entries as proof — the entry must pay your side of the same link and match the amount exactly (`AMOUNT_MISMATCH` otherwise).
  - `REJECT` takes a `reason`.
- Reversing the payment entry (entry delete) automatically `CANCEL`s its settlement and restores the outstanding amount.

### Workspace-wide obligations (Obligations page)
- **`GET /workspaces/:workspaceId/obligations`** (workspace member)
  - **Query:** `?status=ACTIVE|OPEN|PARTIAL|PAID|CANCELLED&type=RECEIVABLE|PAYABLE&cashbookId=uuid&search=...&page=1&limit=20`
  - Books are narrowed server-side: org-wide roles (OWNER/ADMIN/GM/ACCOUNTANT) see every book; others see only books they hold a `CashbookMember` row for. Rows include `cashbook`, `contact`, `peerLink` and `interest`.

### Error codes to handle
| Code | Meaning |
|---|---|
| `SELF_PEER_LINK` | Tried to propose to yourself |
| `USER_NOT_FOUND` | No active user with that email |
| `INVALID_STATUS` | Link/settlement already decided — refresh |
| `CURRENCY_MISMATCH` | Chosen book's currency differs from the link's |
| `INVALID_CASHBOOK` | Chosen the initiator's own book |
| `INVALID_MATCH` / `AMOUNT_MISMATCH` | Matched entry isn't on your side of the link / wrong amount |

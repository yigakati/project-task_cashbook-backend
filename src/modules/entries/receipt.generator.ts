import PDFDocument from 'pdfkit';
import https from 'https';
import http from 'http';
import sharp from 'sharp';
import { container } from 'tsyringe';
import { StorageService } from '../files/storage.service';

// ══════════════════════════════════════════════════════════════════════════════
// PAGE & LAYOUT CONSTANTS
// All coordinates extracted from the Wave reference PDF via pdfplumber.
// Page is US Letter (612 × 792 pt) — Wave's native size, not A4.
// ══════════════════════════════════════════════════════════════════════════════

const PAGE_W = 612;
const PAGE_H = 792;

// Horizontal centre of the page — all centred text uses align:'center' + width:PAGE_W
const CX = PAGE_W / 2;   // 306

// Outer card inset (Wave: 12 pt each side)
const CARD_INSET = 12;
const CARD_R     = 10;    // corner radius for card border

// Body text band — Wave centres content between x=156 and x=456
const BODY_L = 156;
const BODY_W = 300;   // 456 − 156

// ── Logo slot (centred, top of card) ─────────────────────────────────────────
// Wave: image x0=238.5 top=65.2 w=135 h=103 → slot starts at y=65
const LOGO_Y = 65;
const LOGO_W = 135;
const LOGO_H = 103;

// ── Footer band (Wave: x0=133.5 top=670.5 x1=478.5 bot=738) ─────────────────
// We keep the same horizontal span but add a 12 pt corner radius to the bottom
// corners, and clamp the band inside the card's bottom border.
const FB_X  = 133.5;
const FB_Y  = 658;      // slightly higher than Wave to accommodate curved radius
const FB_W  = 478.5 - 133.5;   // 345 pt
const FB_H  = 80;               // tall enough for text + radius breathing room
const FB_R  = 12;               // bottom corner radius (top corners are square)
const FB_TX = BODY_L;           // text left edge inside band
const FB_TW = BODY_W;           // text width inside band

// ══════════════════════════════════════════════════════════════════════════════
// COLOUR PALETTE  (extracted from Wave PDF RGB values)
// ══════════════════════════════════════════════════════════════════════════════
const C = {
    white:      '#FFFFFF',
    dark:       '#111827',   // primary body text
    mid:        '#6B7280',   // secondary / muted text
    hairline:   '#D4DAE0',   // separator lines  (Wave: 0.83, 0.87, 0.89 RGB)
    footerBg:   '#EEF1F3',   // footer band fill (Wave: 0.93, 0.94, 0.95 RGB)
    footerLine: '#C8D0D8',   // footer band border
    green:      '#16A34A',   // paid / positive amounts
    badgeGreen: '#22C55E',   // PAID badge stroke (slightly lighter for visibility)
} as const;

// ══════════════════════════════════════════════════════════════════════════════
// FALLBACK LOGO
// Priority:
//   1. Business-uploaded logo from settings.logoUrl  (must be PNG or JPEG)
//   2. https://inchange.odixtec.com/logo.png          (from original codebase)
//   3. null → initials circle rendered inline
//
// SVG URLs are always skipped — pdfkit cannot render SVG.
// ══════════════════════════════════════════════════════════════════════════════
const FALLBACK_LOGO_URL = 'https://inchange.odixtec.com/logo.png';

// ══════════════════════════════════════════════════════════════════════════════
// TYPES
// ══════════════════════════════════════════════════════════════════════════════

export interface PdfReceipt {
    receiptNumber: string;
    paymentDate:   Date | string;
    amountPaid:    any;
    currency:      string;
    paymentMode?:  { name: string } | null;
    reference?:    string | null;
    obligation: {
        title:             string;   // e.g. "Invoice #31"
        totalAmount:       any;
        outstandingAmount: any;
    };
    customer: {
        name:     string;
        email?:   string | null;
        phone?:   string | null;
        company?: string | null;
        customerProfile?: {
            billingAddress?: any;
            taxId?:          string | null;
        } | null;
    };
    /**
     * Seller / issuer details shown in the centred business block.
     * Mirrors the Wave layout: name → address → city → country → phone →
     * mobile → email, each on its own line, centred.
     */
    business?: {
        name:     string;
        address?: string | null;
        city?:    string | null;
        country?: string | null;
        phone?:   string | null;
        mobile?:  string | null;
        email?:   string | null;
    } | null;
    notes?:  string | null;   // short note shown above payment details
    footer?: string | null;   // text displayed inside the footer band
}

export interface PdfSettings {
    /** Object key of the workspace's logo, if it has uploaded one. */
    logoKey?:       string | null;
    accentColor?:   string | null;
    defaultFooter?: string | null;
    // `template` is accepted but ignored — single template only
    template?:      string | null;
}

// ══════════════════════════════════════════════════════════════════════════════
// LOGO RESOLUTION
// ══════════════════════════════════════════════════════════════════════════════

async function resolveLogo(settings: PdfSettings | null): Promise<Buffer | null> {
    const shrink = (buf: Buffer) =>
        // Prevent PDFKit RGB conversion memory spikes: strictly downscale
        // huge images to maximum 250px before embedding into the PDF document.
        sharp(buf).resize({ width: 250, withoutEnlargement: true }).png({ quality: 80 }).toBuffer();

    // The workspace's own logo, read straight out of the object store rather
    // than fetched over HTTP. The logo used to be any URL somebody typed, and
    // fetching that from here aimed this server at whatever host it named.
    const key = settings?.logoKey?.trim();
    if (key) {
        try {
            const buf = await container.resolve(StorageService).getObjectBuffer(key);
            if (isPngOrJpeg(buf)) return await shrink(buf);
        } catch {
            // Unreadable object — fall back to the platform logo.
        }
    }

    try {
        const buf = await fetchUrlBuffer(FALLBACK_LOGO_URL);
        if (isPngOrJpeg(buf)) return await shrink(buf);
    } catch {
        // Network error / timeout / non-2xx — no logo at all.
    }
    return null;   // → initials circle fallback
}

function isPngOrJpeg(buf: Buffer): boolean {
    if (buf.length < 4) return false;
    const isPng  = buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47;
    const isJpeg = buf[0] === 0xff && buf[1] === 0xd8;
    return isPng || isJpeg;
}

// ══════════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Generate a receipt PDF in-memory.
 * A single Wave-style centred layout is always used regardless of
 * settings.template.
 */
export async function generateReceiptPdf(
    receipt:      PdfReceipt,
    businessName: string,
    settings:     PdfSettings | null,
): Promise<Buffer> {
    const accent = settings?.accentColor ?? '#4F46E5';
    const logo   = await resolveLogo(settings);

    return new Promise((resolve, reject) => {
        try {
            const doc = new PDFDocument({
                size       : [PAGE_W, PAGE_H],
                margin     : 0,           // all positioning is manual
                compress   : true,
                bufferPages: true,        // required for footer page-number pass
                info: {
                    Title:   `Receipt ${receipt.receiptNumber}`,
                    Author:  businessName,
                    Creator: 'InChange PDF Engine',
                },
            });

            const chunks: Buffer[] = [];
            doc.on('data',  (c: Buffer) => chunks.push(c));
            doc.on('end',   () => resolve(Buffer.concat(chunks)));
            doc.on('error', reject);

            renderReceipt(doc, receipt, businessName, accent, logo);
            renderFooter(doc, receipt, settings);

            doc.end();
        } catch (err) {
            reject(err);
        }
    });
}

// ══════════════════════════════════════════════════════════════════════════════
// MAIN RENDERER  — Wave-style centred layout
//
// Vertical rhythm (pt from page top):
//   12        card border top
//   65–168    logo slot  (centred, 135 × 103 pt)
//   184       "Payment Receipt"        24 pt bold
//   218       obligation title         14 pt bold      e.g. "Invoice #31"
//   242       "for {customer name}"    12 pt regular
//   260       "paid on {date}"         12 pt regular
//   284       ── thin hairline ──
//   296       customer contact block   10.5 pt (email + phone + address)
//   ~340      ── thin hairline ──
//   ~354      business name            10.5 pt bold
//   ~370+     business details         10.5 pt regular (centred lines)
//   divY      ── heart divider ──
//   divY+22   notes text
//   +         ── hairline ──
//   +         Payment Amount           14 pt mixed-weight
//   +         ── hairline ──
//   +         Payment Method / Ref     10.5 pt
//   +         summary rows (original / remaining)
//   +         PAID badge (if settled)
//   658+      footer band (rounded bottom corners)
// ══════════════════════════════════════════════════════════════════════════════

function renderReceipt(
    doc:          InstanceType<typeof PDFDocument>,
    receipt:      PdfReceipt,
    businessName: string,
    accent:       string,
    logo:         Buffer | null,
): void {

    // ── Outer card border ─────────────────────────────────────────────────────
    // Wave draws a plain rectangle; we keep rx=0 (top) to stay faithful,
    // but the footer band independently carries rounded bottom corners.
    doc
        .rect(
            CARD_INSET,
            CARD_INSET,
            PAGE_W - CARD_INSET * 2,
            PAGE_H - CARD_INSET * 2,
        )
        .lineWidth(0.5)
        .strokeColor(C.hairline)
        .stroke();

    // ── Logo — centred at top ─────────────────────────────────────────────────
    if (logo) {
        try {
            doc.image(logo, CX - LOGO_W / 2, LOGO_Y, {
                fit   : [LOGO_W, LOGO_H],
                align : 'center',
                valign: 'center',
            });
        } catch {
            // pdfkit rejected the buffer — fall through to initials circle
            renderInitialsCircle(doc, businessName, CX, LOGO_Y + LOGO_H / 2, 38, accent);
        }
    } else {
        renderInitialsCircle(doc, businessName, CX, LOGO_Y + LOGO_H / 2, 38, accent);
    }

    // ── "Payment Receipt" — 24 pt bold, centred ───────────────────────────────
    cx(doc, 'Payment Receipt', 24, 'Helvetica-Bold', C.dark, 184);

    // ── Obligation / invoice title — 14 pt bold ───────────────────────────────
    // e.g. "Invoice #31" — taken directly from obligation.title
    cx(doc, receipt.obligation.title, 14, 'Helvetica-Bold', C.dark, 218);

    // ── "for {customer name}" — 12 pt regular ────────────────────────────────
    cx(doc, `for ${receipt.customer.name}`, 12, 'Helvetica', C.mid, 242);

    // ── "paid on {date}" — 12 pt regular ─────────────────────────────────────
    cx(doc, `paid on ${fmtDate(receipt.paymentDate)}`, 12, 'Helvetica', C.mid, 260);

    // ── Thin hairline ─────────────────────────────────────────────────────────
    hairline(doc, 284);

    // ── Customer contact block ────────────────────────────────────────────────
    // Shows email, phone and address so the recipient can verify the payment
    // was applied to the correct account. Centred, 10.5 pt regular.
    let contactY = 298;
    const contactLines = buildContactLines(receipt);
    for (const line of contactLines) {
        cx(doc, line, 10, 'Helvetica', C.mid, contactY);
        contactY += 15;
    }

    // ── Second hairline (after contact block) ─────────────────────────────────
    const afterContact = contactLines.length > 0 ? contactY + 6 : 296;
    hairline(doc, afterContact);

    // ── Business block — seller/issuer details ────────────────────────────────
    // Matches Wave exactly: bold name, then regular detail lines, all centred.
    let bizY = afterContact + 16;
    const biz = receipt.business;

    cx(doc, businessName, 10.5, 'Helvetica-Bold', C.dark, bizY);
    bizY += 17;

    const bizLines: (string | null | undefined)[] = [
        biz?.address,
        biz?.city,
        biz?.country,
        biz?.phone   ? `Phone: ${biz.phone}`   : null,
        biz?.mobile  ? `Mobile: ${biz.mobile}`  : null,
        biz?.email,
    ];
    for (const line of bizLines) {
        if (!line) continue;
        cx(doc, line, 10.5, 'Helvetica', C.mid, bizY);
        bizY += 16;
    }

    // ── Heart divider ─────────────────────────────────────────────────────────
    // Wave: two short hairline segments flanking a small heart glyph.
    const divY = bizY + 14;
    doc
        .moveTo(BODY_L, divY)
        .lineTo(CX - 16, divY)
        .strokeColor(C.hairline).lineWidth(0.5).stroke();
    doc
        .moveTo(CX + 16, divY)
        .lineTo(BODY_L + BODY_W, divY)
        .strokeColor(C.hairline).lineWidth(0.5).stroke();
    doc
        .fontSize(10).fillColor(C.hairline).font('Helvetica')
        .text('♥', CX - 6, divY - 8);

    // ── Notes text ────────────────────────────────────────────────────────────
    let y = divY + 22;
    const notes = receipt.notes;
    if (notes) {
        doc.fontSize(10.5).fillColor(C.dark).font('Helvetica')
            .text(notes, BODY_L, y, { width: BODY_W });
        y += doc.heightOfString(notes, { width: BODY_W }) + 18;
    } else {
        y += 8;
    }

    // ── Hairline ──────────────────────────────────────────────────────────────
    hairline(doc, y);
    y += 14;

    // ── Payment Amount — centred, mixed weight ────────────────────────────────
    // Wave: "Payment Amount: UGX100,000.00 UGX"
    //       label in regular weight, value in bold — measured and positioned
    //       as a single visual line centred on CX.
    const amtLabel = 'Payment Amount: ';
    const amtValue = `${receipt.currency} ${formatDecimal(receipt.amountPaid)}`;
    const lw = doc.fontSize(14).font('Helvetica').widthOfString(amtLabel);
    const vw = doc.fontSize(14).font('Helvetica-Bold').widthOfString(amtValue);
    const ax = CX - (lw + vw) / 2;

    doc.fontSize(14).fillColor(C.dark).font('Helvetica')
        .text(amtLabel, ax, y, { lineBreak: false });
    doc.fontSize(14).fillColor(C.dark).font('Helvetica-Bold')
        .text(amtValue, ax + lw, y, { lineBreak: false });
    y += 30;

    // ── Hairline ──────────────────────────────────────────────────────────────
    hairline(doc, y);
    y += 16;

    // ── Payment Method — centred, mixed weight ────────────────────────────────
    const method     = receipt.paymentMode?.name ?? 'CASH';
    const mLabel     = 'PAYMENT METHOD: ';
    const mlw        = doc.fontSize(10.5).font('Helvetica-Bold').widthOfString(mLabel);
    const mvw        = doc.fontSize(10.5).font('Helvetica').widthOfString(method.toUpperCase());
    const mx         = CX - (mlw + mvw) / 2;

    doc.fontSize(10.5).fillColor(C.dark).font('Helvetica-Bold')
        .text(mLabel, mx, y, { lineBreak: false });
    doc.fontSize(10.5).fillColor(C.dark).font('Helvetica')
        .text(method.toUpperCase(), mx + mlw, y, { lineBreak: false });
    y += 18;

    // ── Reference (optional) ─────────────────────────────────────────────────
    if (receipt.reference) {
        y += 6;
        const rLabel = 'Reference: ';
        const rlw    = doc.fontSize(10).font('Helvetica-Bold').widthOfString(rLabel);
        const rvw    = doc.fontSize(10).font('Helvetica').widthOfString(receipt.reference);
        const rx     = CX - (rlw + rvw) / 2;

        doc.fontSize(10).fillColor(C.mid).font('Helvetica-Bold')
            .text(rLabel, rx, y, { lineBreak: false });
        doc.fontSize(10).fillColor(C.dark).font('Helvetica')
            .text(receipt.reference, rx + rlw, y, { lineBreak: false });
        y += 18;
    }

    // ── Financial summary rows ────────────────────────────────────────────────
    // Original amount and remaining balance displayed as compact centred rows,
    // separated by thin hairlines. Visually equivalent to Wave's summary block.
    const isPaidOff = toNumber(receipt.obligation.outstandingAmount) <= 0;

    if (receipt.obligation.totalAmount !== undefined) {
        y += 10;
        thinHairline(doc, y);
        y += 10;

        summaryRowCentred(
            doc,
            'Original Amount',
            `${receipt.currency} ${formatDecimal(receipt.obligation.totalAmount)}`,
            C.mid, C.dark, y,
        );
        y += 22;

        thinHairline(doc, y);
        y += 10;

        const balColor = isPaidOff ? C.green : C.dark;
        summaryRowCentred(
            doc,
            'Remaining Balance',
            `${receipt.currency} ${formatDecimal(receipt.obligation.outstandingAmount)}`,
            C.mid, balColor, y,
        );
        y += 22;
    }

    // ── PAID badge ────────────────────────────────────────────────────────────
    // Rendered when the obligation is fully settled. Centred, rotated −14°,
    // matching the Wave stamp position between the summary and footer.
    if (isPaidOff) {
        y += 18;
        renderPaidBadge(doc, CX, y + 28);
        y += 72;
    } else {
        y += 18;
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// FOOTER BAND  — bottom of card, rounded bottom corners
//
// Wave footer geometry (from pdfplumber):
//   band x0=133.5  top=670.5  x1=478.5  bot=738
//   top border at y=670.5, bottom border at y=738
//   fill: rgb(0.93, 0.94, 0.95) = #EEF1F3
//
// We replicate this using a custom rounded-bottom path:
//   top-left and top-right corners are square (rx=0)
//   bottom-left and bottom-right corners are rounded (rx=FB_R)
//
// pdfkit's .roundedRect() rounds ALL corners equally — to get rounded-bottom-
// only we draw the path manually using .moveTo / .lineTo / .quadraticCurveTo.
// ══════════════════════════════════════════════════════════════════════════════

function renderFooter(
    doc:      any,
    receipt:  PdfReceipt,
    settings: PdfSettings | null,
): void {
    const range = doc.bufferedPageRange();

    for (let i = 0; i < range.count; i++) {
        doc.switchToPage(range.start + i);

        // ── Top border of footer band ─────────────────────────────────────────
        doc
            .moveTo(FB_X, FB_Y)
            .lineTo(FB_X + FB_W, FB_Y)
            .strokeColor(C.footerLine)
            .lineWidth(0.7)
            .stroke();

        // ── Rounded-bottom rectangle ──────────────────────────────────────────
        // Path: start top-left → top-right → round bottom-right →
        //       bottom-left corner → round bottom-left → back to top-left.
        // Note: pdfkit's quadraticCurveTo(cpX, cpY, x, y) — control point first.
        doc.save();

        doc
            .moveTo(FB_X, FB_Y)                                    // top-left (square)
            .lineTo(FB_X + FB_W, FB_Y)                             // → top-right (square)
            .lineTo(FB_X + FB_W, FB_Y + FB_H - FB_R)              // → before bottom-right curve
            .quadraticCurveTo(
                FB_X + FB_W, FB_Y + FB_H,                         // control point
                FB_X + FB_W - FB_R, FB_Y + FB_H,                  // bottom-right arc end
            )
            .lineTo(FB_X + FB_R, FB_Y + FB_H)                     // → before bottom-left curve
            .quadraticCurveTo(
                FB_X, FB_Y + FB_H,                                 // control point
                FB_X, FB_Y + FB_H - FB_R,                         // bottom-left arc end
            )
            .lineTo(FB_X, FB_Y)                                    // → back to top-left
            .fillColor(C.footerBg)
            .fill();

        doc.restore();

        // ── Bottom border (draws along the curved bottom edge) ────────────────
        // A straight line at the base of the band (pdfkit can't stroke a curved
        // path after fill without re-drawing). We draw a tight line just above
        // where the curves begin so it reads as a clean bottom edge.
        doc
            .moveTo(FB_X + FB_R, FB_Y + FB_H)
            .lineTo(FB_X + FB_W - FB_R, FB_Y + FB_H)
            .strokeColor(C.footerLine)
            .lineWidth(0.7)
            .stroke();

        // ── Footer text ───────────────────────────────────────────────────────
        // Line 1: custom footer message or default — centred in band
        const footerText =
            receipt.footer ??
            settings?.defaultFooter ??
            'Thank you for your payment.';

        doc
            .fontSize(10)
            .fillColor(C.mid)
            .font('Helvetica')
            .text(footerText, FB_TX, FB_Y + 14, { width: FB_TW, align: 'center' });

        // Line 2: "Powered by {app}" branding
        const appName = process.env.APP_NAME ?? 'ODIN Cashbook';
        doc
            .fontSize(8)
            .fillColor('#9CA3AF')
            .font('Helvetica')
            .text(`Powered by ${appName}`, FB_TX, FB_Y + 34, {
                width: FB_TW, align: 'center',
            });

        // Page number — right-aligned inside band
        doc
            .fontSize(7)
            .fillColor('#9CA3AF')
            .text(`Page ${i + 1} of ${range.count}`, FB_TX, FB_Y + 54, {
                width: FB_TW, align: 'right',
            });
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// ELEMENT HELPERS
// ══════════════════════════════════════════════════════════════════════════════

/**
 * PAID IN FULL badge — vector equivalent of Wave's green rubber-stamp image.
 * Drawn as a rotated rounded-rect outline with matching green text.
 * Centred on (cx, cy).
 */
function renderPaidBadge(doc: any, cx: number, cy: number): void {
    doc.save();
    doc.translate(cx, cy).rotate(-14);

    const w = 114, h = 36, r = 6;
    doc
        .roundedRect(-w / 2, -h / 2, w, h, r)
        .lineWidth(2.5)
        .strokeColor(C.badgeGreen)
        .stroke();

    doc
        .fontSize(13)
        .fillColor(C.badgeGreen)
        .font('Helvetica-Bold')
        .text('PAID IN FULL', -w / 2, -8, { align: 'center', width: w });

    doc.restore();
}

/**
 * Initials circle — shown when no logo buffer is available.
 * Draws a filled circle with the first two initials of businessName in white.
 */
function renderInitialsCircle(
    doc:    any,
    name:   string,
    cx:     number,
    cy:     number,
    radius: number,
    accent: string,
): void {
    const initials = name
        .split(/\s+/)
        .map(w => w[0] ?? '')
        .slice(0, 2)
        .join('')
        .toUpperCase();

    doc.circle(cx, cy, radius).fill(accent);
    doc
        .fontSize(radius * 0.75)
        .fillColor(C.white)
        .font('Helvetica-Bold')
        .text(initials, cx - radius, cy - radius * 0.42, {
            width: radius * 2, align: 'center',
        });
}

// ── Centred text helper ───────────────────────────────────────────────────────

function cx(
    doc:   any,
    text:  string,
    size:  number,
    font:  string,
    color: string,
    y:     number,
): void {
    doc.fontSize(size).fillColor(color).font(font)
        .text(text, 0, y, { align: 'center', width: PAGE_W });
}

// ── Hairline helpers ──────────────────────────────────────────────────────────

/** Full-width hairline (Wave-style, body band width). */
function hairline(doc: any, y: number): void {
    doc
        .moveTo(BODY_L, y)
        .lineTo(BODY_L + BODY_W, y)
        .strokeColor(C.hairline)
        .lineWidth(0.5)
        .stroke();
}

/** Thinner divider (0.3 pt) for internal summary section separators. */
function thinHairline(doc: any, y: number): void {
    doc
        .moveTo(BODY_L, y)
        .lineTo(BODY_L + BODY_W, y)
        .strokeColor(C.hairline)
        .lineWidth(0.3)
        .stroke();
}

// ── Summary row ───────────────────────────────────────────────────────────────

/**
 * Centred label: value row.
 * Both segments are measured with widthOfString so the combined string sits
 * exactly at the horizontal centre regardless of value length.
 */
function summaryRowCentred(
    doc:        any,
    label:      string,
    value:      string,
    labelColor: string,
    valueColor: string,
    y:          number,
): void {
    const labelStr = `${label}: `;
    const lw = doc.fontSize(9).font('Helvetica').widthOfString(labelStr);
    const vw = doc.fontSize(9).font('Helvetica-Bold').widthOfString(value);
    const sx = CX - (lw + vw) / 2;

    doc.fontSize(9).fillColor(labelColor).font('Helvetica')
        .text(labelStr, sx, y, { lineBreak: false });
    doc.fontSize(9).fillColor(valueColor).font('Helvetica-Bold')
        .text(value, sx + lw, y, { lineBreak: false });
}

// ══════════════════════════════════════════════════════════════════════════════
// CONTENT BUILDERS
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Build the customer contact lines shown below the "paid on" subtitle.
 * We show email, phone, and billing address — the data the recipient
 * needs to verify their account. Company and Tax ID follow if present.
 */
function buildContactLines(receipt: PdfReceipt): string[] {
    const p = receipt.customer.customerProfile;
    const lines: (string | null | undefined)[] = [
        receipt.customer.company,
        receipt.customer.email,
        receipt.customer.phone,
        p?.billingAddress ? formatAddress(p.billingAddress) : null,
        p?.taxId          ? `Tax ID: ${p.taxId}`           : null,
    ];
    return lines.filter((l): l is string => !!l);
}

// ══════════════════════════════════════════════════════════════════════════════
// UTILITIES
// ══════════════════════════════════════════════════════════════════════════════

function formatDecimal(value: any): string {
    if (value === null || value === undefined) return '0.00';
    const n = typeof value === 'string' ? parseFloat(value) : Number(value);
    return isNaN(n)
        ? '0.00'
        : n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function toNumber(value: any): number {
    const n = Number(value ?? 0);
    return isNaN(n) ? 0 : n;
}

function fmtDate(d: Date | string): string {
    return new Date(d).toLocaleDateString('en-GB', {
        day: '2-digit', month: 'short', year: 'numeric',
    });
}

function formatAddress(addr: Record<string, any> | string): string {
    if (typeof addr === 'string') return addr;
    return [addr.line1, addr.line2, addr.city, addr.state, addr.zip, addr.country]
        .filter(Boolean)
        .join(', ');
}

function fetchUrlBuffer(url: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        const client = url.startsWith('https') ? https : http;
        const req = client.get(url, (res) => {
            if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
                res.resume();   // drain socket before rejecting
                return reject(new Error(`HTTP ${res.statusCode} — ${url}`));
            }
            const chunks: Buffer[] = [];
            res.on('data',  (c: Buffer) => chunks.push(c));
            res.on('end',   () => resolve(Buffer.concat(chunks)));
            res.on('error', reject);
        });
        req.on('error', reject);
        req.setTimeout(8_000, () => {
            req.destroy();
            reject(new Error(`Logo fetch timeout — ${url}`));
        });
    });
}
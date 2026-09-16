import PDFDocument from 'pdfkit';
import { Decimal } from '@prisma/client/runtime/library';
import https from 'https';
import http from 'http';
import sharp from 'sharp';
import { container } from 'tsyringe';
import { StorageService } from '../files/storage.service';

// ─── Constants ─────────────────────────────────────────────────────────────────
/**
 * PNG fallback served by your own Next.js / Express dev server.
 * pdfkit cannot render SVG — only raster images (PNG / JPEG / BMP / GIF).
 * This is tried when no business logo has been uploaded yet.
 * In production, point this to an absolute HTTPS URL.
 */
const FALLBACK_LOGO_URL = 'https://inchange.odixtec.net/logo.png';

const PAGE_WIDTH    = 595.28;              // A4 width  (pt)
const PAGE_HEIGHT   = 841.89;             // A4 height (pt)
const MARGIN        = 48;
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN * 2;   // 499.28 pt

// Safe vertical zone for footer / page-numbers (inside A4 bleed)
const FOOTER_Y   = PAGE_HEIGHT - 46;   // ≈ 795 pt
const PAGE_NUM_Y = PAGE_HEIGHT - 22;   // ≈ 819 pt

// ── Header logo slot ──────────────────────────────────────────────────────────
// The logo always occupies a fixed LEFT slot inside the header band.
// The business name sits to the RIGHT of the logo (or takes the full left zone
// when no logo is present). The right half of every band is reserved for the
// invoice number / badge and must never be touched by the left content.
const LOGO_MAX_W = 110;   // maximum logo width  (pt)
const LOGO_MAX_H =  44;   // maximum logo height (pt)
const LOGO_X     = MARGIN;

// Business-name position changes depending on whether a logo is rendered
const NAME_X_WITH_LOGO    = MARGIN + LOGO_MAX_W + 10;   // 168 pt
const NAME_W_WITH_LOGO    = 150;                          // keeps name clear of right badge zone
const NAME_X_WITHOUT_LOGO = MARGIN;
const NAME_W_WITHOUT_LOGO = 240;

// Invoice badge right-aligns to this edge on every template
const BADGE_RIGHT = PAGE_WIDTH - MARGIN;   // 547.28 pt

// ── Table column X positions ──────────────────────────────────────────────────
// name:48 → qty:272 → price:330 → tax:408 → total:462 → right-edge:547
const COL = {
    name : MARGIN,   // 48  — item name / description
    qty  : 272,      // quantity   (50 pt wide, centre-aligned)
    price: 330,      // unit price
    tax  : 408,      // tax amount
    total: 462,      // line total, right-aligned within 75 pt
} as const;

// Row heights (pt)
const ROW_1LINE = 20;
const ROW_2LINE = 32;
const ROW_PAD   =  2;

// ─── Types ──────────────────────────────────────────────────────────────────────
interface PdfInvoice {
    invoiceNumber: string;
    status: string;
    issueDate: Date | string;
    dueDate: Date | string;
    currency: string;
    subtotal: any;
    discountAmount: any;
    taxAmount: any;
    totalAmount: any;
    amountPaid: any;
    amountDue: any;
    notes?: string | null;
    footer?: string | null;
    customer: {
        name: string;
        email?: string | null;
        phone?: string | null;
        company?: string | null;
        customerProfile?: {
            billingAddress?: any;
            taxId?: string | null;
            currency?: string | null;
        } | null;
    };
    items: Array<{
        name: string;
        description?: string | null;
        quantity: any;
        unitPrice: any;
        taxAmount: any;
        taxRate?: any;
        total: any;
        inventoryItem?: { name: string; sku?: string | null; unit: string } | null;
    }>;
}

interface PdfSettings {
    /** Object key of the workspace's logo, if it has uploaded one. */
    logoKey?: string | null;
    accentColor?: string | null;
    template?: string | null;
    defaultTerms?: string | null;
    defaultFooter?: string | null;
    defaultNotes?: string | null;
}

// ─── Logo resolution ────────────────────────────────────────────────────────────
/**
 * Resolves the logo to render:
 *
 *  1. The workspace's own logo, read straight out of the object store by its
 *     key. Not fetched over HTTP — the URL used to be free text, and fetching
 *     whatever address someone typed let them aim this server at hosts it
 *     should never reach. There is no URL in the decision any more.
 *  2. The platform logo, fetched from the marketing site.
 *  3. null — nothing renderable; the header falls back to a text-only layout.
 *
 * Every candidate is checked for raster magic bytes, so a stored object that
 * turns out to be HTML or an SVG is skipped rather than crashing pdfkit.
 */
async function resolveLogo(settings: PdfSettings | null): Promise<Buffer | null> {
    const shrink = (buf: Buffer) =>
        // Prevent PDFKit RGB conversion memory spikes: strictly downscale
        // huge images to maximum 250px before embedding into the document.
        sharp(buf).resize({ width: 250, withoutEnlargement: true }).png({ quality: 80 }).toBuffer();

    const key = settings?.logoKey?.trim();
    if (key) {
        try {
            const buf = await container.resolve(StorageService).getObjectBuffer(key);
            if (isPngOrJpeg(buf)) return await shrink(buf);
        } catch {
            // Unreadable object — fall through to the platform logo.
        }
    }

    for (const url of [FALLBACK_LOGO_URL]) {
        try {
            const buf = await fetchUrlBuffer(url);
            if (isPngOrJpeg(buf)) {
                // Prevent PDFKit RGB conversion memory spikes: strictly downscale 
                // huge images to maximum 250px before embedding into the PDF document.
                return await sharp(buf)
                    .resize({ width: 250, withoutEnlargement: true })
                    .png({ quality: 80 })
                    .toBuffer();
            }
            // Non-raster response (HTML error page, SVG body, etc.) — skip
        } catch {
            // Network error / timeout / non-2xx — try next candidate
        }
    }

    return null;   // all candidates failed → text-only header
}

/** Quick magic-byte check: returns true for PNG (\x89PNG) or JPEG (\xff\xd8). */
function isPngOrJpeg(buf: Buffer): boolean {
    if (buf.length < 4) return false;
    const isPng  = buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47;
    const isJpeg = buf[0] === 0xff && buf[1] === 0xd8;
    return isPng || isJpeg;
}

// ─── Public API ────────────────────────────────────────────────────────────────
export async function generateInvoicePdf(
    invoice: PdfInvoice,
    settings: PdfSettings | null,
    businessName: string,
): Promise<Buffer> {
    const accentColor = settings?.accentColor || '#4F46E5';
    const template    = settings?.template    || 'classic';

    // Resolve the logo once and share it across all template renderers
    const logoBuffer = await resolveLogo(settings);

    return new Promise((resolve, reject) => {
        try {
            const doc = new PDFDocument({
                margin     : MARGIN,
                size       : 'A4',
                compress   : true,
                bufferPages: true,   // required for renderPageNumbers()
            });
            const chunks: Buffer[] = [];
            doc.on('data',  (c: Buffer) => chunks.push(c));
            doc.on('end',   () => resolve(Buffer.concat(chunks)));
            doc.on('error', reject);

            switch (template) {
                case 'modern':
                    renderModern(doc, invoice, settings, businessName, accentColor, logoBuffer);
                    break;
                case 'contemporary':
                    renderContemporary(doc, invoice, settings, businessName, accentColor, logoBuffer);
                    break;
                default:
                    renderClassic(doc, invoice, settings, businessName, accentColor, logoBuffer);
            }

            renderPageNumbers(doc);
            doc.end();
        } catch (err) {
            reject(err);
        }
    });
}

// ══════════════════════════════════════════════════════════════════════════════
// ─── SHARED: HEADER LEFT ZONE (LOGO + BUSINESS NAME) ─────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Renders the left portion of the invoice header so that:
 *   • Logo AND name are NEVER painted at the same x/y coordinates.
 *   • When a logo is present  → logo left, name to its right (two columns).
 *   • When no logo            → name fills the full left zone (single column).
 *
 * The right zone (invoice number / badge) is the caller's responsibility.
 *
 * @param nameColor  Text colour — white on dark bands, dark on light headers.
 * @param bandTop    Y of the top of the header area (0 on Classic/Modern, 6 on Contemporary).
 * @param bandH      Height of the header zone — used to vertically centre elements.
 * @param fontSize   Business name font size (pt).
 */
function renderHeaderLeft(
    doc: any,
    logo: Buffer | null,
    businessName: string,
    nameColor: string,
    bandTop: number,
    bandH: number,
    fontSize: number,
): void {
    // Vertical centre of the band for alignment calculations
    const midY = bandTop + bandH / 2;

    if (logo) {
        // ── Logo present: image left, name to its right ───────────────────────
        const logoY = midY - LOGO_MAX_H / 2;

        try {
            // fit[] preserves aspect ratio; the image never exceeds the slot.
            doc.image(logo, LOGO_X, logoY, { fit: [LOGO_MAX_W, LOGO_MAX_H] });
        } catch {
            // pdfkit rejected the buffer (corrupted / unsupported sub-format)
            // → degrade gracefully to text-only layout for this render
            _drawName(doc, businessName, nameColor, NAME_X_WITHOUT_LOGO, NAME_W_WITHOUT_LOGO, midY, fontSize);
            return;
        }

        // Business name sits to the RIGHT of the logo slot, vertically centred
        _drawName(doc, businessName, nameColor, NAME_X_WITH_LOGO, NAME_W_WITH_LOGO, midY, fontSize);
    } else {
        // ── No logo: name fills the full left zone ────────────────────────────
        _drawName(doc, businessName, nameColor, NAME_X_WITHOUT_LOGO, NAME_W_WITHOUT_LOGO, midY, fontSize);
    }
}

/** Internal: draw the business name at a vertically centred position. */
function _drawName(
    doc: any,
    name: string,
    color: string,
    x: number,
    width: number,
    midY: number,
    fontSize: number,
): void {
    // Approximate line-height for one line of this font size
    const lineH = fontSize * 1.25;
    const y     = midY - lineH / 2;

    doc
        .fontSize(fontSize)
        .fillColor(color)
        .font('Helvetica-Bold')
        .text(name, x, y, { width, lineBreak: false, ellipsis: true });
}

// ══════════════════════════════════════════════════════════════════════════════
// ─── TEMPLATE: CLASSIC ────────────────────────────────────────────────────────
// Dark header band. Accent table header. Ruled totals.
// ══════════════════════════════════════════════════════════════════════════════

function renderClassic(
    doc: InstanceType<typeof PDFDocument>,
    invoice: PdfInvoice,
    settings: PdfSettings | null,
    businessName: string,
    accent: string,
    logo: Buffer | null,
): void {
    const BAND_H    = 116;
    const lightGrey = '#F8F9FB';
    const midGrey   = '#6B7280';
    const dark      = '#111827';

    // ── Header band ──────────────────────────────────────────────────────────
    doc.rect(0, 0, PAGE_WIDTH, BAND_H).fill(dark);

    // LEFT  → logo + name (non-overlapping via renderHeaderLeft)
    renderHeaderLeft(doc, logo, businessName, '#FFFFFF', 0, BAND_H, 15);

    // RIGHT → "INVOICE" small label / number / status (stacked, right-aligned)
    doc.fontSize(7.5).fillColor(hexAlpha(accent, 0.9)).font('Helvetica-Bold')
        .text('INVOICE', 0, 24, { align: 'right', width: BADGE_RIGHT });
    doc.fontSize(21).fillColor('#FFFFFF').font('Helvetica-Bold')
        .text(invoice.invoiceNumber, 0, 36, { align: 'right', width: BADGE_RIGHT });
    doc.fontSize(7.5).fillColor(statusToColor(invoice.status)).font('Helvetica-Bold')
        .text(invoice.status.toUpperCase(), 0, 68, { align: 'right', width: BADGE_RIGHT });

    // ── Bill-to / Dates row ───────────────────────────────────────────────────
    const rowY     = BAND_H + 22;
    const dateColX = PAGE_WIDTH - MARGIN - 190;

    doc.fontSize(7).fillColor(midGrey).font('Helvetica-Bold')
        .text('BILL TO', MARGIN, rowY);
    doc.fontSize(10.5).fillColor(dark).font('Helvetica-Bold')
        .text(invoice.customer.name, MARGIN, rowY + 13, { width: 220 });

    let billY = rowY + 28;
    const profile = invoice.customer.customerProfile;
    if (invoice.customer.company) {
        doc.fontSize(8.5).fillColor(midGrey).font('Helvetica')
            .text(invoice.customer.company, MARGIN, billY, { width: 220 });
        billY += 13;
    }
    if (invoice.customer.email) {
        doc.fontSize(8.5).fillColor(midGrey)
            .text(invoice.customer.email, MARGIN, billY, { width: 220 });
        billY += 13;
    }
    if (invoice.customer.phone) {
        doc.fontSize(8.5).fillColor(midGrey)
            .text(invoice.customer.phone, MARGIN, billY, { width: 220 });
        billY += 13;
    }
    if (profile?.billingAddress) {
        const addr = formatAddress(profile.billingAddress);
        if (addr) {
            doc.fontSize(8).fillColor(midGrey).text(addr, MARGIN, billY, { width: 220 });
            billY += 22;
        }
    }
    if (profile?.taxId) {
        doc.fontSize(8).fillColor(midGrey).text(`Tax ID: ${profile.taxId}`, MARGIN, billY);
    }

    renderLabelValue(doc, 'Issue Date', fmtDate(invoice.issueDate), dateColX, rowY,      accent);
    renderLabelValue(doc, 'Due Date',   fmtDate(invoice.dueDate),   dateColX, rowY + 26, accent);
    renderLabelValue(doc, 'Currency',   invoice.currency,            dateColX, rowY + 52, accent);

    // ── Separator → table ─────────────────────────────────────────────────────
    const tableTop = rowY + 112;
    doc.moveTo(MARGIN, tableTop - 8).lineTo(PAGE_WIDTH - MARGIN, tableTop - 8)
        .strokeColor('#E5E7EB').lineWidth(0.5).stroke();

    renderClassicTableHeader(doc, tableTop, accent);
    let y = renderItemRows(doc, invoice.items, tableTop + 24, lightGrey, dark, midGrey, accent);

    y += 18;
    y = renderTotals(doc, invoice, y, accent, dark, midGrey);
    renderNotesTermsFooter(doc, invoice, settings, y + 24, midGrey, dark);
}

// ══════════════════════════════════════════════════════════════════════════════
// ─── TEMPLATE: MODERN ─────────────────────────────────────────────────────────
// Full-width accent band. Meta-pill sidebar. Bold typographic hierarchy.
// ══════════════════════════════════════════════════════════════════════════════

function renderModern(
    doc: InstanceType<typeof PDFDocument>,
    invoice: PdfInvoice,
    settings: PdfSettings | null,
    businessName: string,
    accent: string,
    logo: Buffer | null,
): void {
    const BAND_H    = 140;
    const dark      = '#0F172A';
    const midGrey   = '#64748B';
    const lightGrey = '#F1F5F9';

    // ── Full-width accent band ────────────────────────────────────────────────
    doc.rect(0, 0, PAGE_WIDTH, BAND_H).fill(accent);

    // LEFT → logo + name
    renderHeaderLeft(doc, logo, businessName, '#FFFFFF', 0, BAND_H, 17);

    // RIGHT → ghost watermark + number
    doc.fontSize(26).fillColor('rgba(255,255,255,0.15)').font('Helvetica-Bold')
        .text('INVOICE', 0, 58, { align: 'right', width: BADGE_RIGHT });
    doc.fontSize(13).fillColor('#FFFFFF').font('Helvetica-Bold')
        .text(invoice.invoiceNumber, 0, 90, { align: 'right', width: BADGE_RIGHT });

    // ── Billing block ─────────────────────────────────────────────────────────
    const rowY  = BAND_H + 22;
    const metaX = PAGE_WIDTH - MARGIN - 200;

    doc.fontSize(7).fillColor(accent).font('Helvetica-Bold')
        .text('BILLED TO', MARGIN, rowY);
    doc.fontSize(11).fillColor(dark).font('Helvetica-Bold')
        .text(invoice.customer.name, MARGIN, rowY + 13, { width: 220 });

    let billY = rowY + 28;
    const profile = invoice.customer.customerProfile;
    if (invoice.customer.company) {
        doc.fontSize(8.5).fillColor(midGrey).font('Helvetica')
            .text(invoice.customer.company, MARGIN, billY, { width: 220 });
        billY += 13;
    }
    if (invoice.customer.email) {
        doc.fontSize(8.5).fillColor(midGrey)
            .text(invoice.customer.email, MARGIN, billY, { width: 220 });
        billY += 13;
    }
    if (invoice.customer.phone) {
        doc.fontSize(8.5).fillColor(midGrey)
            .text(invoice.customer.phone, MARGIN, billY, { width: 220 });
        billY += 13;
    }
    if (profile?.billingAddress) {
        const addr = formatAddress(profile.billingAddress);
        if (addr) {
            doc.fontSize(8).fillColor(midGrey).text(addr, MARGIN, billY, { width: 220 });
        }
    }

    // Meta pills — each 32 pt tall, 6 pt gap
    const PILL_H   = 32;
    const PILL_GAP =  6;
    renderMetaPill(doc, 'ISSUE DATE', fmtDate(invoice.issueDate), metaX, rowY,                            accent, dark);
    renderMetaPill(doc, 'DUE DATE',   fmtDate(invoice.dueDate),   metaX, rowY + (PILL_H + PILL_GAP),      accent, dark);
    renderMetaPill(doc, 'CURRENCY',   invoice.currency,            metaX, rowY + (PILL_H + PILL_GAP) * 2,  accent, dark);
    renderMetaPill(doc, 'STATUS',     invoice.status,              metaX, rowY + (PILL_H + PILL_GAP) * 3,
        statusToColor(invoice.status), dark);

    // ── Items table ───────────────────────────────────────────────────────────
    // 4 pills × (32+6) = 152 pt + 20 pt breathing room
    const tableTop = rowY + 172;

    doc.rect(MARGIN, tableTop, CONTENT_WIDTH, 22).fill(dark);
    doc.fontSize(7.5).fillColor('#FFFFFF').font('Helvetica-Bold');
    doc.text('ITEM',       COL.name  + 4, tableTop + 11, { baseline: 'middle' });
    doc.text('QTY',        COL.qty,        tableTop + 11, { align: 'center', width: 50, baseline: 'middle' });
    doc.text('UNIT PRICE', COL.price,      tableTop + 11, { baseline: 'middle' });
    doc.text('TAX',        COL.tax,        tableTop + 11, { baseline: 'middle' });
    doc.text('TOTAL',      COL.total,      tableTop + 11, { align: 'right', width: 75, baseline: 'middle' });

    let y = renderItemRows(doc, invoice.items, tableTop + 26, lightGrey, dark, midGrey, accent);

    y += 18;
    y = renderTotals(doc, invoice, y, accent, dark, midGrey);
    renderNotesTermsFooter(doc, invoice, settings, y + 24, midGrey, dark);
}

// ══════════════════════════════════════════════════════════════════════════════
// ─── TEMPLATE: CONTEMPORARY ──────────────────────────────────────────────────
// Minimal. 6 pt accent bar. Whitespace-heavy. Understated typography.
// ══════════════════════════════════════════════════════════════════════════════

function renderContemporary(
    doc: InstanceType<typeof PDFDocument>,
    invoice: PdfInvoice,
    settings: PdfSettings | null,
    businessName: string,
    accent: string,
    logo: Buffer | null,
): void {
    const ACCENT_H = 6;    // 6 pt minimum for reliable PDF viewer rendering
    const HEADER_H = 62;   // header zone below the accent bar
    const dark      = '#1C1C1E';
    const midGrey   = '#8E8E93';
    const lightLine = '#E5E5EA';

    // ── Thin accent bar ───────────────────────────────────────────────────────
    doc.rect(0, 0, PAGE_WIDTH, ACCENT_H).fill(accent);

    // LEFT → logo + name on white background (name colour is dark, not white)
    renderHeaderLeft(doc, logo, businessName, dark, ACCENT_H, HEADER_H, 14);

    // RIGHT → minimalist invoice label + number
    const bandMidY = ACCENT_H + HEADER_H / 2;
    doc.fontSize(8).fillColor(midGrey).font('Helvetica')
        .text('Invoice', 0, bandMidY - 16, { align: 'right', width: BADGE_RIGHT });
    doc.fontSize(13).fillColor(dark).font('Helvetica-Bold')
        .text(invoice.invoiceNumber, 0, bandMidY - 4, { align: 'right', width: BADGE_RIGHT });

    // Thin separator
    const sepY = ACCENT_H + HEADER_H + 4;
    doc.moveTo(MARGIN, sepY).lineTo(PAGE_WIDTH - MARGIN, sepY)
        .lineWidth(0.5).strokeColor(lightLine).stroke();

    // ── Billing block ─────────────────────────────────────────────────────────
    const rowY = sepY + 14;

    doc.fontSize(7.5).fillColor(midGrey).font('Helvetica-Bold')
        .text('BILL TO', MARGIN, rowY);
    doc.fontSize(10.5).fillColor(dark).font('Helvetica-Bold')
        .text(invoice.customer.name, MARGIN, rowY + 13, { width: 220 });

    let billY = rowY + 28;
    const profile = invoice.customer.customerProfile;
    if (invoice.customer.company) {
        doc.fontSize(8.5).fillColor(midGrey).font('Helvetica')
            .text(invoice.customer.company, MARGIN, billY, { width: 220 });
        billY += 13;
    }
    if (invoice.customer.email) {
        doc.fontSize(8.5).fillColor(midGrey)
            .text(invoice.customer.email, MARGIN, billY, { width: 220 });
        billY += 13;
    }
    if (invoice.customer.phone) {
        doc.fontSize(8.5).fillColor(midGrey)
            .text(invoice.customer.phone, MARGIN, billY, { width: 220 });
        billY += 13;
    }
    if (profile?.billingAddress) {
        const addr = formatAddress(profile.billingAddress);
        if (addr) {
            doc.fontSize(8).fillColor(midGrey).text(addr, MARGIN, billY, { width: 220 });
        }
    }

    // Right date fields — status colour applied to label only; value stays dark
    const dX = PAGE_WIDTH - MARGIN - 185;
    renderContemporaryField(doc, 'Issued',   fmtDate(invoice.issueDate), dX, rowY,      midGrey, dark);
    renderContemporaryField(doc, 'Due',      fmtDate(invoice.dueDate),   dX, rowY + 28, midGrey, dark);
    renderContemporaryField(doc, 'Currency', invoice.currency,            dX, rowY + 56, midGrey, dark);
    renderContemporaryField(doc, 'Status',   invoice.status,              dX, rowY + 84,
        statusToColor(invoice.status), dark);

    // ── Items table ───────────────────────────────────────────────────────────
    const tableTop = rowY + 118;

    doc.moveTo(MARGIN, tableTop).lineTo(PAGE_WIDTH - MARGIN, tableTop)
        .lineWidth(0.5).strokeColor(lightLine).stroke();

    doc.fontSize(7.5).fillColor(midGrey).font('Helvetica-Bold');
    doc.text('DESCRIPTION', COL.name  + 2, tableTop + 7);
    doc.text('QTY',         COL.qty,        tableTop + 7, { width: 50, align: 'center' });
    doc.text('PRICE',       COL.price,      tableTop + 7);
    doc.text('TAX',         COL.tax,        tableTop + 7);
    doc.text('TOTAL',       COL.total,      tableTop + 7, { align: 'right', width: 75 });

    doc.moveTo(MARGIN, tableTop + 20).lineTo(PAGE_WIDTH - MARGIN, tableTop + 20)
        .lineWidth(0.5).strokeColor(lightLine).stroke();

    let y = renderItemRows(
        doc, invoice.items, tableTop + 22,
        null,   // no alternating fills; thin dividers separate rows
        dark, midGrey, accent,
        { dividerColor: lightLine, dividerWidth: 0.3 },
    );

    y += 18;
    y = renderTotals(doc, invoice, y, accent, dark, midGrey);
    renderNotesTermsFooter(doc, invoice, settings, y + 24, midGrey, dark);
}

// ══════════════════════════════════════════════════════════════════════════════
// ─── SHARED RENDERING HELPERS ─────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

/** Classic: accent-filled table header, white bold column labels at vertical midpoint. */
function renderClassicTableHeader(doc: any, y: number, accent: string): void {
    const H = 22;
    doc.rect(MARGIN, y, CONTENT_WIDTH, H).fill(accent);
    doc.fontSize(7.5).fillColor('#FFFFFF').font('Helvetica-Bold');
    doc.text('ITEM / DESCRIPTION', COL.name  + 4, y + H / 2, { baseline: 'middle' });
    doc.text('QTY',                COL.qty,        y + H / 2, { width: 50, align: 'center', baseline: 'middle' });
    doc.text('UNIT PRICE',         COL.price,      y + H / 2, { baseline: 'middle' });
    doc.text('TAX',                COL.tax,        y + H / 2, { baseline: 'middle' });
    doc.text('TOTAL',              COL.total,      y + H / 2, { align: 'right', width: 75, baseline: 'middle' });
}

/**
 * Render all invoice line items.
 * @param altFill  Even/odd alternating background (null = no fills — Contemporary).
 * @param divider  Thin horizontal rule below each row (Contemporary).
 */
function renderItemRows(
    doc: any,
    items: PdfInvoice['items'],
    startY: number,
    altFill: string | null,
    dark: string,
    grey: string,
    accent: string,
    divider?: { dividerColor: string; dividerWidth: number },
): number {
    let y = startY;

    for (let i = 0; i < items.length; i++) {
        const item   = items[i];
        const hasSub = !!(item.description || item.inventoryItem);
        const rowH   = hasSub ? ROW_2LINE : ROW_1LINE;
        const bg     = altFill ? (i % 2 === 0 ? altFill : '#FFFFFF') : null;

        if (bg) doc.rect(MARGIN, y - 2, CONTENT_WIDTH, rowH + ROW_PAD).fill(bg);

        const textY = hasSub ? y + 3 : y + Math.floor((rowH - 9) / 2);

        doc.fontSize(8.5).fillColor(dark).font('Helvetica-Bold')
            .text(truncate(item.name, 34), COL.name + 4, textY);

        if (item.description) {
            doc.fontSize(7.5).fillColor(grey).font('Helvetica')
                .text(truncate(item.description, 50), COL.name + 4, textY + 12);
        }
        if (item.inventoryItem) {
            const sub = `SKU: ${item.inventoryItem.sku || '—'} · Unit: ${item.inventoryItem.unit}`;
            doc.fontSize(7).fillColor(accent)
                .text(sub, COL.name + 4, textY + (item.description ? 22 : 12));
        }

        doc.fontSize(8.5).fillColor(dark).font('Helvetica')
            .text(String(item.quantity),         COL.qty,   textY, { width: 50, align: 'center' })
            .text(formatDecimal(item.unitPrice),  COL.price, textY)
            .text(formatDecimal(item.taxAmount),  COL.tax,   textY)
            .text(formatDecimal(item.total),      COL.total, textY, { align: 'right', width: 75 });

        if (divider) {
            doc.moveTo(MARGIN, y + rowH + ROW_PAD)
                .lineTo(PAGE_WIDTH - MARGIN, y + rowH + ROW_PAD)
                .lineWidth(divider.dividerWidth).strokeColor(divider.dividerColor).stroke();
        }

        y += rowH + ROW_PAD;

        // Preserve 160 pt for the totals block before triggering a page break
        if (y > PAGE_HEIGHT - 160) {
            doc.addPage();
            y = MARGIN;
        }
    }

    return y;
}

/**
 * Totals block: subtotal → discount → tax → highlighted TOTAL → paid → due.
 * Anchored to the right margin; startX default 340 pt.
 */
function renderTotals(
    doc: any,
    invoice: PdfInvoice,
    y: number,
    accent: string,
    dark: string,
    grey: string,
    startX = 340,
): number {
    const W = PAGE_WIDTH - MARGIN - startX;   // 207.28 pt

    doc.fontSize(9).font('Helvetica');
    _totalRow(doc, 'Subtotal', formatDecimal(invoice.subtotal), startX, y, grey, dark, W);
    y += 19;

    if (new Decimal(invoice.discountAmount || 0).greaterThan(0)) {
        _totalRow(doc, 'Discount', `− ${formatDecimal(invoice.discountAmount)}`, startX, y, grey, '#DC2626', W);
        y += 19;
    }
    if (new Decimal(invoice.taxAmount || 0).greaterThan(0)) {
        _totalRow(doc, 'Tax', formatDecimal(invoice.taxAmount), startX, y, grey, dark, W);
        y += 19;
    }

    // TOTAL highlight box
    const BOX_H = 26;
    doc.rect(startX, y, W, BOX_H).fill(accent);
    doc.fontSize(10.5).fillColor('#FFFFFF').font('Helvetica-Bold')
        .text('TOTAL', startX + 8, y + BOX_H / 2, { baseline: 'middle' });
    doc.text(
        `${invoice.currency} ${formatDecimal(invoice.totalAmount)}`,
        startX, y + BOX_H / 2,
        { align: 'right', width: W - 8, baseline: 'middle' },
    );
    y += BOX_H + 10;

    if (new Decimal(invoice.amountPaid || 0).greaterThan(0)) {
        _totalRow(doc, 'Amount Paid', formatDecimal(invoice.amountPaid), startX, y, grey, '#16A34A', W);
        y += 19;
        _totalRow(doc, 'Amount Due',
            `${invoice.currency} ${formatDecimal(invoice.amountDue)}`,
            startX, y, accent, accent, W);
        y += 22;
    }

    return y;
}

function _totalRow(
    doc: any,
    label: string, value: string,
    x: number, y: number,
    labelColor: string, valueColor: string,
    width: number,
): void {
    doc.fontSize(9).fillColor(labelColor).font('Helvetica').text(`${label}:`, x + 8, y);
    doc.fontSize(9).fillColor(valueColor).font('Helvetica-Bold')
        .text(value, x, y, { align: 'right', width: width - 8 });
}

/** Notes, terms, and footer pinned to FOOTER_Y. */
function renderNotesTermsFooter(
    doc: any,
    invoice: PdfInvoice,
    settings: PdfSettings | null,
    y: number,
    grey: string,
    dark: string,
): number {
    const notes = invoice.notes || settings?.defaultNotes;
    if (notes) {
        doc.fontSize(8).fillColor(grey).font('Helvetica-Bold').text('Notes', MARGIN, y);
        doc.fontSize(8).fillColor(dark).font('Helvetica')
            .text(notes, MARGIN, y + 13, { width: CONTENT_WIDTH });
        y += 14 + Math.ceil(notes.length / 90) * 10 + 12;
    }

    const terms = settings?.defaultTerms;
    if (terms) {
        doc.fontSize(8).fillColor(grey).font('Helvetica-Bold').text('Terms & Conditions', MARGIN, y);
        doc.fontSize(8).fillColor(dark).font('Helvetica')
            .text(terms, MARGIN, y + 13, { width: CONTENT_WIDTH });
        y += 14 + Math.ceil(terms.length / 90) * 10 + 12;
    }

    const footer = invoice.footer || settings?.defaultFooter;
    if (footer) {
        doc.fontSize(7.5).fillColor(grey).font('Helvetica')
            .text(footer, MARGIN, FOOTER_Y, { width: CONTENT_WIDTH, align: 'center' });
    }

    return y;
}

/** Stamp "Page N of M" on every buffered page — call after all content is written. */
function renderPageNumbers(doc: any): void {
    const range = doc.bufferedPageRange();
    for (let i = 0; i < range.count; i++) {
        doc.switchToPage(range.start + i);
        doc.fontSize(7).fillColor('#9CA3AF')
            .text(`Page ${i + 1} of ${range.count}`, MARGIN, PAGE_NUM_Y, {
                align: 'right', width: CONTENT_WIDTH,
            });
    }
}

// ── Per-template field helpers ────────────────────────────────────────────────

/** Classic: small accent label / larger dark value (stacked, left-aligned). */
function renderLabelValue(
    doc: any,
    label: string, value: string,
    x: number, y: number,
    accent: string,
): void {
    doc.fontSize(7.5).fillColor(accent).font('Helvetica-Bold').text(label, x, y);
    doc.fontSize(9.5).fillColor('#111827').font('Helvetica').text(value, x, y + 12);
}

/** Modern: 200 × 32 pt pill card with 4 pt left accent strip. */
function renderMetaPill(
    doc: any,
    label: string, value: string,
    x: number, y: number,
    accent: string, dark: string,
): void {
    const W = 200; const H = 32;
    doc.rect(x, y, W, H).fill('#F8FAFC');
    doc.rect(x, y, 4, H).fill(accent);
    doc.fontSize(7).fillColor(accent).font('Helvetica-Bold').text(label, x + 12, y + 7);
    doc.fontSize(9.5).fillColor(dark).font('Helvetica-Bold').text(value, x + 12, y + 18);
}

/** Contemporary: muted label / bold dark value. Status colour → label only. */
function renderContemporaryField(
    doc: any,
    label: string, value: string,
    x: number, y: number,
    labelColor: string, dark: string,
): void {
    doc.fontSize(7.5).fillColor(labelColor).font('Helvetica').text(label, x, y);
    doc.fontSize(10).fillColor(dark).font('Helvetica-Bold').text(value, x, y + 11);
}

// ══════════════════════════════════════════════════════════════════════════════
// ─── UTILITIES ────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

function formatDecimal(value: any): string {
    if (value === null || value === undefined) return '0.00';
    const n = typeof value === 'string' ? parseFloat(value) : Number(value);
    return isNaN(n)
        ? '0.00'
        : n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function fmtDate(d: Date | string): string {
    return new Date(d).toLocaleDateString('en-GB', {
        day: '2-digit', month: 'short', year: 'numeric',
    });
}

function truncate(str: string, max: number): string {
    return str.length > max ? `${str.substring(0, max)}…` : str;
}

function formatAddress(addr: Record<string, any>): string {
    if (typeof addr === 'string') return addr;
    return [addr.line1, addr.line2, addr.city, addr.state, addr.zip, addr.country]
        .filter(Boolean).join(', ');
}

function statusToColor(status: string): string {
    switch (status?.toUpperCase()) {
        case 'PAID':           return '#16A34A';
        case 'PARTIALLY_PAID': return '#D97706';
        case 'OVERDUE':        return '#DC2626';
        case 'VOID':           return '#6B7280';
        case 'SENT':           return '#2563EB';
        default:               return '#9CA3AF';
    }
}

/** Build an rgba() colour string from a #rrggbb hex and 0–1 alpha. */
function hexAlpha(hex: string, alpha: number): string {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `rgba(${r},${g},${b},${alpha})`;
}

/**
 * Fetch a URL and return its raw bytes.
 * Supports both http and https. Rejects on non-2xx status, network error,
 * or an 8-second timeout.
 */
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
            reject(new Error(`Timeout fetching logo — ${url}`));
        });
    });
}
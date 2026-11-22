import { join } from 'node:path';
import PDFDocument from 'pdfkit';
import { container } from 'tsyringe';
import { InvoiceSettings, WorkspaceProfile } from '@prisma/client';
import { StorageService } from '../files/storage.service';
import { receiptPlatformLogo } from '../entries/receipt-platform-logo';
import sharp from 'sharp';
import { invoiceThemePath } from './invoice-theme-assets';
import { invoiceTheme } from './invoice-templates';
import { buildInvoiceDocument, InvoiceDocument } from './invoice-document';

/** Choose a legible foreground even when a business uses a very light accent. */
export function invoiceInk(hex: string): string {
    const rgb = hex
        .slice(1)
        .match(/../g)!
        .map((value) => {
            const channel = parseInt(value, 16) / 255;
            return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
        });
    return rgb[0] * 0.2126 + rgb[1] * 0.7152 + rgb[2] * 0.0722 > 0.179 ? '#0F172A' : '#FFFFFF';
}

export async function renderInvoicePdf(
    invoice: InvoiceDocument,
    logoKey?: string | null,
    artworkKey?: string | null,
): Promise<Buffer> {
    let logo: Buffer = receiptPlatformLogo;
    if (logoKey) {
        try {
            logo = await sharp(await container.resolve(StorageService).getObjectBuffer(logoKey), {
                limitInputPixels: 20_000_000,
            })
                .png()
                .toBuffer();
        } catch {
            /* A missing business logo falls back to the bundled brand. */
        }
    }
    let artwork: Buffer | null = null;
    if (artworkKey) {
        try {
            artwork = await sharp(
                await container.resolve(StorageService).getObjectBuffer(artworkKey),
                { limitInputPixels: 20_000_000 },
            )
                .png()
                .toBuffer();
        } catch {
            /* Decorative images never prevent issuing a financial document. */
        }
    }
    return new Promise((resolve, reject) => {
        const { template, customization, accentColor: accent } = invoice.appearance;
        const theme = invoiceTheme(template, customization);
        const compactLayout = Boolean(
            theme || artwork || ('layout' in template && template.layout === 'compact'),
        );
        const darkTheme =
            theme && ['wave', 'workshop', 'panel', 'ribbon', 'estate'].includes(theme);
        const drawDecoration = (firstPage: boolean) => {
            if (theme) {
                doc.save();
                try {
                    doc.opacity(firstPage ? 1 : 0.1).image(invoiceThemePath(theme), 0, 0, {
                        width: doc.page.width,
                        height: doc.page.height,
                    });
                } catch {
                    /* Template text and totals remain available if an asset is unavailable. */
                } finally {
                    doc.restore();
                }
            }
            if (theme === 'panel' && firstPage)
                doc.roundedRect(28, 123, doc.page.width - 56, doc.page.height - 185, 18).fill(
                    '#FFFFFF',
                );
            if (artwork) {
                doc.save();
                if (customization.artworkPlacement === 'header' && firstPage) {
                    doc.rect(0, 0, doc.page.width, 123).clip();
                    doc.image(artwork, 0, 0, { cover: [doc.page.width, 123] });
                    doc.rect(0, 0, doc.page.width, 123).fillOpacity(0.7).fill('#0F172A');
                } else if (customization.artworkPlacement === 'background') {
                    doc.rect(0, 0, doc.page.width, doc.page.height).clip();
                    doc.opacity(customization.artworkOpacity).image(artwork, 0, 0, {
                        cover: [doc.page.width, doc.page.height],
                    });
                } else if (customization.artworkPlacement === 'watermark') {
                    doc.opacity(customization.artworkOpacity).image(
                        artwork,
                        50,
                        doc.page.height - 265,
                        { fit: [220, 140] },
                    );
                }
                doc.restore();
            }
            if (theme === 'watermark') {
                doc.save()
                    .opacity(0.075)
                    .image(logo, 48, doc.page.height - 295, { fit: [210, 155] })
                    .restore();
            }
        };
        const doc = new PDFDocument({
            size: customization.paperSize,
            margins: { top: 44, bottom: 54, left: 44, right: 44 },
            bufferPages: true,
            info: { Title: `Invoice ${invoice.invoiceNumber}`, Author: invoice.business.name },
        });
        const chunks: Buffer[] = [];
        doc.on('data', (chunk: Buffer) => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', reject);
        try {
            doc.registerFont(
                'Regular',
                join(__dirname, '../entries/assets/LiberationSans-Regular.ttf'),
            );
            doc.registerFont('Bold', join(__dirname, '../entries/assets/LiberationSans-Bold.ttf'));
            const serif =
                (customization.font === 'template' ? template.font : customization.font) ===
                'serif';
            const width = doc.page.width - 88;
            const right = 44 + width;
            const bottom = () => doc.page.height - 64;
            const tableStyle =
                customization.tableStyle === 'template' ? template.table : customization.tableStyle;
            const padding = customization.density === 'compact' ? 6 : 10;
            let y = 44;
            let tableActive = false;
            const font = (bold = false, size = 10) =>
                doc
                    .font(bold ? 'Bold' : 'Regular')
                    .fontSize(size)
                    .fillColor('#1E293B');
            const headingFont = (size: number) =>
                doc.font(serif ? 'Times-Bold' : 'Bold').fontSize(size);
            const rule = (at: number, color = '#CBD5E1', weight = 0.6) =>
                doc.moveTo(44, at).lineTo(right, at).lineWidth(weight).strokeColor(color).stroke();
            const columns = [0, width * 0.43, width * 0.52, width * 0.69, width * 0.82, width];
            const drawTableHeader = () => {
                const filled =
                    compactLayout ||
                    tableStyle === 'striped' ||
                    template.header === 'banner' ||
                    template.header === 'dark';
                if (filled)
                    doc.rect(44, y, width, 26).fill(
                        !compactLayout && template.header === 'dark' ? '#172033' : accent,
                    );
                ['Description', 'Qty', 'Rate', 'Tax', 'Amount'].forEach((label, i) => {
                    font(true, 9)
                        .fillColor(
                            filled
                                ? invoiceInk(
                                      !compactLayout && template.header === 'dark'
                                          ? '#172033'
                                          : accent,
                                  )
                                : '#1E293B',
                        )
                        .text(label, 44 + columns[i] + 5, y + 8, {
                            width: columns[i + 1] - columns[i] - 10,
                            align: i ? 'right' : 'left',
                            lineBreak: false,
                        });
                });
                y += 26;
                if (!filled) rule(y, accent);
            };
            const nextPage = () => {
                doc.addPage();
                drawDecoration(false);
                y = 44;
                font(true, 9).text(`INVOICE ${invoice.invoiceNumber} • continued`, 44, y, {
                    width,
                });
                y += 24;
                if (tableActive) drawTableHeader();
            };
            const ensure = (height: number) => {
                if (y + height > bottom()) nextPage();
            };
            // Wrap at measured glyph widths, including unbroken identifiers and explicit newlines.
            const lines = (value: string, available: number): string[] => {
                const output: string[] = [];
                for (const paragraph of value.split('\n')) {
                    let line = '';
                    for (const word of paragraph.split(/\s+/)) {
                        if (!word) continue;
                        if (doc.widthOfString(line ? `${line} ${word}` : word) <= available) {
                            line = line ? `${line} ${word}` : word;
                            continue;
                        }
                        if (line) output.push(line);
                        line = '';
                        for (const character of word) {
                            if (line && doc.widthOfString(line + character) > available) {
                                output.push(line);
                                line = '';
                            }
                            line += character;
                        }
                    }
                    output.push(line);
                }
                return output;
            };
            const block = (
                value: string,
                size = 10,
                bold = false,
                align: 'left' | 'center' = 'left',
            ) => {
                font(bold, size);
                for (const line of lines(value, width)) {
                    ensure(size + 5);
                    font(bold, size).text(line, 44, y, { width, align, lineBreak: false });
                    y += size + 5;
                }
            };
            drawDecoration(true);
            if (compactLayout) {
                const headerInk =
                    darkTheme || (artwork && customization.artworkPlacement === 'header')
                        ? '#FFFFFF'
                        : '#172033';
                const leftLogo = customization.logoPlacement !== 'right';
                const logoX = leftLogo ? 44 : right - 95;
                doc.roundedRect(logoX - 4, 39, 96, 60, 3).fill('#FFFFFF');
                try {
                    doc.image(logo, logoX, 44, { fit: [88, 48] });
                } catch {
                    doc.image(receiptPlatformLogo, logoX, 44, { fit: [88, 48] });
                }
                const businessX = leftLogo ? 150 : 230;
                const businessWidth = leftLogo
                    ? right - 185 - businessX - 12
                    : right - 100 - businessX - 12;
                const headingX = leftLogo ? right - 185 : 44;
                headingFont(28).fillColor(headerInk).text('INVOICE', headingX, 46, {
                    width: 185,
                    align: 'right',
                    lineBreak: false,
                });
                font(true, 8)
                    .fillColor(headerInk)
                    .text('FROM', businessX, 43, { width: businessWidth });
                let by = 57;
                let identityContinued = false;
                for (const [value, bold] of [
                    [invoice.business.name, true],
                    ...invoice.business.lines.map((line) => [line, false]),
                ] as [string, boolean][]) {
                    font(bold, bold ? 10 : 8);
                    for (const line of lines(value, businessWidth)) {
                        if (by > bottom() - 48) {
                            y = by;
                            nextPage();
                            identityContinued = true;
                            by = y;
                        }
                        font(bold, bold ? 10 : 8)
                            .fillColor(!identityContinued && by < 123 ? headerInk : '#1E293B')
                            .text(line, businessX, by, { width: businessWidth, lineBreak: false });
                        by += bold ? 15 : 12;
                    }
                }
                y = Math.max(identityContinued ? y : 143, by + 24);
                ensure(110);
                const customerWidth = width * 0.52;
                font(true, 8).text('BILL TO', 44, y, { width: customerWidth });
                const referenceX = 44 + width * 0.6;
                let referenceY = y;
                for (const [label, value] of [
                    ['Invoice #', invoice.invoiceNumber],
                    ['Issued', invoice.issueDate],
                    ['Due', invoice.dueDate],
                    ['Status', invoice.status.replace(/_/g, ' ')],
                    ['Currency', invoice.currency],
                ]) {
                    font(true, 8).text(label, referenceX, referenceY, {
                        width: 52,
                        lineBreak: false,
                    });
                    font(false, 8);
                    const referenceLines = lines(value, right - referenceX - 58);
                    for (const line of referenceLines) {
                        font(false, 8).text(line, referenceX + 56, referenceY, {
                            width: right - referenceX - 56,
                            align: 'right',
                            lineBreak: false,
                        });
                        referenceY += 12;
                    }
                }
                y += 15;
                let customerContinued = false;
                for (const [value, bold] of [
                    [invoice.customer.name, true],
                    ...invoice.customer.lines.map((line) => [line, false]),
                ] as [string, boolean][]) {
                    font(bold, bold ? 10 : 8);
                    for (const line of lines(value, customerWidth)) {
                        if (y + 14 > bottom()) {
                            nextPage();
                            customerContinued = true;
                        }
                        font(bold, bold ? 10 : 8).text(line, 44, y, {
                            width: customerWidth,
                            lineBreak: false,
                        });
                        y += 13;
                    }
                }
                y = (customerContinued ? y : Math.max(y, referenceY)) + 20;
            } else {
                // Each template has its own masthead geometry; content below flows and paginates.
                const header = template.header;
                if (header === 'banner' || header === 'dark')
                    doc.rect(0, 0, doc.page.width, 116).fill(
                        header === 'dark' ? '#172033' : accent,
                    );
                if (header === 'rail') doc.rect(0, 0, 14, doc.page.height).fill(accent);
                if (header === 'split')
                    doc.rect(doc.page.width * 0.51, 0, doc.page.width * 0.49, 116).fill(accent);
                if (header === 'boxed')
                    doc.rect(44, 30, width, 75).lineWidth(1).strokeColor(accent).stroke();
                if (header === 'frame')
                    doc.rect(28, 28, doc.page.width - 56, doc.page.height - 56)
                        .lineWidth(1)
                        .strokeColor(accent)
                        .stroke();
                const centered = ['centered', 'frame'].includes(header);
                const logoX = centered
                    ? (doc.page.width - 90) / 2
                    : customization.logoPlacement === 'right'
                      ? right - 100
                      : 44;
                // A white logo card retains contrast on dark or coloured mastheads.
                doc.roundedRect(logoX - 5, 35, 110, 56, 3).fill('#FFFFFF');
                try {
                    doc.image(logo, logoX, 40, { fit: [100, 46] });
                } catch {
                    doc.image(receiptPlatformLogo, logoX, 40, { fit: [100, 46] });
                }
                y = centered ? 106 : 48;
                const titleX = centered
                    ? 44
                    : customization.logoPlacement === 'right'
                      ? 44
                      : right - 240;
                const titleColor = ['banner', 'dark'].includes(header)
                    ? invoiceInk(header === 'dark' ? '#172033' : accent)
                    : header === 'split' && customization.logoPlacement !== 'right'
                      ? invoiceInk(accent)
                      : '#0F172A';
                headingFont(header === 'editorial' ? 36 : header === 'minimal' ? 22 : 27)
                    .fillColor(titleColor)
                    .text('INVOICE', titleX, y, {
                        width: centered ? width : 240,
                        align: centered
                            ? 'center'
                            : customization.logoPlacement === 'right'
                              ? 'left'
                              : 'right',
                        lineBreak: false,
                    });
                y = centered ? 148 : 134;
                if (['rule', 'boxed', 'editorial'].includes(header)) {
                    rule(y - 14, accent, header === 'editorial' ? 2 : 1);
                    if (header === 'editorial') rule(y - 9, accent);
                }
                block(invoice.business.name, 17, true, centered ? 'center' : 'left');
                for (const line of invoice.business.lines)
                    block(line, 9, false, centered ? 'center' : 'left');
                y += 16;
                block(
                    `${invoice.invoiceNumber}  |  ${invoice.status.replace(/_/g, ' ')}`,
                    11,
                    true,
                );
                block(
                    `Issued: ${invoice.issueDate}    Due: ${invoice.dueDate}    Currency: ${invoice.currency}`,
                    9,
                );
                y += 12;
                block('BILL TO', 9, true);
                block(invoice.customer.name, 12, true);
                for (const line of invoice.customer.lines) block(line, 9);
                y += 20;
            }
            ensure(60);
            tableActive = true;
            drawTableHeader();
            invoice.items.forEach((item, index) => {
                font(false, 9);
                const description = lines(
                    [item.name, item.description, item.rental].filter(Boolean).join('\n'),
                    columns[1] - 12,
                );
                let offset = 0;
                while (offset < description.length) {
                    ensure(padding * 2 + 13);
                    const count = Math.max(
                        1,
                        Math.min(
                            description.length - offset,
                            Math.floor((bottom() - y - padding * 2) / 13),
                        ),
                    );
                    const height = count * 13 + padding * 2;
                    if (compactLayout) doc.rect(44, y, width, height).fill('#FFFFFF');
                    if (tableStyle === 'striped' && index % 2 === 0)
                        doc.rect(44, y, width, height).fill('#F1F5F9');
                    description.slice(offset, offset + count).forEach((line, i) =>
                        font(offset === 0 && i === 0, 9).text(line, 49, y + padding + i * 13, {
                            width: columns[1] - 12,
                            lineBreak: false,
                        }),
                    );
                    if (!offset) {
                        [item.quantity, item.unitPrice, item.tax, item.total].forEach(
                            (value, i) => {
                                const col = i + 1;
                                const available = columns[col + 1] - columns[col] - 10;
                                font(false, 9);
                                const size = Math.min(
                                    9,
                                    (9 * available) / Math.max(1, doc.widthOfString(value)),
                                );
                                font(false, size).text(value, 44 + columns[col] + 5, y + padding, {
                                    width: available,
                                    align: 'right',
                                    lineBreak: false,
                                });
                            },
                        );
                    }
                    y += height;
                    if (tableStyle === 'ruled' || compactLayout) rule(y);
                    if (compactLayout && tableStyle !== 'minimal') {
                        columns.forEach((column) =>
                            doc
                                .moveTo(44 + column, y - height)
                                .lineTo(44 + column, y)
                                .lineWidth(0.35)
                                .strokeColor('#D6DDE5')
                                .stroke(),
                        );
                    }
                    offset += count;
                    if (offset < description.length) nextPage();
                }
            });
            tableActive = false;
            y += 18;
            ensure(162);
            invoice.totals.forEach((total, index) => {
                const emphasized = index === 3 || index === 5;
                if (index === 5) doc.rect(right - 270, y, 270, 28).fill(accent);
                font(emphasized, 10)
                    .fillColor(index === 5 ? invoiceInk(accent) : '#1E293B')
                    .text(total.label, right - 260, y + 7, { width: 90, lineBreak: false });
                const value = `${invoice.currency} ${total.value}`;
                const available = 155;
                const size = Math.min(10, (10 * available) / Math.max(1, doc.widthOfString(value)));
                doc.fontSize(size).text(value, right - 165, y + 7, {
                    width: available,
                    align: 'right',
                    lineBreak: false,
                });
                y += 26;
            });
            y += 24;
            for (const [label, content] of [
                ['Payment terms', invoice.paymentTerms],
                ['Notes', invoice.notes],
                ['', invoice.footer],
            ]) {
                if (!content) continue;
                ensure(45);
                if (label) block(label, 10, true);
                block(content, 9);
                y += 12;
            }
            const pages = doc.bufferedPageRange();
            for (let i = pages.start; i < pages.start + pages.count; i++) {
                doc.switchToPage(i);
                // Footer stays outside flowing content and cannot create a phantom page.
                doc.page.margins.bottom = 0;
                rule(doc.page.height - 45);
                if (theme === 'panel')
                    doc.rect(42, doc.page.height - 39, width + 4, 17).fill('#FFFFFF');
                font(false, 8)
                    .fillColor('#64748B')
                    .text(
                        `${invoice.invoiceNumber}  •  ${invoice.currency}`,
                        44,
                        doc.page.height - 33,
                        { width: width / 2, lineBreak: false },
                    );
                doc.text(`Page ${i + 1} of ${pages.count}`, 44 + width / 2, doc.page.height - 33, {
                    width: width / 2,
                    align: 'right',
                    lineBreak: false,
                });
            }
            doc.end();
        } catch (error) {
            doc.end();
            reject(error);
        }
    });
}

export async function generateInvoicePdf(
    invoice: Parameters<typeof buildInvoiceDocument>[0],
    settings: InvoiceSettings | null,
    businessName: string,
    profile?: WorkspaceProfile | null,
): Promise<Buffer> {
    return renderInvoicePdf(
        buildInvoiceDocument(invoice, settings, businessName, profile),
        settings?.logoKey,
        settings?.artworkKey,
    );
}

import { join } from 'node:path';
import PDFDocument from 'pdfkit';
import sharp from 'sharp';
import { Decimal } from '@prisma/client/runtime/library';
import { container } from 'tsyringe';
import { StorageService } from '../files/storage.service';
import { receiptPlatformLogo } from './receipt-platform-logo';

export interface ReceiptDocument {
    receiptNumber: string;
    paymentDate: string;
    timezone: string;
    amountPaid: string;
    currency: string;
    paymentMode: { name: string } | null;
    description: string;
    obligation: { title: string; totalAmount: string; outstandingAmount: string } | null;
    customer: { name: string; email: string | null; phone: string | null; company: string | null };
    business: {
        name: string;
        legalName: string | null;
        address: string | null;
        phone: string | null;
        email: string | null;
        website: string | null;
        taxId: string | null;
        registrationNo: string | null;
        notes: string | null;
        footer: string | null;
        accentColor: string | null;
    };
}

/** Group decimal strings without converting financial amounts to binary floats. */
export function formatReceiptMoney(value: string): string {
    const decimal = new Decimal(value);
    const [whole, fraction] = decimal
        .toFixed(Math.max(2, Math.min(4, decimal.decimalPlaces())))
        .split('.');
    return `${whole.replace(/\B(?=(\d{3})+(?!\d))/g, ',')}.${fraction}`;
}

async function logoBuffer(key?: string | null): Promise<Buffer> {
    if (key) {
        try {
            const source = await container.resolve(StorageService).getObjectBuffer(key);
            return await sharp(source, { limitInputPixels: 20_000_000 })
                .resize({ width: 320, height: 160, fit: 'inside', withoutEnlargement: true })
                .png()
                .toBuffer();
        } catch {
            // Deleted, unavailable or corrupt business logos still produce a receipt.
        }
    }
    return receiptPlatformLogo;
}

/** The original frontend receipt card, centered on A4 and continued safely for long content. */
export async function generateReceiptPdf(
    receipt: ReceiptDocument,
    settings: { logoKey?: string | null } | null,
): Promise<Buffer> {
    const logo = await logoBuffer(settings?.logoKey);
    const logoSize = await sharp(logo).metadata();
    return new Promise((resolve, reject) => {
        const cardWidth = (148 / 25.4) * 72;
        const padding = 18;
        const pageTop = 36;
        const pageBottom = 36;
        const doc = new PDFDocument({
            size: 'A4',
            margins: { top: pageTop + 21, bottom: pageBottom + 21, left: 0, right: 0 },
            bufferPages: true,
            info: { Title: `Receipt ${receipt.receiptNumber}`, Author: receipt.business.name },
        });
        const chunks: Buffer[] = [];
        doc.on('data', (chunk: Buffer) => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', reject);
        try {
            doc.registerFont(
                'ReceiptRegular',
                join(__dirname, 'assets/LiberationSans-Regular.ttf'),
            );
            doc.registerFont('ReceiptBold', join(__dirname, 'assets/LiberationSans-Bold.ttf'));
            const cardX = (doc.page.width - cardWidth) / 2;
            const x = cardX + padding;
            const width = cardWidth - padding * 2;
            const ink = '#0F172A';
            const muted = '#64748B';
            const pageEnds = new Map<number, number>();
            let pageNumber = 0;
            const border = (bottom: number) => {
                doc.save()
                    .lineWidth(0.6)
                    .strokeColor('#E2E8F0')
                    .rect(cardX, pageTop, cardWidth, bottom - pageTop)
                    .stroke()
                    .restore();
            };
            doc.on('pageAdded', () => {
                pageEnds.set(pageNumber, doc.page.height - pageBottom);
                pageNumber++;
            });
            const ensure = (height: number) => {
                if (doc.y + height > doc.page.height - doc.page.margins.bottom) doc.addPage();
            };
            const text = (
                value: string,
                size = 9,
                bold = false,
                color = ink,
                align: 'left' | 'center' = 'left',
            ) => {
                doc.font(bold ? 'ReceiptBold' : 'ReceiptRegular')
                    .fontSize(size)
                    .fillColor(color)
                    .text(value, x, doc.y, { width, lineGap: 2, align });
            };
            const divider = () => {
                doc.save()
                    .lineWidth(0.6)
                    .strokeColor('#E2E8F0')
                    .moveTo(x, doc.y)
                    .lineTo(x + width, doc.y)
                    .stroke()
                    .restore();
            };
            const row = (label: string, value: string) => {
                const labelWidth = 108;
                const valueX = x + labelWidth + 12;
                const valueWidth = width - labelWidth - 12;
                doc.font('ReceiptBold').fontSize(10.5);
                const height = Math.max(
                    13,
                    doc.heightOfString(value, { width: valueWidth, lineGap: 2 }),
                );
                ensure(Math.min(height + 6, doc.page.height - 120));
                const start = doc.y;
                doc.font('ReceiptRegular')
                    .fontSize(10.5)
                    .fillColor(muted)
                    .text(label, x, start, { width: labelWidth, lineGap: 2 });
                const labelEnd = doc.y;
                const firstPage = pageNumber;
                doc.font('ReceiptBold')
                    .fontSize(10.5)
                    .fillColor(ink)
                    .text(value, valueX, start, { width: valueWidth, align: 'right', lineGap: 2 });
                doc.y = (pageNumber === firstPage ? Math.max(labelEnd, doc.y) : doc.y) + 6;
            };
            doc.y = pageTop + 21;
            const logoHeight = 36;
            const logoWidth = Math.min(
                width,
                (logoHeight * (logoSize.width ?? 1)) / (logoSize.height ?? 1),
            );
            doc.image(logo, x + (width - logoWidth) / 2, doc.y, {
                width: logoWidth,
                height: (logoWidth * (logoSize.height ?? 1)) / (logoSize.width ?? 1),
            });
            doc.y += logoHeight + 9;
            text(receipt.business.name, 12, true, ink, 'center');
            const business = receipt.business;
            for (const line of [
                business.legalName !== business.name ? business.legalName : null,
                business.address,
                business.phone,
                business.email,
                business.website,
                business.taxId ? `Tax ID: ${business.taxId}` : null,
                business.registrationNo ? `Registration: ${business.registrationNo}` : null,
            ]) {
                if (line) {
                    doc.y += 3;
                    text(line, 9, false, '#475569', 'center');
                }
            }
            doc.y += 9;
            ensure(40);
            doc.font('ReceiptBold').fontSize(9).fillColor(ink).text('PAYMENT RECEIPT', x, doc.y, {
                width,
                align: 'center',
                characterSpacing: 1.6,
            });
            doc.y += 12;
            divider();
            doc.y += 15;
            row('Receipt no.', receipt.receiptNumber);
            row(
                'Date',
                new Date(receipt.paymentDate).toLocaleDateString('en-GB', {
                    day: '2-digit',
                    month: 'short',
                    year: 'numeric',
                    timeZone: receipt.timezone,
                }),
            );
            row('Received from', receipt.customer.name);
            if (receipt.customer.company) row('Company', receipt.customer.company);
            if (receipt.customer.email) row('Email', receipt.customer.email);
            if (receipt.customer.phone) row('Phone', receipt.customer.phone);
            if (receipt.paymentMode) row('Paid by', receipt.paymentMode.name);
            doc.y += 6;
            ensure(50);
            divider();
            doc.y += 9;
            text('For', 9, false, muted);
            text(receipt.obligation?.title ?? receipt.description, 10.5);
            doc.y += 9;
            divider();
            doc.y += 12;
            const amount = `${receipt.currency} ${formatReceiptMoney(receipt.amountPaid)}`;
            // Keep the exact decimal amount inside the shaded box, even for unusually large values.
            let amountSize = 15;
            doc.font('ReceiptBold').fontSize(amountSize);
            while (doc.widthOfString(amount) > width - 18 && amountSize > 10) {
                doc.fontSize(--amountSize);
            }
            const amountHeight = doc.heightOfString(amount, { width: width - 18, lineGap: 2 });
            const boxHeight = 9 + 13 + amountHeight + 9;
            ensure(boxHeight + 12);
            const boxY = doc.y;
            doc.save().roundedRect(x, boxY, width, boxHeight, 6).fill('#F8FAFC').restore();
            doc.font('ReceiptRegular')
                .fontSize(9)
                .fillColor(muted)
                .text('Amount paid', x + 9, boxY + 9, { width: width - 18 });
            doc.font('ReceiptBold')
                .fontSize(amountSize)
                .fillColor(ink)
                .text(amount, x + 9, boxY + 22, { width: width - 18, lineGap: 2 });
            doc.y = boxY + boxHeight + 12;
            if (receipt.obligation) {
                row(
                    'Total due',
                    `${receipt.currency} ${formatReceiptMoney(receipt.obligation.totalAmount)}`,
                );
                row(
                    'Balance remaining',
                    new Decimal(receipt.obligation.outstandingAmount).greaterThan(0)
                        ? `${receipt.currency} ${formatReceiptMoney(receipt.obligation.outstandingAmount)}`
                        : 'Paid in full',
                );
            }
            if (business.notes) {
                doc.y += 12;
                text(business.notes);
            }
            if (business.footer) {
                doc.y += 12;
                ensure(28);
                divider();
                doc.y += 9;
                text(business.footer, 9, false, ink, 'center');
            }
            doc.y += 12;
            ensure(16);
            text('Thank you for your payment.', 9, false, muted, 'center');
            pageEnds.set(pageNumber, doc.y + 21);
            const pages = doc.bufferedPageRange();
            for (let page = pages.start; page < pages.start + pages.count; page++) {
                doc.switchToPage(page);
                border(pageEnds.get(page) ?? doc.page.height - pageBottom);
                if (pages.count > 1) {
                    doc.page.margins.bottom = 0;
                    doc.font('ReceiptRegular')
                        .fontSize(8)
                        .fillColor(muted)
                        .text(
                            `Receipt ${receipt.receiptNumber} - ${page + 1} / ${pages.count}`,
                            x,
                            doc.page.height - 24,
                            { width, align: 'center', lineBreak: false },
                        );
                }
            }
            doc.end();
        } catch (error) {
            doc.end();
            reject(error);
        }
    });
}

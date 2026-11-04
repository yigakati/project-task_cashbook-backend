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

/** Flowing layout: long business details and notes wrap and paginate safely. */
export async function generateReceiptPdf(
    receipt: ReceiptDocument,
    settings: { logoKey?: string | null } | null,
): Promise<Buffer> {
    const logo = await logoBuffer(settings?.logoKey);
    return new Promise((resolve, reject) => {
        const doc = new PDFDocument({
            size: 'A4',
            margins: { top: 44, bottom: 54, left: 48, right: 48 },
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
            const width = doc.page.width - 96;
            const accent = /^#[\da-f]{6}$/i.test(receipt.business.accentColor ?? '')
                ? receipt.business.accentColor!
                : '#4F46E5';
            const text = (value: string, size = 10, bold = false, color = '#475569') => {
                doc.font(bold ? 'ReceiptBold' : 'ReceiptRegular')
                    .fontSize(size)
                    .fillColor(color)
                    .text(value, 48, doc.y, { width, lineGap: 3 });
            };
            const gap = () => doc.moveDown(0.7);
            doc.image(logo, 48, 44, { fit: [120, 55] });
            doc.y = 116;
            text(receipt.business.name, 18, true, '#0F172A');
            const business = receipt.business;
            for (const line of [
                business.legalName !== business.name ? business.legalName : null,
                business.address,
                business.phone,
                business.email,
                business.website,
                business.taxId ? `Tax ID: ${business.taxId}` : null,
                business.registrationNo ? `Registration: ${business.registrationNo}` : null,
            ])
                if (line) text(line);
            gap();
            text('PAYMENT RECEIPT', 16, true, accent);
            text(`Receipt no. ${receipt.receiptNumber}`);
            text(
                `Date: ${new Date(receipt.paymentDate).toLocaleDateString('en-GB', {
                    day: '2-digit',
                    month: 'short',
                    year: 'numeric',
                    timeZone: receipt.timezone,
                })}`,
            );
            gap();
            text(`Received from: ${receipt.customer.name}`, 11, true, '#0F172A');
            for (const line of [
                receipt.customer.company,
                receipt.customer.email,
                receipt.customer.phone,
            ]) {
                if (line) text(line);
            }
            gap();
            text('For', 10, true);
            text(receipt.obligation?.title ?? receipt.description, 11);
            gap();
            text(
                `Amount paid: ${receipt.currency} ${formatReceiptMoney(receipt.amountPaid)}`,
                15,
                true,
                '#0F172A',
            );
            if (receipt.paymentMode) text(`Paid by: ${receipt.paymentMode.name}`);
            if (receipt.obligation) {
                text(
                    `Total due: ${receipt.currency} ${formatReceiptMoney(receipt.obligation.totalAmount)}`,
                );
                text(
                    new Decimal(receipt.obligation.outstandingAmount).greaterThan(0)
                        ? `Balance remaining: ${receipt.currency} ${formatReceiptMoney(receipt.obligation.outstandingAmount)}`
                        : 'Paid in full',
                    11,
                    true,
                );
            }
            if (business.notes) {
                gap();
                text(business.notes);
            }
            if (business.footer) {
                gap();
                text(business.footer, 9);
            }
            gap();
            text('Thank you for your payment.', 9);
            const pages = doc.bufferedPageRange();
            for (let page = pages.start; page < pages.start + pages.count; page++) {
                doc.switchToPage(page);
                // Footer lies below the content margin; prevent PDFKit from
                // moving it to a new page during automatic line layout.
                doc.page.margins.bottom = 0;
                doc.font('ReceiptRegular')
                    .fontSize(8)
                    .fillColor('#64748B')
                    .text(
                        `Receipt ${receipt.receiptNumber} - ${page + 1} / ${pages.count}`,
                        48,
                        doc.page.height - 40,
                        { width, align: 'center', lineBreak: false },
                    );
            }
            doc.end();
        } catch (error) {
            doc.end();
            reject(error);
        }
    });
}

import { afterEach, describe, expect, it, vi } from 'vitest';
import {
    generateReceiptPdf,
    formatReceiptMoney,
    ReceiptDocument,
} from '../../modules/entries/receipt.generator';
import { StorageService } from '../../modules/files/storage.service';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

function extract(pdf: Buffer, bbox = false) {
    const directory = mkdtempSync(join(tmpdir(), 'receipt-layout-'));
    const path = join(directory, 'receipt.pdf');
    try {
        writeFileSync(path, pdf);
        return execFileSync('pdftotext', [bbox ? '-bbox' : '-layout', path, '-'], {
            encoding: 'utf8',
        });
    } finally {
        rmSync(directory, { recursive: true, force: true });
    }
}

const model: ReceiptDocument = {
    receiptNumber: 'RCPT-1001',
    paymentDate: '2026-11-03T08:00:00.000Z',
    timezone: 'Africa/Kampala',
    amountPaid: '25000.125',
    currency: 'UGX',
    description: 'Goods supplied',
    paymentMode: { name: 'Cash' },
    obligation: null,
    customer: { name: 'Jane Customer', email: 'jane@example.test', phone: null, company: null },
    business: {
        name: 'Kampala Supplies',
        legalName: 'KS Limited',
        address: 'Plot 42 Market Road, Kampala, Uganda',
        phone: '+256700000001',
        email: 'billing@example.test',
        website: 'https://example.test',
        taxId: 'TIN-123',
        registrationNo: 'REG-123',
        notes: 'Keep this receipt for your records.',
        footer: 'Thank you for shopping with us.',
        accentColor: '#123456',
    },
};
afterEach(() => vi.restoreAllMocks());
describe('receipt PDF generation', () => {
    it('formats large and fractional financial amounts without losing precision', () => {
        expect(formatReceiptMoney('1234567890123456.125')).toBe('1,234,567,890,123,456.125');
        expect(formatReceiptMoney('25000')).toBe('25,000.00');
        expect(formatReceiptMoney('0.0001')).toBe('0.0001');
    });
    it('renders with a bundled logo when private storage is unavailable', async () => {
        vi.spyOn(StorageService.prototype, 'getObjectBuffer').mockRejectedValue(
            new Error('Unavailable'),
        );
        const pdf = await generateReceiptPdf(model, { logoKey: 'logos/deleted.png' });
        expect(pdf.subarray(0, 5).toString()).toBe('%PDF-');
        expect(pdf.length).toBeGreaterThan(3000);
        expect(pdf.toString('latin1').match(/\/Type \/Page\b/g)).toHaveLength(1);
    });
    it('paginates long details and notes without failing', async () => {
        const pdf = await generateReceiptPdf(
            {
                ...model,
                customer: { ...model.customer, name: 'Customer'.repeat(500) },
                business: {
                    ...model.business,
                    notes: 'Long receipt details. '.repeat(700) + ' FINAL-NOTE',
                },
            },
            null,
        );
        const pages = pdf.toString('latin1').match(/\/Type \/Page\b/g);
        expect(pages!.length).toBeGreaterThan(1);
        const content = extract(pdf);
        expect(content).toContain('FINAL-NOTE');
        expect(content).toContain('25,000.125');
        expect(content).toContain('Thank you for your payment.');
    });
    it('centers the original business header and aligns receipt values in a narrow card', async () => {
        const pdf = await generateReceiptPdf(model, null);
        const bbox = extract(pdf, true);
        const words = Array.from(
            bbox.matchAll(
                /<word xMin="([\d.]+)" yMin="([\d.]+)" xMax="([\d.]+)" yMax="([\d.]+)">([^<]+)<\/word>/g,
            ),
        );
        const name = words.find((word) => word[5] === 'Kampala')!;
        const endName = words.find((word) => word[5] === 'Supplies')!;
        expect((Number(name[1]) + Number(endName[3])) / 2).toBeCloseTo(595.28 / 2, 1);
        const number = words.find((word) => word[5] === model.receiptNumber)!;
        const label = words.find((word) => word[5] === 'Receipt')!;
        expect(Number(number[2])).toBeCloseTo(Number(label[2]), 1);
        expect(Number(label[1])).toBeGreaterThan(100);
        expect(Number(number[3])).toBeLessThan(495);
        expect(Number(number[1])).toBeGreaterThan(400);
        expect(extract(pdf)).toContain('Amount paid');
    });
    it.each(['25.125', '0'])(
        'includes obligation totals and balance %s without changing precision',
        async (outstandingAmount) => {
            const content = extract(
                await generateReceiptPdf(
                    {
                        ...model,
                        obligation: {
                            title: 'Services due',
                            totalAmount: '25025.25',
                            outstandingAmount,
                        },
                    },
                    null,
                ),
            );
            expect(content).toContain('Total due');
            expect(content).toContain('25,025.25');
            expect(content).toContain('Balance remaining');
            expect(content).toContain(outstandingAmount === '0' ? 'Paid in full' : '25.125');
        },
    );
});

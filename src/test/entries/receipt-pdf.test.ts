import { afterEach, describe, expect, it, vi } from 'vitest';
import {
    generateReceiptPdf,
    formatReceiptMoney,
    ReceiptDocument,
} from '../../modules/entries/receipt.generator';
import { StorageService } from '../../modules/files/storage.service';

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
                business: { ...model.business, notes: 'Long receipt details. '.repeat(700) },
            },
            null,
        );
        const pages = pdf.toString('latin1').match(/\/Type \/Page\b/g);
        expect(pages!.length).toBeGreaterThan(1);
    });
});

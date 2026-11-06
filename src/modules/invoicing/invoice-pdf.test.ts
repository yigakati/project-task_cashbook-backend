import { describe, expect, it, vi, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { invoiceTemplates } from './invoice-templates';
import { sampleInvoiceDocument } from './invoice-document';
import { invoiceInk, renderInvoicePdf } from './pdf.generator';
import { StorageService } from '../files/storage.service';

const directory = mkdtempSync(join(tmpdir(), 'invoice-pdf-'));
afterEach(() => vi.restoreAllMocks());
function extract(pdf: Buffer, name: string) {
    const file = join(directory, `${name}.pdf`);
    writeFileSync(file, pdf);
    try {
        return execFileSync('pdftotext', ['-layout', file, '-'], { encoding: 'utf8' });
    } finally {
        rmSync(file);
    }
}

describe('invoice PDF rendering', () => {
    it.each(invoiceTemplates)(
        'renders $name with readable content and one page',
        async (template) => {
            const model = sampleInvoiceDocument(null, 'Example Business');
            model.appearance.template = template;
            const pdf = await renderInvoicePdf(model);
            expect(pdf.subarray(0, 5).toString()).toBe('%PDF-');
            expect(pdf.toString('latin1').match(/\/Type \/Page\b/g)).toHaveLength(1);
            const text = extract(pdf, template.id);
            for (const content of [
                'Example Business',
                'PREVIEW-001',
                'Professional services',
                '285,000.00',
                'DRAFT',
                'Page 1 of 1',
            ])
                expect(text).toContain(content);
            expect(text).not.toContain('FULLY PAID');
        },
    );

    it('preserves every long row and note across pages with repeated headings', async () => {
        const model = sampleInvoiceDocument(null, 'Long Business Name '.repeat(15));
        model.appearance.customization.paperSize = 'LETTER';
        model.items = Array.from({ length: 45 }, (_, index) => ({
            ...model.items[0],
            name: `Line-${index + 1}`,
            description: 'Long description with details '.repeat(index === 0 ? 170 : 8),
        }));
        model.notes = 'Long payment conditions. '.repeat(80) + ' FINAL-NOTE-MARKER';
        const pdf = await renderInvoicePdf(model, 'logos/unavailable.png');
        const text = extract(pdf, 'long');
        for (let i = 1; i <= 45; i++) expect(text).toContain(`Line-${i}`);
        expect(text).toContain('FINAL-NOTE-MARKER');
        expect(text.match(/Description/g)!.length).toBeGreaterThan(2);
        expect(pdf.toString('latin1').match(/\/Type \/Page\b/g)!.length).toBeGreaterThan(3);
    });

    it('falls back for missing or corrupt logos and chooses accessible accent text', async () => {
        vi.spyOn(StorageService.prototype, 'getObjectBuffer').mockResolvedValue(
            Buffer.from('not an image'),
        );
        expect(
            await renderInvoicePdf(sampleInvoiceDocument(null, 'Business'), 'logos/corrupt.png'),
        ).toBeInstanceOf(Buffer);
        expect(invoiceInk('#FFFFFF')).toBe('#0F172A');
        expect(invoiceInk('#000000')).toBe('#FFFFFF');
    });
});

import {
    Invoice,
    InvoiceItem,
    InvoiceSettings,
    Contact,
    CustomerProfile,
    WorkspaceProfile,
} from '@prisma/client';
import { invoiceTemplate, readInvoiceCustomization, invoiceTheme } from './invoice-templates';
import { invoiceThemeUrl } from './invoice-theme-assets';
import { invoiceArtworkUrl } from './invoice-artwork';
import { invoiceLogoUrl } from './invoice-logo';
import { formatReceiptMoney } from '../entries/receipt.generator';

type InvoiceSource = Pick<
    Invoice,
    | 'invoiceNumber'
    | 'status'
    | 'issueDate'
    | 'dueDate'
    | 'currency'
    | 'subtotal'
    | 'discountAmount'
    | 'taxAmount'
    | 'totalAmount'
    | 'amountPaid'
    | 'amountDue'
    | 'notes'
    | 'footer'
    | 'paymentTerms'
    | 'billToSnapshot'
> & {
    items: Pick<
        InvoiceItem,
        | 'name'
        | 'description'
        | 'quantity'
        | 'unitPrice'
        | 'taxAmount'
        | 'total'
        | 'lineType'
        | 'rentalPeriodCount'
        | 'rentalPeriodUnit'
        | 'rentalStart'
        | 'rentalEnd'
    >[];
    customer: Pick<Contact, 'name' | 'email' | 'phone' | 'company'> & {
        customerProfile?: CustomerProfile | null;
    };
};

function address(value: unknown): string | null {
    if (typeof value === 'string') return value;
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const record = value as Record<string, unknown>;
    return (
        [
            record.line1 ?? record.addressLine1 ?? record.street,
            record.line2 ?? record.addressLine2,
            record.city,
            record.state,
            record.postalCode,
            record.country,
        ]
            .filter((value) => typeof value === 'string' && value.trim())
            .join(', ') || null
    );
}

export function buildInvoiceDocument(
    invoice: InvoiceSource,
    settings: InvoiceSettings | null,
    businessName: string,
    profile?: WorkspaceProfile | null,
) {
    const snapshot =
        invoice.billToSnapshot &&
        typeof invoice.billToSnapshot === 'object' &&
        !Array.isArray(invoice.billToSnapshot)
            ? (invoice.billToSnapshot as Record<string, unknown>)
            : null;
    const customer = snapshot ?? {
        ...invoice.customer,
        billingAddress: invoice.customer.customerProfile?.billingAddress,
        taxId: invoice.customer.customerProfile?.taxId,
    };
    const field = (key: string) =>
        typeof customer[key as keyof typeof customer] === 'string'
            ? String(customer[key as keyof typeof customer])
            : null;
    const template = invoiceTemplate(settings?.template);
    const customization = readInvoiceCustomization(settings?.customization);
    const theme = invoiceTheme(template, customization);
    return {
        invoiceNumber: invoice.invoiceNumber,
        status: invoice.status,
        issueDate: invoice.issueDate.toISOString().slice(0, 10),
        dueDate: invoice.dueDate.toISOString().slice(0, 10),
        currency: invoice.currency,
        business: {
            name: profile?.displayName?.trim() || businessName,
            lines: [
                profile?.legalName !== profile?.displayName ? profile?.legalName : null,
                [
                    profile?.addressLine1,
                    profile?.addressLine2,
                    profile?.city,
                    profile?.state,
                    profile?.postalCode,
                    profile?.country,
                ]
                    .filter(Boolean)
                    .join(', '),
                profile?.billingEmail || profile?.email,
                profile?.phone,
                profile?.website,
                profile?.taxId ? `Tax ID: ${profile.taxId}` : null,
                profile?.registrationNo ? `Registration: ${profile.registrationNo}` : null,
            ].filter((value): value is string => Boolean(value)),
        },
        customer: {
            name: field('name') || invoice.customer.name,
            lines: [
                field('company'),
                address(customer.billingAddress),
                field('email'),
                field('phone'),
                field('taxId') ? `Tax ID: ${field('taxId')}` : null,
            ].filter((value): value is string => Boolean(value)),
        },
        items: invoice.items.map((item) => ({
            name: item.name,
            description: item.description,
            quantity: item.quantity.toString(),
            unitPrice: formatReceiptMoney(item.unitPrice.toString()),
            tax: formatReceiptMoney(item.taxAmount.toString()),
            total: formatReceiptMoney(item.total.toString()),
            rental:
                item.lineType === 'RENTAL'
                    ? `${item.rentalPeriodCount ?? 1} ${item.rentalPeriodUnit?.toLowerCase() ?? 'day'} period(s)${item.rentalStart ? ` from ${item.rentalStart.toISOString().slice(0, 10)}` : ''}${item.rentalEnd ? ` to ${item.rentalEnd.toISOString().slice(0, 10)}` : ''}`
                    : null,
        })),
        totals: [
            { label: 'Subtotal', value: formatReceiptMoney(invoice.subtotal.toString()) },
            { label: 'Discount', value: formatReceiptMoney(invoice.discountAmount.toString()) },
            { label: 'Tax', value: formatReceiptMoney(invoice.taxAmount.toString()) },
            { label: 'Total', value: formatReceiptMoney(invoice.totalAmount.toString()) },
            { label: 'Paid', value: formatReceiptMoney(invoice.amountPaid.toString()) },
            { label: 'Amount due', value: formatReceiptMoney(invoice.amountDue.toString()) },
        ],
        notes: invoice.notes,
        footer: invoice.footer,
        paymentTerms: invoice.paymentTerms,
        appearance: {
            template,
            accentColor: /^#[0-9a-f]{6}$/i.test(settings?.accentColor ?? '')
                ? settings!.accentColor === '#4F46E5' && 'color' in template
                    ? template.color
                    : settings!.accentColor!
                : 'color' in template
                  ? template.color
                  : '#4F46E5',
            customization,
            logoUrl: invoiceLogoUrl(settings?.logoKey),
            theme,
            themeUrl: theme ? invoiceThemeUrl(theme) : null,
            artworkUrl: invoiceArtworkUrl(settings?.artworkKey),
        },
    };
}
export type InvoiceDocument = ReturnType<typeof buildInvoiceDocument>;

/** Deliberately fictional data. It cannot issue an invoice or change accounting. */
export function sampleInvoiceDocument(
    settings: InvoiceSettings | null,
    businessName: string,
    profile?: WorkspaceProfile | null,
    currency = 'UGX',
): InvoiceDocument {
    const sample = buildInvoiceDocument(
        {
            invoiceNumber: 'PREVIEW-001',
            status: 'DRAFT',
            issueDate: new Date('2026-01-15T00:00:00Z'),
            dueDate: new Date('2026-01-29T00:00:00Z'),
            currency,
            subtotal: '250000',
            discountAmount: '10000',
            taxAmount: '45000',
            totalAmount: '285000',
            amountPaid: '0',
            amountDue: '285000',
            notes: settings?.defaultNotes || 'Thank you for choosing our business.',
            footer: settings?.defaultFooter || null,
            paymentTerms: settings?.defaultTerms || null,
            billToSnapshot: null,
            customer: {
                name: 'Sample customer',
                email: 'customer@example.com',
                phone: null,
                company: 'Example Company',
            },
            items: [
                {
                    name: 'Professional services',
                    description: 'Consultation and implementation',
                    quantity: '2',
                    unitPrice: '100000',
                    taxAmount: '36000',
                    total: '236000',
                    lineType: 'SALE',
                },
                {
                    name: 'Support package',
                    description: 'Monthly maintenance',
                    quantity: '1',
                    unitPrice: '50000',
                    taxAmount: '9000',
                    total: '59000',
                    lineType: 'SALE',
                },
            ],
        } as unknown as InvoiceSource,
        settings,
        businessName,
        profile,
    );
    return sample;
}

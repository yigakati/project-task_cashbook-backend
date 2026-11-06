import { injectable, inject } from 'tsyringe';
import {
    PrismaClient,
    InvoiceSettings,
    InvoiceStatus,
    ContactType,
    ObligationStatus,
    ObligationType,
    InventoryReferenceType,
    InventoryTransactionType,
} from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import { InvoicingRepository } from './invoicing.repository';
import { AppError, NotFoundError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';
import { generateInvoicePdf, renderInvoicePdf } from './pdf.generator';
import { buildInvoiceDocument, sampleInvoiceDocument } from './invoice-document';
import { invoiceTemplates, invoiceTemplate, invoiceDesignAccess } from './invoice-templates';
import { config } from '../../config';
import { planOf } from '../../core/billing/entitlements';
import { Prisma } from '@prisma/client';
import { sendEmail, isEmailConfigured } from '../../config/email';
import { formatReceiptMoney } from '../entries/receipt.generator';
import { invoiceEmailTemplate } from '../../utils/emailTemplates';
import { InventoryService } from '../inventory/inventory.service';
import {
    CreateInvoiceDto,
    UpdateInvoiceDto,
    InvoiceQueryDto,
    UpdateInvoiceSettingsDto,
    SendInvoiceDto,
} from './invoicing.dto';
import { assertSameCurrency, normalizeCurrency } from '../../core/finance';
import sharp from 'sharp';
import { logger } from '../../utils/logger';
import { StorageService } from '../files/storage.service';
import { assertCashbookWritable } from '../cashbooks/cashbook-state';
import { LOGO_FILE_PATTERN, LOGO_PREFIX, invoiceLogoUrl, logoObjectKey } from './invoice-logo';
import { assertStorageAvailable, lockWorkspaceStorage } from '../storage/storage-quota.service';

// ─── Internal type for calculated line items ───────────────────────────────────
interface CalculatedItem {
    productServiceId?: string;
    inventoryItemId?: string; // resolved from productService.inventoryItemId or item-level override
    lineType: 'SALE' | 'RENTAL';
    name: string;
    description?: string;
    quantity: Decimal;
    unitPrice: Decimal;
    taxId?: string;
    taxRate: Decimal;
    taxAmount: Decimal;
    total: Decimal;
    rentalStart?: Date | null;
    rentalEnd?: Date | null;
    rentalPeriodUnit?: 'DAY' | 'WEEK' | 'MONTH' | null;
    rentalPeriodCount?: number | null;
}

@injectable()
export class InvoicingService {
    constructor(
        private repository: InvoicingRepository,
        private inventoryService: InventoryService,
        private storage: StorageService,
        @inject('PrismaClient') private prisma: PrismaClient,
    ) {}

    /**
     * Settings as the API hands them out.
     *
     * logoUrl is derived from the stored key rather than kept in a column, so
     * it is always right for the address this deployment answers on.
     */
    private withLogoUrl<T extends { logoKey: string | null }>(settings: T) {
        return { ...settings, logoUrl: invoiceLogoUrl(settings.logoKey) };
    }

    // ═══════════════════════════════════════════════════════
    // ─── Create Invoice (DRAFT) ────────────────────────────
    // ═══════════════════════════════════════════════════════

    async createInvoice(workspaceId: string, userId: string, dto: CreateInvoiceDto) {
        const workspace = await this.prisma.workspace.findUnique({ where: { id: workspaceId } });
        if (!workspace || !workspace.isActive) {
            throw new NotFoundError('Workspace');
        }
        const workspaceCurrency = normalizeCurrency(workspace.defaultCurrency);
        // Validate customer
        const customer = await this.prisma.contact.findUnique({
            where: { id: dto.customerId },
            include: { customerProfile: true },
        });
        if (!customer || customer.workspaceId !== workspaceId || !customer.isActive) {
            throw new NotFoundError('Customer');
        }
        if (customer.type !== ContactType.CUSTOMER) {
            throw new AppError(
                'Contact must be of type CUSTOMER to create an invoice',
                400,
                'INVALID_CUSTOMER_TYPE',
            );
        }

        // Validate cashbook
        const cashbook = await this.prisma.cashbook.findUnique({
            where: { id: dto.cashbookId },
            select: {
                id: true,
                name: true,
                workspaceId: true,
                isActive: true,
                currency: true,
                archivedAt: true,
            },
        });
        if (!cashbook || cashbook.workspaceId !== workspaceId || !cashbook.isActive) {
            throw new NotFoundError('Cashbook');
        }
        assertCashbookWritable(cashbook);

        if (dto.currency) {
            assertSameCurrency(workspaceCurrency, dto.currency, 'workspace base vs invoice');
        }
        const invoiceCurrency = workspaceCurrency;
        // Invoice must match linked cashbook currency (payments land in that book)
        assertSameCurrency(cashbook.currency, invoiceCurrency, 'invoice vs cashbook');

        // Generate invoice number if not provided
        const invoiceNumber =
            dto.invoiceNumber || (await this.repository.getNextInvoiceNumber(workspaceId));

        // Check for duplicate invoice number
        const existingInvoice = await this.prisma.invoice.findUnique({
            where: { workspaceId_invoiceNumber: { workspaceId, invoiceNumber } },
        });
        if (existingInvoice) {
            throw new AppError('Invoice number already exists', 409, 'DUPLICATE_INVOICE_NUMBER');
        }

        // Validate due date >= issue date
        if (new Date(dto.dueDate) < new Date(dto.issueDate)) {
            throw new AppError(
                'Due date must be on or after the issue date',
                400,
                'INVALID_DUE_DATE',
            );
        }

        // Server-side calculations (resolves inventoryItemId via product service link)
        const { items, subtotal, taxAmount, discountAmount, totalAmount, amountDue } =
            await this.calculateInvoiceTotals(
                workspaceId,
                dto.items,
                dto.discountAmount,
                invoiceCurrency,
            );

        if (totalAmount.lessThan(0)) {
            throw new AppError('Invoice total cannot be negative', 400, 'NEGATIVE_TOTAL');
        }

        const defaults = await this.repository.getInvoiceSettings(workspaceId);
        const invoice = await this.prisma.$transaction(async (tx) => {
            const inv = await tx.invoice.create({
                data: {
                    workspaceId,
                    customerId: dto.customerId,
                    invoiceNumber,
                    status: InvoiceStatus.DRAFT,
                    issueDate: new Date(dto.issueDate),
                    dueDate: new Date(dto.dueDate),
                    currency: invoiceCurrency,
                    subtotal,
                    discountAmount,
                    taxAmount,
                    totalAmount,
                    amountPaid: new Decimal(0),
                    amountDue,
                    notes: dto.notes === undefined ? defaults?.defaultNotes : dto.notes || null,
                    footer: dto.footer === undefined ? defaults?.defaultFooter : dto.footer || null,
                    paymentTerms:
                        dto.paymentTerms === undefined
                            ? defaults?.defaultTerms
                            : dto.paymentTerms || null,
                    createdById: userId,
                    cashbookId: dto.cashbookId,
                } as any,
            });

            // Create invoice items — including line type, rental fields, inventory snapshot
            await tx.invoiceItem.createMany({
                data: items.map((item, position) => ({
                    position,
                    invoiceId: inv.id,
                    productServiceId: item.productServiceId || null,
                    inventoryItemId: item.inventoryItemId || null,
                    lineType: item.lineType as any,
                    name: item.name,
                    description: item.description || null,
                    quantity: item.quantity,
                    unitPrice: item.unitPrice,
                    taxId: item.taxId || null,
                    taxRate: item.taxRate,
                    taxAmount: item.taxAmount,
                    total: item.total,
                    rentalStart: item.rentalStart || null,
                    rentalEnd: item.rentalEnd || null,
                    rentalPeriodUnit: (item.rentalPeriodUnit as any) || null,
                    rentalPeriodCount: item.rentalPeriodCount ?? null,
                })),
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.INVOICE_CREATED,
                    resource: 'invoice',
                    resourceId: inv.id,
                    details: {
                        invoiceNumber,
                        customerId: dto.customerId,
                        totalAmount: totalAmount.toString(),
                    } as any,
                },
            });

            return inv;
        });

        return this.repository.findById(invoice.id);
    }

    // ═══════════════════════════════════════════════════════
    // ─── Update Invoice (DRAFT only) ───────────────────────
    // ═══════════════════════════════════════════════════════

    async updateInvoice(
        invoiceId: string,
        workspaceId: string,
        userId: string,
        dto: UpdateInvoiceDto,
    ) {
        const existing = await this.repository.findById(invoiceId);
        if (!existing || existing.workspaceId !== workspaceId) {
            throw new NotFoundError('Invoice');
        }

        if (existing.status !== InvoiceStatus.DRAFT) {
            throw new AppError('Only DRAFT invoices can be edited', 400, 'INVOICE_NOT_EDITABLE');
        }

        if (dto.customerId) {
            const customer = await this.prisma.contact.findUnique({
                where: { id: dto.customerId },
            });
            if (
                !customer ||
                customer.workspaceId !== workspaceId ||
                customer.type !== ContactType.CUSTOMER
            ) {
                throw new AppError('Invalid customer', 400, 'INVALID_CUSTOMER');
            }
        }

        if (dto.invoiceNumber && dto.invoiceNumber !== existing.invoiceNumber) {
            const dup = await this.prisma.invoice.findUnique({
                where: {
                    workspaceId_invoiceNumber: { workspaceId, invoiceNumber: dto.invoiceNumber },
                },
            });
            if (dup)
                throw new AppError(
                    'Invoice number already exists',
                    409,
                    'DUPLICATE_INVOICE_NUMBER',
                );
        }

        const workspace = await this.prisma.workspace.findUnique({ where: { id: workspaceId } });
        if (!workspace || !workspace.isActive) throw new NotFoundError('Workspace');
        const nextCurrency = normalizeCurrency(existing.currency);
        if (dto.currency) {
            assertSameCurrency(nextCurrency, dto.currency, 'workspace base vs invoice');
        }
        if (dto.cashbookId || dto.currency || (existing as any).cashbookId) {
            const cashbookId = dto.cashbookId || (existing as any).cashbookId;
            if (cashbookId) {
                const cashbook = await this.prisma.cashbook.findUnique({
                    where: { id: cashbookId },
                    select: {
                        id: true,
                        name: true,
                        workspaceId: true,
                        isActive: true,
                        currency: true,
                        archivedAt: true,
                    },
                });
                if (!cashbook || cashbook.workspaceId !== workspaceId || !cashbook.isActive) {
                    throw new NotFoundError('Cashbook');
                }
                assertCashbookWritable(cashbook);
                assertSameCurrency(cashbook.currency, nextCurrency, 'invoice vs cashbook');
            }
        }

        const issueDate = dto.issueDate ? new Date(dto.issueDate) : existing.issueDate;
        const dueDate = dto.dueDate ? new Date(dto.dueDate) : existing.dueDate;
        if (dueDate < issueDate)
            throw new AppError(
                'Due date must be on or after the issue date',
                400,
                'INVALID_DUE_DATE',
            );
        const calculated = dto.items
            ? await this.calculateInvoiceTotals(
                  workspaceId,
                  dto.items,
                  dto.discountAmount ?? existing.discountAmount.toString(),
                  nextCurrency,
              )
            : null;
        const discountAmount = new Decimal(dto.discountAmount ?? existing.discountAmount);
        const totalAmount =
            calculated?.totalAmount ??
            new Decimal(existing.subtotal).sub(discountAmount).add(existing.taxAmount);
        if (totalAmount.lessThan(0))
            throw new AppError('Invoice total cannot be negative', 400, 'NEGATIVE_TOTAL');
        await this.prisma.$transaction(async (tx) => {
            await tx.$queryRaw`SELECT id FROM invoices WHERE id = ${invoiceId}::uuid FOR UPDATE`;
            const current = await tx.invoice.findUniqueOrThrow({ where: { id: invoiceId } });
            if (
                current.status !== 'DRAFT' ||
                current.updatedAt.getTime() !== existing.updatedAt.getTime()
            ) {
                throw new AppError(
                    'This invoice changed. Reload it before editing.',
                    409,
                    'INVOICE_CONFLICT',
                );
            }
            if (calculated) {
                await tx.invoiceItem.deleteMany({ where: { invoiceId } });
                await tx.invoiceItem.createMany({
                    data: calculated.items.map((item, position) => ({
                        ...item,
                        invoiceId,
                        position,
                    })),
                });
            }
            await tx.invoice.update({
                where: { id: invoiceId },
                data: {
                    ...(dto.customerId && { customerId: dto.customerId }),
                    ...(dto.invoiceNumber && { invoiceNumber: dto.invoiceNumber }),
                    issueDate,
                    dueDate,
                    ...(dto.notes !== undefined && { notes: dto.notes }),
                    ...(dto.footer !== undefined && { footer: dto.footer }),
                    ...(dto.paymentTerms !== undefined && { paymentTerms: dto.paymentTerms }),
                    ...(dto.cashbookId && { cashbookId: dto.cashbookId }),
                    subtotal: calculated?.subtotal ?? existing.subtotal,
                    taxAmount: calculated?.taxAmount ?? existing.taxAmount,
                    discountAmount,
                    totalAmount,
                    amountDue: totalAmount,
                },
            });
            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.INVOICE_UPDATED,
                    resource: 'invoice',
                    resourceId: invoiceId,
                },
            });
        });
        return this.repository.findById(invoiceId);
    }

    // ═══════════════════════════════════════════════════════
    // ─── Send Invoice ──────────────────────────────────────
    // ═══════════════════════════════════════════════════════

    async sendInvoice(
        invoiceId: string,
        workspaceId: string,
        userId: string,
        payment?: SendInvoiceDto,
    ) {
        const invoice = await this.repository.findById(invoiceId);
        if (!invoice || invoice.workspaceId !== workspaceId) {
            throw new NotFoundError('Invoice');
        }

        if (invoice.status !== InvoiceStatus.DRAFT) {
            throw new AppError('Only DRAFT invoices can be sent', 400, 'INVALID_STATUS');
        }

        const cashbookId = (invoice as any).cashbookId;
        if (!cashbookId) {
            throw new AppError('Invoice is not linked to a cashbook', 400, 'MISSING_CASHBOOK');
        }

        const cashbook = await this.prisma.cashbook.findUnique({
            where: { id: cashbookId },
            select: {
                id: true,
                name: true,
                workspaceId: true,
                isActive: true,
                currency: true,
                archivedAt: true,
            },
        });
        if (!cashbook || cashbook.workspaceId !== workspaceId || !cashbook.isActive) {
            throw new NotFoundError('Cashbook');
        }
        assertCashbookWritable(cashbook);
        assertSameCurrency(cashbook.currency, invoice.currency, 'invoice vs cashbook on send');

        if (payment?.paymentAmount) {
            const payAmt = new Decimal(payment.paymentAmount);
            if (payAmt.greaterThan(new Decimal(invoice.amountDue))) {
                throw new AppError(
                    `Payment amount exceeds invoice amount due (${invoice.amountDue})`,
                    400,
                    'OVERPAYMENT',
                );
            }
        }

        let obligationId: string | null = null;

        await this.prisma.$transaction(async (tx) => {
            await tx.$queryRaw`SELECT id FROM invoices WHERE id = ${invoiceId}::uuid FOR UPDATE`;
            const current = await tx.invoice.findUniqueOrThrow({ where: { id: invoiceId } });
            if (
                current.status !== 'DRAFT' ||
                current.updatedAt.getTime() !== invoice.updatedAt.getTime()
            ) {
                throw new AppError(
                    'This invoice changed or was already issued. Reload it before continuing.',
                    409,
                    'INVOICE_CONFLICT',
                );
            }
            // 1. Mark invoice as SENT, freezing who it was billed to.
            //
            // The customer row is live, and for a contact connected to another
            // workspace it now refreshes from that workspace's own profile.
            // Without this snapshot, their next address change would silently
            // rewrite what this already-issued invoice claims.
            const billTo = await tx.contact.findUnique({
                where: { id: invoice.customerId },
                select: {
                    name: true,
                    email: true,
                    phone: true,
                    company: true,
                    customerProfile: {
                        select: { billingAddress: true, taxId: true, accountNumber: true },
                    },
                },
            });

            await tx.invoice.update({
                where: { id: invoiceId },
                data: {
                    status: InvoiceStatus.SENT,
                    billToSnapshot: billTo
                        ? ({
                              name: billTo.name,
                              email: billTo.email,
                              phone: billTo.phone,
                              company: billTo.company,
                              taxId: billTo.customerProfile?.taxId ?? null,
                              accountNumber: billTo.customerProfile?.accountNumber ?? null,
                              billingAddress: billTo.customerProfile?.billingAddress ?? null,
                              snapshotAt: new Date().toISOString(),
                          } as any)
                        : undefined,
                },
            });

            // 2. Create a RECEIVABLE obligation linked back to this invoice
            const obligation = await tx.cashbookObligation.create({
                data: {
                    workspaceId,
                    cashbookId,
                    type: ObligationType.RECEIVABLE,
                    title: `Invoice ${invoice.invoiceNumber}`,
                    description: `Receivable for invoice ${invoice.invoiceNumber} — ${invoice.customer.name}`,
                    totalAmount: invoice.totalAmount,
                    // An invoice is all principal. Interest is a lending
                    // concept — what an invoice bills for is the goods or work,
                    // and any late-payment charge would be a separate document.
                    principalAmount: invoice.totalAmount,
                    outstandingAmount: invoice.amountDue,
                    status: ObligationStatus.OPEN,
                    dueDate: invoice.dueDate,
                    contactId: invoice.customerId,
                    referenceType: 'INVOICE',
                    referenceId: invoiceId,
                },
            });
            obligationId = obligation.id;

            // 3. Stock movements: SALE → permanent COGS stock-out; RENTAL → RENTAL_OUT + InventoryRental
            const rentalLines = invoice.items.filter(
                (li: any) => li.lineType === 'RENTAL' && li.inventoryItemId,
            );
            if (rentalLines.length > 0) {
                const earliestStart = rentalLines.reduce(
                    (min: Date, li: any) => {
                        const d = li.rentalStart ? new Date(li.rentalStart) : new Date();
                        return d < min ? d : min;
                    },
                    new Date(rentalLines[0].rentalStart || Date.now()),
                );
                const latestEnd = rentalLines.reduce(
                    (max: Date | null, li: any) => {
                        if (!li.rentalEnd) return max;
                        const d = new Date(li.rentalEnd);
                        return !max || d > max ? d : max;
                    },
                    null as Date | null,
                );

                const rental = await tx.inventoryRental.create({
                    data: {
                        workspaceId,
                        customerId: invoice.customerId,
                        invoiceId,
                        status: 'ACTIVE' as any,
                        currency: invoice.currency,
                        startDate: earliestStart,
                        endDate: latestEnd,
                        createdById: userId,
                        notes: `Rental for invoice ${invoice.invoiceNumber}`,
                    },
                });

                for (const lineItem of rentalLines) {
                    const qty = Math.round(Number(lineItem.quantity));
                    if (qty <= 0) continue;

                    const periodCount = lineItem.rentalPeriodCount ?? 1;
                    await tx.inventoryRentalLine.create({
                        data: {
                            rentalId: rental.id,
                            inventoryItemId: lineItem.inventoryItemId!,
                            quantity: qty,
                            unitRate: lineItem.unitPrice,
                            periodUnit: (lineItem.rentalPeriodUnit || 'DAY') as any,
                            periodCount,
                            lineTotal: lineItem.total,
                        },
                    });

                    await this.inventoryService.processRentalOutForInvoice(
                        tx,
                        workspaceId,
                        invoiceId,
                        lineItem.inventoryItemId!,
                        qty,
                        userId,
                        `Rental out for invoice ${invoice.invoiceNumber}`,
                        new Decimal(lineItem.unitPrice),
                    );
                }
            }

            for (const lineItem of invoice.items) {
                if (!lineItem.inventoryItemId) continue;
                if ((lineItem as any).lineType === 'RENTAL') continue; // handled above

                const qty = Math.round(Number(lineItem.quantity));
                if (qty <= 0) continue;

                await this.inventoryService.processStockOut(
                    workspaceId,
                    lineItem.inventoryItemId,
                    InventoryTransactionType.SALE,
                    qty,
                    userId,
                    InventoryReferenceType.INVOICE,
                    invoiceId,
                    `Stock-out for invoice ${invoice.invoiceNumber}`,
                    tx,
                    new Decimal(lineItem.unitPrice),
                );
            }

            // 4. Audit log
            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.INVOICE_SENT,
                    resource: 'invoice',
                    resourceId: invoiceId,
                },
            });
        });

        let paymentEntry: unknown = null;
        if (payment?.paymentAmount && obligationId) {
            // An account is required so the payment entry is linked to a wallet.
            // Without it the cashbook entry has no account to post to — the same
            // gap the entries DTO enforces on normal creation paths.
            if (!payment.accountId) {
                throw new AppError(
                    'An account (wallet) is required to record the payment. Select the wallet the money was received into.',
                    400,
                    'MISSING_ACCOUNT',
                );
            }
            try {
                const { container } = await import('tsyringe');
                const { EntriesService } = await import('../entries/entries.service');
                const entriesService = container.resolve(EntriesService);
                paymentEntry = await entriesService.createEntry(cashbookId, userId, {
                    type: 'INCOME' as any,
                    amount: payment.paymentAmount,
                    description:
                        payment.paymentDescription ||
                        `Payment for invoice ${invoice.invoiceNumber}`,
                    entryDate: payment.entryDate || new Date().toISOString(),
                    contactId: invoice.customerId,
                    obligationId,
                    accountId: payment.accountId,
                } as any);
            } catch (payErr: any) {
                // Send already committed — surface payment failure without undoing send.
                throw new AppError(
                    payErr?.message ||
                        'Invoice was sent but payment failed. Pay the receivable from the cashbook.',
                    payErr?.statusCode || 400,
                    payErr?.code || 'INVOICE_PAYMENT_FAILED',
                );
            }
        }

        // 5. Generate ephemeral PDF and send professional email (outside transaction — failure is non-blocking)
        let emailDelivery: 'sent' | 'failed' | 'not_configured' | 'no_email' = invoice.customer
            .email
            ? 'not_configured'
            : 'no_email';
        try {
            if (invoice.customer.email && isEmailConfigured()) {
                const [settings, workspace, profile] = await Promise.all([
                    this.repository.getInvoiceSettings(workspaceId),
                    this.prisma.workspace.findUnique({ where: { id: workspaceId } }),
                    this.prisma.workspaceProfile.findUnique({ where: { workspaceId } }),
                ]);

                // Fetch the freshly-sent invoice with inventory item data for PDF
                const invoiceForPdf = await this.prisma.invoice.findUnique({
                    where: { id: invoiceId },
                    include: {
                        customer: {
                            select: {
                                id: true,
                                name: true,
                                email: true,
                                phone: true,
                                company: true,
                                customerProfile: true,
                            },
                        },
                        items: {
                            include: {
                                inventoryItem: { select: { name: true, sku: true, unit: true } },
                                tax: { select: { id: true, name: true, rate: true } },
                            },
                            orderBy: [{ position: 'asc' }, { id: 'asc' }],
                        },
                    },
                });

                const businessName = profile?.displayName || workspace?.name || 'Business';
                const pdfBuffer = await generateInvoicePdf(
                    invoiceForPdf as any,
                    settings,
                    businessName,
                    profile,
                );

                // Build items summary for email body (≤5 shown inline, rest noted)
                const itemsSummary = (invoiceForPdf?.items || []).map((item) => ({
                    name: item.name,
                    quantity: String(item.quantity),
                    total: formatReceiptMoney(item.total.toString()),
                }));

                const htmlBody = invoiceEmailTemplate({
                    customerName: invoice.customer.name,
                    businessName,
                    invoiceNumber: invoice.invoiceNumber,
                    currency: invoice.currency,
                    totalAmount: formatReceiptMoney(invoice.totalAmount.toString()),
                    dueDate: new Date(invoice.dueDate).toLocaleDateString('en-GB', {
                        day: '2-digit',
                        month: 'short',
                        year: 'numeric',
                    }),
                    itemsSummary,
                    notes: invoice.notes,
                    logoUrl: invoiceLogoUrl(settings?.logoKey),
                });

                await sendEmail({
                    to: invoice.customer.email,
                    subject: `Invoice ${invoice.invoiceNumber} from ${businessName}`,
                    html: htmlBody,
                    attachments: [
                        {
                            filename: `${invoice.invoiceNumber}.pdf`,
                            content: pdfBuffer,
                            contentType: 'application/pdf',
                        },
                    ],
                });
                emailDelivery = 'sent';
            }
        } catch (_err) {
            emailDelivery = 'failed';
            logger.error('Invoice email could not be delivered', {
                invoiceId,
                workspaceId,
                error: _err instanceof Error ? _err.message : String(_err),
            });
            // Email / PDF failure must not roll back the send operation.
            // Invoice is already SENT and obligation already created.
        }

        const sent = await this.repository.findById(invoiceId);
        return {
            ...sent,
            obligationId,
            paymentApplied: Boolean(paymentEntry),
            emailDelivery,
        };
    }

    // ═══════════════════════════════════════════════════════
    // ─── Void Invoice ──────────────────────────────────────
    // ═══════════════════════════════════════════════════════

    async voidInvoice(invoiceId: string, workspaceId: string, userId: string) {
        const invoice = await this.repository.findById(invoiceId);
        if (!invoice || invoice.workspaceId !== workspaceId) {
            throw new NotFoundError('Invoice');
        }

        if (invoice.status === InvoiceStatus.VOID) {
            throw new AppError('Invoice is already voided', 400, 'ALREADY_VOIDED');
        }

        if (new Decimal(invoice.amountPaid).greaterThan(0)) {
            throw new AppError(
                'Cannot void an invoice with payments applied. Refund payments first.',
                400,
                'HAS_PAYMENTS',
            );
        }

        await this.prisma.$transaction(async (tx) => {
            // 1. Mark invoice VOID
            await tx.invoice.update({
                where: { id: invoiceId },
                data: { status: InvoiceStatus.VOID },
            });

            // 2. Cancel the linked RECEIVABLE obligation, taking its remaining
            //    balance off the books. A bare status flip would leave the
            //    receivable sitting on the balance sheet forever.
            if (
                invoice.status === InvoiceStatus.SENT ||
                invoice.status === InvoiceStatus.OVERDUE ||
                invoice.status === InvoiceStatus.PARTIALLY_PAID
            ) {
                const linked = await tx.cashbookObligation.findMany({
                    where: {
                        referenceType: 'INVOICE',
                        referenceId: invoiceId,
                        status: { not: ObligationStatus.CANCELLED },
                    },
                    select: { id: true, cashbookId: true },
                });

                const { ObligationsService } =
                    await import('../cashbook-obligations/obligations.service');
                const { container } = await import('tsyringe');
                const obligationsService = container.resolve(ObligationsService);

                for (const obligation of linked) {
                    await obligationsService.cancelObligationInTx(
                        tx,
                        obligation.id,
                        userId,
                        `Invoice ${invoice.invoiceNumber} voided`,
                    );
                }
            }

            // 3. Reverse inventory stock-outs via RETURN_IN (proper lot restoration for FIFO/LIFO)
            await this.reverseInvoiceInventory(tx, invoice, workspaceId, userId);

            // 4. Audit
            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.INVOICE_VOIDED,
                    resource: 'invoice',
                    resourceId: invoiceId,
                },
            });
        });

        return this.repository.findById(invoiceId);
    }

    // ═══════════════════════════════════════════════════════
    // ─── Delete Invoice ────────────────────────────────────
    // ═══════════════════════════════════════════════════════

    async deleteInvoice(invoiceId: string, workspaceId: string, userId: string) {
        const invoice = await this.repository.findById(invoiceId);
        if (!invoice || invoice.workspaceId !== workspaceId) {
            throw new NotFoundError('Invoice');
        }

        if (invoice.status !== InvoiceStatus.DRAFT && invoice.status !== InvoiceStatus.VOID) {
            throw new AppError('Only DRAFT or VOID invoices can be deleted', 400, 'CANNOT_DELETE');
        }

        if (new Decimal(invoice.amountPaid).greaterThan(0)) {
            throw new AppError(
                'Cannot delete an invoice with payments applied',
                400,
                'HAS_PAYMENTS',
            );
        }

        await this.prisma.$transaction(async (tx) => {
            await tx.invoiceItem.deleteMany({ where: { invoiceId } });
            await tx.invoice.delete({ where: { id: invoiceId } });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.INVOICE_DELETED,
                    resource: 'invoice',
                    resourceId: invoiceId,
                },
            });
        });
    }

    // ═══════════════════════════════════════════════════════
    // ─── Get / List ────────────────────────────────────────
    // ═══════════════════════════════════════════════════════

    async getInvoice(invoiceId: string, workspaceId: string) {
        const invoice = await this.repository.findById(invoiceId);
        if (!invoice || invoice.workspaceId !== workspaceId) throw new NotFoundError('Invoice');
        return invoice;
    }

    async listInvoices(workspaceId: string, query: InvoiceQueryDto) {
        const page = Number(query.page) || 1;
        const limit = Number(query.limit) || 20;
        const skip = (page - 1) * limit;

        const { invoices, total } = await this.repository.findByWorkspace(workspaceId, {
            skip,
            take: limit,
            status: query.status as InvoiceStatus | undefined,
            customerId: query.customerId,
            startDate: query.startDate,
            endDate: query.endDate,
            sortBy: query.sortBy || 'createdAt',
            sortOrder: query.sortOrder || 'desc',
        });

        const totalPages = Math.ceil(total / limit);
        return {
            data: invoices,
            pagination: {
                page,
                limit,
                total,
                totalPages,
                hasNext: page < totalPages,
                hasPrevious: page > 1,
            },
        };
    }

    // ═══════════════════════════════════════════════════════
    // ─── Reporting ─────────────────────────────────────────
    // ═══════════════════════════════════════════════════════

    async getOverdueInvoices(workspaceId: string) {
        return this.repository.findOverdueInvoices(workspaceId);
    }

    async getInvoiceSummary(workspaceId: string) {
        const [totalReceivables, overdueCount, statusCounts] = await Promise.all([
            this.prisma.invoice.aggregate({
                where: {
                    workspaceId,
                    status: {
                        in: [
                            InvoiceStatus.SENT,
                            InvoiceStatus.PARTIALLY_PAID,
                            InvoiceStatus.OVERDUE,
                        ],
                    },
                },
                _sum: { amountDue: true },
            }),
            this.prisma.invoice.count({
                where: {
                    workspaceId,
                    status: { in: [InvoiceStatus.SENT, InvoiceStatus.PARTIALLY_PAID] },
                    dueDate: { lt: new Date() },
                },
            }),
            this.prisma.invoice.groupBy({
                by: ['status'],
                where: { workspaceId },
                _count: { id: true },
                _sum: { totalAmount: true },
            }),
        ]);

        return {
            totalReceivables: totalReceivables._sum.amountDue?.toString() || '0',
            overdueCount,
            byStatus: statusCounts.map((s) => ({
                status: s.status,
                count: s._count.id,
                totalAmount: s._sum.totalAmount?.toString() || '0',
            })),
        };
    }

    async getCustomerOutstanding(workspaceId: string) {
        const results = await this.prisma.invoice.groupBy({
            by: ['customerId'],
            where: {
                workspaceId,
                status: {
                    in: [InvoiceStatus.SENT, InvoiceStatus.PARTIALLY_PAID, InvoiceStatus.OVERDUE],
                },
            },
            _sum: { amountDue: true },
            _count: { id: true },
        });

        const customerIds = results.map((r) => r.customerId);
        const customers = await this.prisma.contact.findMany({
            where: { id: { in: customerIds } },
            select: { id: true, name: true, email: true },
        });
        const customerMap = new Map(customers.map((c) => [c.id, c]));

        return results.map((r) => ({
            customer: customerMap.get(r.customerId) || { id: r.customerId, name: 'Unknown' },
            outstandingAmount: r._sum.amountDue?.toString() || '0',
            invoiceCount: r._count.id,
        }));
    }

    // ═══════════════════════════════════════════════════════
    // ─── Invoice Settings ──────────────────────────────────
    // ═══════════════════════════════════════════════════════

    async designAccess(workspaceId: string) {
        const workspace = await this.prisma.workspace.findUnique({ where: { id: workspaceId } });
        if (!workspace || !workspace.isActive) throw new NotFoundError('Workspace');
        const { plan } = await planOf(this.prisma, workspace.ownerId);
        return invoiceDesignAccess(config.NODE_ENV, config.INVOICE_SUBSCRIPTIONS_ACTIVE, plan);
    }

    async getSettings(workspaceId: string) {
        const access = await this.designAccess(workspaceId);
        await this.prisma.invoiceSettings.createMany({
            data: [{ workspaceId }],
            skipDuplicates: true,
        });
        const settings = await this.prisma.invoiceSettings.findUniqueOrThrow({
            where: { workspaceId },
        });
        return { ...this.withLogoUrl(settings), access, templates: invoiceTemplates };
    }

    private async assertDesignAccess(
        workspaceId: string,
        dto: UpdateInvoiceSettingsDto,
        current: InvoiceSettings,
    ) {
        const access = await this.designAccess(workspaceId);
        if (
            dto.template &&
            dto.template !== current.template &&
            invoiceTemplate(dto.template).tier === 'premium' &&
            !access.premiumTemplatesAllowed
        ) {
            throw new AppError(
                'A paid workspace-owner plan is required to select this premium template.',
                403,
                'PREMIUM_TEMPLATE_REQUIRED',
            );
        }
        if (
            dto.customization &&
            JSON.stringify(dto.customization) !== JSON.stringify(current.customization) &&
            !access.customizationAllowed
        ) {
            throw new AppError(
                access.subscriptionsActive
                    ? 'A paid workspace-owner plan is required for advanced customization.'
                    : 'Advanced customization becomes available when subscriptions launch.',
                403,
                'INVOICE_CUSTOMIZATION_LOCKED',
            );
        }
    }

    async previewDocument(workspaceId: string, dto: UpdateInvoiceSettingsDto = {}) {
        const settings = await this.getSettings(workspaceId);
        await this.assertDesignAccess(workspaceId, dto, settings);
        const [workspace, profile] = await Promise.all([
            this.prisma.workspace.findUniqueOrThrow({ where: { id: workspaceId } }),
            this.prisma.workspaceProfile.findUnique({ where: { workspaceId } }),
        ]);
        const appearance = { ...settings, ...dto } as InvoiceSettings;
        return sampleInvoiceDocument(
            appearance,
            workspace.name,
            profile,
            workspace.defaultCurrency,
        );
    }

    async draftDocument(workspaceId: string, dto: CreateInvoiceDto) {
        const [settings, workspace, profile, customer] = await Promise.all([
            this.repository.getInvoiceSettings(workspaceId),
            this.prisma.workspace.findUniqueOrThrow({ where: { id: workspaceId } }),
            this.prisma.workspaceProfile.findUnique({ where: { workspaceId } }),
            this.prisma.contact.findFirst({
                where: { id: dto.customerId, workspaceId, type: 'CUSTOMER' },
                include: { customerProfile: true },
            }),
        ]);
        if (!customer) throw new NotFoundError('Customer');
        assertSameCurrency(workspace.defaultCurrency, dto.currency, 'workspace vs invoice');
        if (new Date(dto.dueDate) < new Date(dto.issueDate))
            throw new AppError(
                'Due date must be on or after the issue date',
                400,
                'INVALID_DUE_DATE',
            );
        const totals = await this.calculateInvoiceTotals(
            workspaceId,
            dto.items,
            dto.discountAmount,
            workspace.defaultCurrency,
        );
        if (totals.totalAmount.lessThan(0))
            throw new AppError('Invoice total cannot be negative', 400, 'NEGATIVE_TOTAL');
        return buildInvoiceDocument(
            {
                ...totals,
                invoiceNumber: dto.invoiceNumber || 'DRAFT',
                status: 'DRAFT',
                issueDate: new Date(dto.issueDate),
                dueDate: new Date(dto.dueDate),
                currency: workspace.defaultCurrency,
                customer,
                amountPaid: new Decimal(0),
                billToSnapshot: null,
                notes: dto.notes ?? settings?.defaultNotes ?? null,
                footer: dto.footer ?? settings?.defaultFooter ?? null,
                paymentTerms: dto.paymentTerms ?? settings?.defaultTerms ?? null,
            } as Parameters<typeof buildInvoiceDocument>[0],
            settings,
            workspace.name,
            profile,
        );
    }

    async invoiceDocument(invoiceId: string, workspaceId: string) {
        const invoice = await this.getInvoice(invoiceId, workspaceId);
        const [settings, workspace, profile] = await Promise.all([
            this.repository.getInvoiceSettings(workspaceId),
            this.prisma.workspace.findUniqueOrThrow({ where: { id: workspaceId } }),
            this.prisma.workspaceProfile.findUnique({ where: { workspaceId } }),
        ]);
        return buildInvoiceDocument(invoice, settings, workspace.name, profile);
    }

    async invoicePdf(invoiceId: string, workspaceId: string) {
        const document = await this.invoiceDocument(invoiceId, workspaceId);
        const settings = await this.repository.getInvoiceSettings(workspaceId);
        return renderInvoicePdf(document, settings?.logoKey);
    }

    async previewPdf(workspaceId: string, dto: UpdateInvoiceSettingsDto) {
        const document = await this.previewDocument(workspaceId, dto);
        const settings = await this.repository.getInvoiceSettings(workspaceId);
        return renderInvoicePdf(document, settings?.logoKey);
    }

    /**
     * The stored object behind a public logo URL.
     *
     * The requested name has to be the logo that workspace references right
     * now, so an old file name stops resolving as soon as the logo changes.
     */
    async resolveLogoKey(file: string): Promise<string> {
        if (!LOGO_FILE_PATTERN.test(file)) throw new NotFoundError('Logo');

        const settings = await this.prisma.invoiceSettings.findFirst({
            where: { workspaceId: file.slice(0, 36), logoKey: `${LOGO_PREFIX}${file}` },
            select: { logoKey: true },
        });
        if (!settings?.logoKey) throw new NotFoundError('Logo');
        return settings.logoKey;
    }

    async updateSettings(workspaceId: string, userId: string, dto: UpdateInvoiceSettingsDto) {
        await this.getSettings(workspaceId);
        const result = await this.prisma.$transaction(async (tx) => {
            await lockWorkspaceStorage(tx, workspaceId);
            const current = await tx.invoiceSettings.findUniqueOrThrow({ where: { workspaceId } });
            if (dto.version !== undefined && dto.version !== current.version) {
                throw new AppError(
                    'Invoice settings changed in another session. Reload the saved settings before applying your changes.',
                    409,
                    'INVOICE_SETTINGS_CONFLICT',
                );
            }
            await this.assertDesignAccess(workspaceId, dto, current);
            const { logoUrl, version, ...fields } = dto;
            const data: Prisma.InvoiceSettingsUpdateInput = {
                ...fields,
                version: { increment: 1 },
            };
            let orphanedLogoKey: string | null = null;
            if (logoUrl !== undefined && logoUrl !== invoiceLogoUrl(current.logoKey)) {
                if (logoUrl !== null)
                    throw new AppError(
                        'Upload the logo as an image file — linking to an image hosted elsewhere is not supported.',
                        400,
                        'LOGO_URL_NOT_ALLOWED',
                    );
                data.logoKey = null;
                data.logoSize = null;
                orphanedLogoKey = current.logoKey;
            }
            const settings = await tx.invoiceSettings.update({ where: { workspaceId }, data });
            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.INVOICE_SETTINGS_UPDATED,
                    resource: 'invoice_settings',
                    resourceId: settings.id,
                },
            });
            return { settings, orphanedLogoKey };
        });
        if (result.orphanedLogoKey) await this.deleteLogoObject(result.orphanedLogoKey);
        return {
            ...this.withLogoUrl(result.settings),
            access: await this.designAccess(workspaceId),
            templates: invoiceTemplates,
        };
    }

    async uploadLogo(workspaceId: string, userId: string, file: Express.Multer.File) {
        // 1. Process image via Sharp: Resize if huge, compress layout, convert explicitly to PNG
        const processedBuffer = await sharp(file.buffer)
            .resize({ width: 800, height: 800, fit: 'inside', withoutEnlargement: true })
            .png({ quality: 85, compressionLevel: 9 })
            .toBuffer();
        const logoSize = processedBuffer.length;

        // 2. Refuse before storing anything if it cannot fit. Replacing a logo
        //    frees the old one, so only the difference has to.
        const before = await this.prisma.invoiceSettings.findUnique({
            where: { workspaceId },
            select: { logoSize: true },
        });
        await assertStorageAvailable(this.prisma, workspaceId, logoSize, before?.logoSize ?? 0);

        // 3. Store it, in the same object store as every other uploaded file.
        const fileName = logoObjectKey(workspaceId);
        await this.storage.uploadBuffer(fileName, processedBuffer, 'image/png');

        // 4. Record it under the workspace's storage lock, re-checking the
        //    allowance so two uploads racing each other cannot both squeeze in.
        let result: { settings: InvoiceSettings; previousKey: string | null };
        try {
            result = await this.prisma.$transaction(async (tx) => {
                await lockWorkspaceStorage(tx, workspaceId);
                const current = await tx.invoiceSettings.findUnique({
                    where: { workspaceId },
                    select: { logoKey: true, logoSize: true },
                });
                await assertStorageAvailable(tx, workspaceId, logoSize, current?.logoSize ?? 0);

                const settings = await tx.invoiceSettings.upsert({
                    where: { workspaceId },
                    create: { workspaceId, logoKey: fileName, logoSize },
                    update: { logoKey: fileName, logoSize },
                });
                return { settings, previousKey: current?.logoKey ?? null };
            });
        } catch (error) {
            await this.deleteLogoObject(fileName);
            throw error;
        }

        // 5. The logo it replaced is referenced by nothing now. Without this,
        //    every change left another file behind in the bucket.
        if (result.previousKey && result.previousKey !== fileName) {
            await this.deleteLogoObject(result.previousKey);
        }

        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.INVOICE_SETTINGS_UPDATED,
                resource: 'invoice_settings',
                resourceId: result.settings.id,
            },
        });

        return this.withLogoUrl(result.settings);
    }

    /** Best-effort: a failed delete leaves an orphaned file, never a failed save. */
    private async deleteLogoObject(key: string) {
        try {
            await this.storage.deleteObject(key);
        } catch (error) {
            logger.error('Could not delete a logo from storage', {
                key,
                error: error instanceof Error ? error.message : error,
            });
        }
    }

    // ═══════════════════════════════════════════════════════
    // ─── Payment Sync (called from Entries hook) ───────────
    // ═══════════════════════════════════════════════════════

    /**
     * Called after an Entry payment is applied/reversed on an obligation that references an invoice.
     * Updates the invoice's amount_paid, amount_due, and status.
     * Must run inside the caller's Prisma transaction.
     */
    static async syncInvoicePayment(
        tx: any,
        obligationReferenceId: string,
        newOutstanding: Decimal,
    ) {
        const { invoiceStatusFromOutstanding } = await import('../../core/finance');

        const invoice = await tx.invoice.findUnique({ where: { id: obligationReferenceId } });
        if (!invoice) return;

        const totalAmount = new Decimal(invoice.totalAmount);
        const amountPaid = totalAmount.sub(newOutstanding);
        const amountDue = newOutstanding.lessThan(0) ? new Decimal(0) : newOutstanding;

        const newStatus = invoiceStatusFromOutstanding(
            totalAmount,
            amountDue,
            invoice.status,
        ) as InvoiceStatus;

        await tx.invoice.update({
            where: { id: obligationReferenceId },
            data: {
                amountPaid: amountPaid.lessThan(0) ? totalAmount : amountPaid,
                amountDue,
                status: newStatus,
            },
        });
    }

    /**
     * Sync invoice paid/due/status from a (possibly invoice-linked) obligation.
     * Safe no-op when the obligation is not linked to an invoice.
     */
    static async syncInvoiceFromObligation(
        tx: any,
        obligation: {
            referenceType?: string | null;
            referenceId?: string | null;
            outstandingAmount: Decimal;
        },
    ) {
        if (obligation.referenceType !== 'INVOICE' || !obligation.referenceId) return;
        await InvoicingService.syncInvoicePayment(
            tx,
            obligation.referenceId,
            new Decimal(obligation.outstandingAmount),
        );
    }

    // ═══════════════════════════════════════════════════════
    // ─── Private Helpers ───────────────────────────────────
    // ═══════════════════════════════════════════════════════

    /**
     * Calculate all invoice totals server-side using Decimal.js precision.
     *
     * Also auto-resolves inventoryItemId from the linked ProductService so that
     * sendInvoice can reliably determine which physical stock item to decrement
     * without any fragile name-matching.
     *
     * Enforces hard currency match (no FX) for products and inventory items.
     * Validates commercial mode for SALE vs RENTAL lines.
     */
    private async calculateInvoiceTotals(
        workspaceId: string,
        items: Array<{
            productServiceId?: string;
            inventoryItemId?: string;
            lineType?: 'SALE' | 'RENTAL';
            name: string;
            description?: string;
            quantity: string;
            unitPrice: string;
            taxId?: string;
            rentalStart?: string;
            rentalEnd?: string;
            rentalPeriodUnit?: 'DAY' | 'WEEK' | 'MONTH';
            rentalPeriodCount?: number;
        }>,
        discountAmountStr?: string,
        invoiceCurrency = 'UGX',
    ): Promise<{
        items: CalculatedItem[];
        subtotal: Decimal;
        taxAmount: Decimal;
        discountAmount: Decimal;
        totalAmount: Decimal;
        amountDue: Decimal;
    }> {
        const currency = normalizeCurrency(invoiceCurrency);
        let subtotal = new Decimal(0);
        const discountAmount = discountAmountStr ? new Decimal(discountAmountStr) : new Decimal(0);
        const calculatedItems: CalculatedItem[] = [];

        for (const item of items) {
            const lineType = item.lineType || 'SALE';
            const qty = new Decimal(item.quantity);
            const price = new Decimal(item.unitPrice);
            const periodCount = lineType === 'RENTAL' ? (item.rentalPeriodCount ?? 1) : 1;
            // Rental line total = rate × qty × periods; sale = rate × qty
            const lineTotal = qty.mul(price).mul(periodCount);

            let taxRate = new Decimal(0);
            let taxAmount = new Decimal(0);
            let taxId: string | undefined;

            if (item.taxId) {
                const tax = await this.prisma.tax.findUnique({ where: { id: item.taxId } });
                if (!tax || tax.workspaceId !== workspaceId || !tax.isActive)
                    throw new AppError(
                        `Tax is unavailable for line "${item.name}"`,
                        400,
                        'INVALID_TAX',
                    );
                if (tax) {
                    taxRate = new Decimal(tax.rate);
                    taxId = tax.id;
                    taxAmount = tax.isCompound ? new Decimal(0) : lineTotal.mul(taxRate).div(100);
                }
            }

            // ── Resolve inventoryItemId ───────────────────────────────
            let resolvedInventoryItemId: string | undefined = item.inventoryItemId;
            let productCurrency: string | null = null;

            if (item.productServiceId) {
                const ps = await this.prisma.productService.findUnique({
                    where: { id: item.productServiceId },
                    select: {
                        inventoryItemId: true,
                        workspaceId: true,
                        currency: true,
                        isActive: true,
                        name: true,
                    },
                });
                if (!ps || ps.workspaceId !== workspaceId || !ps.isActive) {
                    throw new AppError(
                        `Product/service not found for line "${item.name}"`,
                        400,
                        'INVALID_PRODUCT',
                    );
                }
                assertSameCurrency(currency, ps.currency, `product "${ps.name}"`);
                productCurrency = ps.currency;
                if (!resolvedInventoryItemId && ps.inventoryItemId) {
                    resolvedInventoryItemId = ps.inventoryItemId;
                }
            }

            if (resolvedInventoryItemId) {
                const inv = await this.prisma.inventoryItem.findUnique({
                    where: { id: resolvedInventoryItemId },
                    select: {
                        id: true,
                        workspaceId: true,
                        isActive: true,
                        currency: true,
                        commercialMode: true,
                        name: true,
                        stock: { select: { quantityOnHand: true, quantityRentedOut: true } },
                    },
                });
                if (!inv || inv.workspaceId !== workspaceId || !inv.isActive) {
                    throw new AppError(
                        `Inventory item not found for line "${item.name}"`,
                        404,
                        'INVALID_INVENTORY_ITEM',
                    );
                }
                assertSameCurrency(currency, inv.currency, `inventory item "${inv.name}"`);

                if (lineType === 'SALE') {
                    if (inv.commercialMode === 'RENT_ONLY') {
                        throw new AppError(
                            `Item "${inv.name}" is rent-only and cannot be sold on invoices`,
                            400,
                            'ITEM_NOT_SELLABLE',
                        );
                    }
                } else {
                    if (inv.commercialMode === 'SELL_ONLY') {
                        throw new AppError(
                            `Item "${inv.name}" is sell-only and cannot be rented`,
                            400,
                            'ITEM_NOT_RENTABLE',
                        );
                    }
                    const onHand = inv.stock?.quantityOnHand ?? 0;
                    const qtyInt = Math.round(Number(item.quantity));
                    if (qtyInt > onHand) {
                        throw new AppError(
                            `Insufficient rentable stock for "${inv.name}". Available: ${onHand}, requested: ${qtyInt}`,
                            400,
                            'INSUFFICIENT_RENTABLE_STOCK',
                        );
                    }
                }
            } else if (lineType === 'RENTAL') {
                throw new AppError(
                    `Rental line "${item.name}" must be linked to an inventory item`,
                    400,
                    'RENTAL_REQUIRES_INVENTORY',
                );
            }

            // Silence unused (productCurrency reserved for future mixed-currency reporting)
            void productCurrency;

            subtotal = subtotal.add(lineTotal);

            calculatedItems.push({
                productServiceId: item.productServiceId,
                inventoryItemId: resolvedInventoryItemId,
                lineType,
                name: item.name,
                description: item.description,
                quantity: qty,
                unitPrice: price,
                taxId,
                taxRate,
                taxAmount,
                total: lineTotal.add(taxAmount),
                rentalStart: item.rentalStart ? new Date(item.rentalStart) : null,
                rentalEnd: item.rentalEnd ? new Date(item.rentalEnd) : null,
                rentalPeriodUnit: item.rentalPeriodUnit || null,
                rentalPeriodCount: lineType === 'RENTAL' ? periodCount : null,
            });
        }

        // Second pass: resolve compound taxes
        const nonCompoundTax = calculatedItems.reduce(
            (sum, i) => sum.add(i.taxAmount),
            new Decimal(0),
        );
        for (const calcItem of calculatedItems) {
            if (calcItem.taxId) {
                const tax = await this.prisma.tax.findUnique({ where: { id: calcItem.taxId } });
                if (tax && tax.isCompound) {
                    const periodMul =
                        calcItem.lineType === 'RENTAL' ? (calcItem.rentalPeriodCount ?? 1) : 1;
                    const base = calcItem.quantity
                        .mul(calcItem.unitPrice)
                        .mul(periodMul)
                        .add(nonCompoundTax);
                    calcItem.taxAmount = base.mul(calcItem.taxRate).div(100);
                    calcItem.total = calcItem.quantity
                        .mul(calcItem.unitPrice)
                        .mul(periodMul)
                        .add(calcItem.taxAmount);
                }
            }
        }

        const totalTax = calculatedItems.reduce((sum, i) => sum.add(i.taxAmount), new Decimal(0));
        const totalAmount = subtotal.sub(discountAmount).add(totalTax);

        return {
            items: calculatedItems,
            subtotal,
            taxAmount: totalTax,
            discountAmount,
            totalAmount,
            amountDue: totalAmount,
        };
    }

    /**
     * Reverse inventory stock-outs when an invoice is voided.
     *
     * Uses processStockIn (RETURN_IN) instead of raw stock increments so that:
     * - WAC average cost is recalculated correctly
     * - A new lot is created for FIFO/LIFO items at the same unit cost as the original sale
     * This preserves full audit trail integrity.
     */
    private async reverseInvoiceInventory(
        tx: any,
        invoice: any,
        workspaceId: string,
        userId: string,
    ) {
        // Only reverse if this invoice was ever sent (stock-out happened on SENT transition)
        if (
            invoice.status !== InvoiceStatus.SENT &&
            invoice.status !== InvoiceStatus.OVERDUE &&
            invoice.status !== InvoiceStatus.PARTIALLY_PAID
        ) {
            return;
        }

        // Reverse SALE stock-outs
        const saleTxs = await tx.inventoryTransaction.findMany({
            where: {
                referenceType: InventoryReferenceType.INVOICE,
                referenceId: invoice.id,
                transactionType: InventoryTransactionType.SALE,
            },
        });

        for (const t of saleTxs) {
            const qty = Math.abs(Number(t.quantity));
            if (qty <= 0) continue;

            await this.inventoryService.processStockIn(
                workspaceId,
                t.itemId,
                InventoryTransactionType.RETURN_IN,
                qty,
                new Decimal(t.unitCost),
                userId,
                InventoryReferenceType.INVOICE,
                invoice.id,
                `Inventory reversal for voided invoice ${invoice.invoiceNumber}`,
                tx,
            );
        }

        // Reverse RENTAL_OUT as RENTAL_IN and mark rentals cancelled
        const rentalOutTxs = await tx.inventoryTransaction.findMany({
            where: {
                referenceType: InventoryReferenceType.INVOICE,
                referenceId: invoice.id,
                transactionType: InventoryTransactionType.RENTAL_OUT,
            },
        });

        for (const t of rentalOutTxs) {
            const qty = Math.abs(Number(t.quantity));
            if (qty <= 0) continue;

            await this.inventoryService.processStockIn(
                workspaceId,
                t.itemId,
                InventoryTransactionType.RENTAL_IN,
                qty,
                new Decimal(0),
                userId,
                InventoryReferenceType.INVOICE,
                invoice.id,
                `Rental return for voided invoice ${invoice.invoiceNumber}`,
                tx,
            );
        }

        await tx.inventoryRental.updateMany({
            where: { invoiceId: invoice.id, status: { in: ['ACTIVE', 'OVERDUE', 'DRAFT'] as any } },
            data: { status: 'CANCELLED' as any, returnedAt: new Date() },
        });
    }
}

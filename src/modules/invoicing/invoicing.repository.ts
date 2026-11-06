import { injectable, inject } from 'tsyringe';
import { PrismaClient, InvoiceStatus } from '@prisma/client';

@injectable()
export class InvoicingRepository {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) {}

    async findByWorkspace(
        workspaceId: string,
        options: {
            skip: number;
            take: number;
            status?: InvoiceStatus;
            customerId?: string;
            startDate?: string;
            endDate?: string;
            sortBy: string;
            sortOrder: 'asc' | 'desc';
        },
    ) {
        const where: any = { workspaceId };
        if (options.status) where.status = options.status;
        if (options.customerId) where.customerId = options.customerId;
        if (options.startDate || options.endDate) {
            where.issueDate = {};
            if (options.startDate) where.issueDate.gte = new Date(options.startDate);
            if (options.endDate) where.issueDate.lte = new Date(options.endDate);
        }

        const [invoices, total] = await Promise.all([
            this.prisma.invoice.findMany({
                where,
                skip: options.skip,
                take: options.take,
                orderBy: { [options.sortBy]: options.sortOrder },
                include: {
                    customer: {
                        select: { id: true, name: true, email: true, phone: true, company: true },
                    },
                    _count: { select: { items: true } },
                },
            }),
            this.prisma.invoice.count({ where }),
        ]);

        return { invoices, total };
    }

    async findById(id: string) {
        return this.prisma.invoice.findUnique({
            where: { id },
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
                        productService: {
                            select: { id: true, name: true, type: true, inventoryItemId: true },
                        },
                        inventoryItem: { select: { name: true, sku: true, unit: true } },
                        tax: { select: { id: true, name: true, rate: true } },
                    },
                    orderBy: [{ position: 'asc' }, { id: 'asc' }],
                },
            },
        });
    }

    async getNextInvoiceNumber(workspaceId: string): Promise<string> {
        const lastInvoice = await this.prisma.invoice.findFirst({
            where: { workspaceId },
            orderBy: { createdAt: 'desc' },
            select: { invoiceNumber: true },
        });

        if (!lastInvoice) return 'INV-0001';

        // Try to extract numeric part and increment
        const match = lastInvoice.invoiceNumber.match(/(\d+)$/);
        if (match) {
            const num = parseInt(match[1], 10) + 1;
            const prefix = lastInvoice.invoiceNumber.replace(/\d+$/, '');
            return `${prefix}${String(num).padStart(match[1].length, '0')}`;
        }

        // Fallback: append timestamp
        return `INV-${Date.now()}`;
    }

    async findOverdueInvoices(workspaceId: string) {
        return this.prisma.invoice.findMany({
            where: {
                workspaceId,
                status: { in: [InvoiceStatus.SENT, InvoiceStatus.PARTIALLY_PAID] },
                dueDate: { lt: new Date() },
            },
            include: {
                customer: { select: { id: true, name: true, email: true } },
            },
            orderBy: { dueDate: 'asc' },
        });
    }

    async getInvoiceSettings(workspaceId: string) {
        return this.prisma.invoiceSettings.findUnique({
            where: { workspaceId },
        });
    }
}

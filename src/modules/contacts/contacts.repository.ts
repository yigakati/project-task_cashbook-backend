import { injectable, inject } from 'tsyringe';
import { PrismaClient, ContactType } from '@prisma/client';

@injectable()
export class ContactsRepository {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    async findByWorkspaceId(workspaceId: string, type?: string) {
        const where: any = { workspaceId, isActive: true };
        if (type) where.type = type;
        const contacts = await this.prisma.contact.findMany({
            where,
            orderBy: { name: 'asc' },
            include: { customerProfile: true },
        });

        /*
         * Resolve the linked platform account at read time. Only auto-created
         * contacts (peer links, staff claims, rental agreements) carry userId
         * from creation; a customer created normally — even when their email
         * matches a platform user — has none, and features like rental
         * contracts would wrongly treat them as accountless. Matching by the
         * email the workspace itself recorded keeps the link honest without
         * mutating rows behind the user's back.
         */
        const unlinked = contacts.filter((c) => !c.userId && c.email);
        if (unlinked.length > 0) {
            const emails = unlinked.map((c) => c.email!.toLowerCase());
            const users = await this.prisma.user.findMany({
                where: { email: { in: emails } },
                select: { id: true, email: true, isActive: true },
            });
            const byEmail = new Map(users.map((u) => [u.email.toLowerCase(), u]));
            for (const contact of unlinked) {
                const user = byEmail.get(contact.email!.toLowerCase());
                // Inactive accounts can't accept anything — they don't count.
                if (user && user.isActive) {
                    (contact as any).userId = user.id;
                }
            }
        }

        return contacts;
    }

    async findById(id: string) {
        return this.prisma.contact.findUnique({
            where: { id },
            include: { customerProfile: true },
        });
    }

    async create(data: {
        workspaceId: string;
        name: string;
        email?: string;
        phone?: string;
        company?: string;
        notes?: string;
        type?: ContactType;
    }) {
        return this.prisma.contact.create({
            data,
            include: { customerProfile: true },
        });
    }

    async update(id: string, data: {
        name?: string;
        email?: string;
        phone?: string;
        company?: string;
        notes?: string;
        type?: ContactType;
    }) {
        return this.prisma.contact.update({
            where: { id },
            data,
            include: { customerProfile: true },
        });
    }

    async softDelete(id: string) {
        return this.prisma.contact.update({ where: { id }, data: { isActive: false } });
    }

    // ─── Customer Profile ──────────────────────────────

    async findCustomerProfile(contactId: string) {
        return this.prisma.customerProfile.findUnique({ where: { contactId } });
    }

    async createCustomerProfile(contactId: string, data: {
        billingAddress?: any;
        shippingAddress?: any;
        currency?: string;
        accountNumber?: string;
        taxId?: string;
        notes?: string;
    }) {
        return this.prisma.customerProfile.create({
            data: { contactId, ...data },
        });
    }

    async updateCustomerProfile(contactId: string, data: {
        billingAddress?: any;
        shippingAddress?: any;
        currency?: string | null;
        accountNumber?: string | null;
        taxId?: string | null;
        notes?: string | null;
    }) {
        return this.prisma.customerProfile.update({
            where: { contactId },
            data,
        });
    }
}

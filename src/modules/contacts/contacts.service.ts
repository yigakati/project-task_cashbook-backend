import { injectable, inject } from 'tsyringe';
import { PrismaClient, ContactType } from '@prisma/client';
import { ContactsRepository } from './contacts.repository';
import { AppError, NotFoundError } from '../../core/errors/AppError';
import { assertManualContactsEnabled } from '../platform/platform-settings.service';
import { AuditAction } from '../../core/types';
import {
    CreateContactDto,
    UpdateContactDto,
    ContactQueryDto,
    CreateCustomerProfileDto,
    UpdateCustomerProfileDto,
} from './contacts.dto';

@injectable()
export class ContactsService {
    constructor(
        private contactsRepository: ContactsRepository,
        @inject('PrismaClient') private prisma: PrismaClient,
    ) { }

    async getContacts(workspaceId: string, query?: ContactQueryDto) {
        return this.contactsRepository.findByWorkspaceId(workspaceId, query?.type);
    }

    async getContact(contactId: string, workspaceId: string) {
        const contact = await this.contactsRepository.findById(contactId);
        // Enforce workspace ownership — never expose contacts from another workspace
        if (!contact || !contact.isActive || contact.workspaceId !== workspaceId) {
            throw new NotFoundError('Contact');
        }
        return contact;
    }

    async createContact(workspaceId: string, userId: string, dto: CreateContactDto) {
        await assertManualContactsEnabled(this.prisma);

        const contact = await this.contactsRepository.create({
            workspaceId,
            ...dto,
            type: (dto.type as ContactType) || ContactType.PERSONAL,
        });
        await this.prisma.auditLog.create({
            data: { userId, workspaceId, action: AuditAction.CONTACT_CREATED, resource: 'contact', resourceId: contact.id, details: { name: dto.name, type: dto.type } as any },
        });
        return contact;
    }

    async updateContact(contactId: string, workspaceId: string, userId: string, dto: UpdateContactDto) {
        const contact = await this.contactsRepository.findById(contactId);
        // Enforce workspace ownership before any mutation
        if (!contact || !contact.isActive || contact.workspaceId !== workspaceId) {
            throw new NotFoundError('Contact');
        }

        if (contact.contactLinkId) {
            /*
             * A connected contact's details belong to the business they
             * describe. They arrived from that workspace's own profile and
             * refresh from it, so editing them here would either be silently
             * reverted by the next sync or, worse, quietly diverge into a
             * private version of somebody else's facts.
             *
             * `type` is the exception, and the only one: whether they are a
             * customer or a vendor is this workspace's own classification of
             * the relationship, not a fact about them.
             */
            const { type, ...ownedByThem } = dto;
            const attempted = Object.keys(ownedByThem).filter(
                (k) => ownedByThem[k as keyof typeof ownedByThem] !== undefined,
            );
            if (attempted.length > 0) {
                throw new AppError(
                    'These details are maintained by the connected business and update automatically. You can still change whether they are a customer or a vendor.',
                    409,
                    'LINKED_CONTACT_READONLY',
                );
            }
            if (type === undefined) return contact;
        } else {
            // An unlinked contact is hand-kept data, so editing it is a manual
            // operation and needs the same grant as creating one.
            await assertManualContactsEnabled(this.prisma);
        }

        const updated = await this.contactsRepository.update(contactId, {
            ...dto,
            type: dto.type ? (dto.type as ContactType) : undefined,
        });
        await this.prisma.auditLog.create({
            data: { userId, workspaceId, action: AuditAction.CONTACT_UPDATED, resource: 'contact', resourceId: contactId, details: dto as any },
        });
        return updated;
    }

    async deleteContact(contactId: string, workspaceId: string, userId: string) {
        const contact = await this.contactsRepository.findById(contactId);
        // Enforce workspace ownership before deletion
        if (!contact || !contact.isActive || contact.workspaceId !== workspaceId) {
            throw new NotFoundError('Contact');
        }

        if (contact.contactLinkId) {
            // Deleting a connection behind the other side's back would leave
            // their half pointing at nothing. Disconnecting is the honest
            // action, and it is symmetric.
            throw new AppError(
                'This contact is a connection. Disconnect it instead — you keep the details you already have.',
                409,
                'LINKED_CONTACT_READONLY',
            );
        }

        await assertManualContactsEnabled(this.prisma);

        await this.contactsRepository.softDelete(contactId);
        await this.prisma.auditLog.create({
            data: { userId, workspaceId, action: AuditAction.CONTACT_DELETED, resource: 'contact', resourceId: contactId },
        });
    }

    // ─── Customer Profile ──────────────────────────────

    /**
     * Billing details follow the same rule as the rest of a contact's facts:
     * a connected business maintains its own (tax id, address, and the rest
     * arrive from their profile and refresh from it), and hand-kept contacts
     * need manual entry to be switched on.
     */
    private async assertBillingEditable(contact: { contactLinkId: string | null }) {
        if (contact.contactLinkId) {
            throw new AppError(
                'Billing details for a connected business are maintained by them and update automatically.',
                409,
                'LINKED_CONTACT_READONLY',
            );
        }
        await assertManualContactsEnabled(this.prisma);
    }

    async createCustomerProfile(contactId: string, workspaceId: string, userId: string, dto: CreateCustomerProfileDto) {
        const contact = await this.contactsRepository.findById(contactId);
        // ── THE REPORTED BUG ─────────────────────────────────────────────────────
        // Without this check any caller with a valid contactId from a different
        // workspace could create a customer profile on that foreign contact.
        if (!contact || !contact.isActive || contact.workspaceId !== workspaceId) {
            throw new NotFoundError('Contact');
        }

        await this.assertBillingEditable(contact);

        // Auto-promote contact to CUSTOMER type if not already
        if (contact.type !== ContactType.CUSTOMER) {
            await this.contactsRepository.update(contactId, { type: ContactType.CUSTOMER });
        }

        // Check if profile already exists
        const existing = await this.contactsRepository.findCustomerProfile(contactId);
        if (existing) {
            throw new AppError('Customer profile already exists for this contact', 409, 'PROFILE_EXISTS');
        }

        const profile = await this.contactsRepository.createCustomerProfile(contactId, dto);
        await this.prisma.auditLog.create({
            data: { userId, workspaceId, action: AuditAction.CUSTOMER_PROFILE_CREATED, resource: 'customer_profile', resourceId: profile.id },
        });
        return profile;
    }

    async updateCustomerProfile(contactId: string, workspaceId: string, userId: string, dto: UpdateCustomerProfileDto) {
        const contact = await this.contactsRepository.findById(contactId);
        // Enforce workspace ownership before any mutation
        if (!contact || !contact.isActive || contact.workspaceId !== workspaceId) {
            throw new NotFoundError('Contact');
        }

        await this.assertBillingEditable(contact);

        const existing = await this.contactsRepository.findCustomerProfile(contactId);
        if (!existing) {
            throw new NotFoundError('Customer Profile');
        }

        const updated = await this.contactsRepository.updateCustomerProfile(contactId, dto);
        await this.prisma.auditLog.create({
            data: { userId, workspaceId, action: AuditAction.CUSTOMER_PROFILE_UPDATED, resource: 'customer_profile', resourceId: updated.id },
        });
        return updated;
    }

    async getCustomerProfile(contactId: string, workspaceId: string) {
        const contact = await this.contactsRepository.findById(contactId);
        // Enforce workspace ownership — never expose profiles from another workspace
        if (!contact || !contact.isActive || contact.workspaceId !== workspaceId) {
            throw new NotFoundError('Contact');
        }
        return contact.customerProfile || null;
    }
}

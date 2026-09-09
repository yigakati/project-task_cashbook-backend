import { injectable, inject } from 'tsyringe';
import {
    PrismaClient,
    Prisma,
    ContactType,
    ContactLinkRequestStatus,
    ContactLinkState,
    NotificationType,
    NotificationEntityType,
} from '@prisma/client';
import {
    AppError,
    NotFoundError,
    AuthorizationError,
    ConflictError,
    WorkspaceProfileIncompleteError,
} from '../../core/errors/AppError';
import { AuditAction, WorkspaceRole } from '../../core/types';
import { hasWorkspacePermission, WorkspacePermission } from '../../core/types/workspace-permissions';
import { checkProfileCompleteness } from '../workspace-profile/workspace-profile.dto';
import { ensureWorkspaceProfile } from '../workspace-profile/workspace-profile.helpers';
import { NotificationsService, NotificationJobData } from '../notifications/notifications.service';
import { sendEmail } from '../../config/email';
import { contactInviteSignupEmailTemplate } from '../../utils/emailTemplates';
import { config } from '../../config';
import { logger } from '../../utils/logger';
import {
    AcceptContactLinkRequestDto,
    CreateContactLinkRequestDto,
    DeclineContactLinkRequestDto,
    ContactLinkRequestQueryDto,
} from './contact-links.dto';

/** A request nobody answers should not sit in an inbox forever. */
const REQUEST_TTL_DAYS = 30;

/**
 * The profile fields a linked contact mirrors, and where each one lands on the
 * Contact row. Kept as data rather than inline assignments so the sync and the
 * "did a human edit this?" check can never drift apart.
 */
const CONTACT_FIELD_SOURCES = {
    name: (p: ProfileLike) => p.displayName?.trim() || null,
    email: (p: ProfileLike) => p.email?.trim() || null,
    phone: (p: ProfileLike) => p.phone?.trim() || null,
    company: (p: ProfileLike) => p.legalName?.trim() || p.displayName?.trim() || null,
} as const;

type ContactField = keyof typeof CONTACT_FIELD_SOURCES;

interface ProfileLike {
    displayName: string;
    legalName: string | null;
    email: string | null;
    phone: string | null;
    taxId: string | null;
    addressLine1: string | null;
    addressLine2: string | null;
    city: string | null;
    state: string | null;
    postalCode: string | null;
    country: string | null;
}

/**
 * CUSTOMER and VENDOR are mirror roles, not the same label twice: if they buy
 * from me they are my CUSTOMER, which makes me their VENDOR. Anything else has
 * no meaningful inverse and lands as a plain contact for them to classify.
 */
export function inverseContactType(type: ContactType): ContactType {
    if (type === ContactType.CUSTOMER) return ContactType.VENDOR;
    if (type === ContactType.VENDOR) return ContactType.CUSTOMER;
    return ContactType.PERSONAL;
}

/** Pairs are stored smaller-id-first so (A,B) and (B,A) cannot both exist. */
function canonicalPair(x: string, y: string): { workspaceAId: string; workspaceBId: string } {
    return x < y ? { workspaceAId: x, workspaceBId: y } : { workspaceAId: y, workspaceBId: x };
}

@injectable()
export class ContactLinksService {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    // ─── Lookup ────────────────────────────────────────

    /**
     * Is this person on the platform, and do we already know them?
     *
     * Returns only what the requester is entitled to act on: the person's name
     * (so they can confirm they have the right person before sending), whether
     * a connection already exists, and which of their own contacts this would
     * attach to. No workspace of the recipient is revealed — which org answers
     * is theirs to choose at acceptance.
     */
    async lookupRecipient(workspaceId: string, requesterUserId: string, email: string) {
        const normalized = email.trim().toLowerCase();

        const user = await this.prisma.user.findUnique({
            where: { email: normalized },
            select: { id: true, firstName: true, lastName: true, email: true, isActive: true },
        });

        if (user && user.id === requesterUserId) {
            /*
             * Their own address — the account behind every workspace they own.
             *
             * Connecting to yourself has no meaning: acceptance would have to
             * come from a workspace of the same person, and the canonical-pair
             * check would refuse the link anyway. Answering plainly here is
             * kinder than letting them send a request that can never be
             * accepted.
             */
            return { found: true as const, isSelf: true as const };
        }

        if (!user || !user.isActive) {
            // Not an error: "nobody here" is a normal, actionable answer. It
            // sends the caller to the two things still open to them — invite
            // the address anyway, or type the details in by hand.
            const [pendingInvite, suggestedContact] = await Promise.all([
                this.prisma.contactLinkRequest.findFirst({
                    where: {
                        requesterWorkspaceId: workspaceId,
                        recipientEmail: normalized,
                        status: ContactLinkRequestStatus.PENDING,
                    },
                    select: { id: true, createdAt: true },
                }),
                this.findContactByEmail(workspaceId, normalized),
            ]);

            return {
                found: false as const,
                pendingRequest: pendingInvite,
                suggestedContact,
            };
        }

        const [pending, activeLink, suggestedContact] = await Promise.all([
            this.prisma.contactLinkRequest.findFirst({
                where: {
                    requesterWorkspaceId: workspaceId,
                    // Keyed on the address, not the account: an invite sent
                    // before they signed up is still the same request.
                    recipientEmail: normalized,
                    status: ContactLinkRequestStatus.PENDING,
                },
                select: { id: true, createdAt: true },
            }),
            this.findActiveLinkWithUser(workspaceId, user.id),
            this.findContactByEmail(workspaceId, normalized),
        ]);

        return {
            found: true as const,
            isSelf: false as const,
            user: {
                id: user.id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
            },
            pendingRequest: pending,
            alreadyConnected: Boolean(activeLink),
            connectedContactId: activeLink?.contactId ?? null,
            suggestedContact,
        };
    }

    // ─── Requesting ────────────────────────────────────

    async createRequest(
        workspaceId: string,
        requesterUserId: string,
        dto: CreateContactLinkRequestDto,
    ) {
        const normalized = dto.email.trim().toLowerCase();

        // An invite does not require an account. Someone who has never heard
        // of the app is exactly who this reaches: the request is filed against
        // their address, emailed to them, and waits. Signing up later is what
        // hands it to them to accept or decline, like any other.
        const recipient = await this.prisma.user.findUnique({
            where: { email: normalized },
            select: { id: true, firstName: true, isActive: true },
        });

        // A deactivated account is a dead end — the address cannot be invited
        // to sign up either, because it is already taken.
        if (recipient && !recipient.isActive) {
            throw new NotFoundError('No active user found with that email');
        }

        // Their own address. Checked here and not only in the UI: a request to
        // yourself could never be accepted (the workspace pair would be the
        // same person's, and a link needs two distinct workspaces), so it
        // would sit pending forever rather than fail honestly.
        if (recipient && recipient.id === requesterUserId) {
            throw new AppError(
                'That is your own account. You cannot invite yourself as a contact.',
                400,
                'SELF_REQUEST',
            );
        }

        if (recipient) {
            const existingLink = await this.findActiveLinkWithUser(workspaceId, recipient.id);
            if (existingLink) {
                throw new ConflictError('You are already connected to this person');
            }
        }

        // Resolve what this connection should attach to, so an org that was
        // already recorded by hand keeps its entries and invoices rather than
        // gaining a second row beside them.
        const targetContact = dto.contactId
            ? await this.assertLinkableContact(workspaceId, dto.contactId)
            : await this.findContactByEmail(workspaceId, normalized);

        const expiresAt = new Date(Date.now() + REQUEST_TTL_DAYS * 24 * 60 * 60 * 1000);

        let request;
        try {
            request = await this.prisma.contactLinkRequest.create({
                data: {
                    requesterUserId,
                    requesterWorkspaceId: workspaceId,
                    requestedType: dto.requestedType as ContactType,
                    requesterContactId: targetContact?.id ?? null,
                    recipientEmail: normalized,
                    recipientUserId: recipient?.id ?? null,
                    message: dto.message,
                    expiresAt,
                },
            });
        } catch (error) {
            // The partial unique index on (requester_workspace_id,
            // recipient_email) WHERE status = 'PENDING' is what actually stops
            // a double-send; this only turns it into a sentence.
            if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
                throw new ConflictError('You already have a pending request to this address');
            }
            throw error;
        }

        const workspace = await this.prisma.workspace.findUniqueOrThrow({
            where: { id: workspaceId },
            select: { name: true, profile: { select: { displayName: true } } },
        });
        const senderName = workspace.profile?.displayName || workspace.name;

        await this.prisma.auditLog.create({
            data: {
                userId: requesterUserId,
                workspaceId,
                action: AuditAction.CONTACT_LINK_REQUESTED,
                resource: 'contact_link_request',
                resourceId: request.id,
                details: {
                    recipientEmail: normalized,
                    recipientUserId: recipient?.id ?? null,
                    requestedType: dto.requestedType,
                } as any,
            },
        });

        if (!recipient) {
            // Nothing to notify in-app — they have no account to notify into.
            // The email is the whole delivery mechanism for this case.
            sendEmail({
                to: normalized,
                subject: `${senderName} wants to add you as a contact on ${config.APP_NAME}`,
                html: contactInviteSignupEmailTemplate({
                    senderName,
                    message: dto.message?.trim() || null,
                    signupUrl: `${config.APP_URL.replace(/\/+$/, '')}/signup?email=${encodeURIComponent(normalized)}`,
                }),
            }).catch((err) => logger.error('Failed to send contact invite email', { to: normalized, err }));

            return request;
        }

        this.notify({
            userId: recipient.id,
            workspaceId,
            type: NotificationType.CONTACT_LINK_RECEIVED,
            title: `${senderName} wants to connect`,
            body: dto.message?.trim()
                ? dto.message.trim()
                : `${senderName} would like to add you as a contact and share their business details.`,
            entityType: NotificationEntityType.CONTACT_LINK_REQUEST,
            entityId: request.id,
        });

        return request;
    }

    async cancelRequest(workspaceId: string, requestId: string, userId: string) {
        const request = await this.prisma.contactLinkRequest.findUnique({ where: { id: requestId } });
        if (!request || request.requesterWorkspaceId !== workspaceId) {
            throw new NotFoundError('Contact request');
        }
        if (request.status !== ContactLinkRequestStatus.PENDING) {
            throw new AppError(
                `This request is already ${request.status.toLowerCase()}`,
                400,
                'INVALID_STATUS',
            );
        }

        const updated = await this.prisma.contactLinkRequest.updateMany({
            where: { id: requestId, status: ContactLinkRequestStatus.PENDING },
            data: { status: ContactLinkRequestStatus.CANCELLED, respondedAt: new Date() },
        });
        if (updated.count === 0) {
            throw new AppError('This request was already answered', 409, 'INVALID_STATUS');
        }

        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.CONTACT_LINK_CANCELLED,
                resource: 'contact_link_request',
                resourceId: requestId,
            },
        });

        return { id: requestId, status: ContactLinkRequestStatus.CANCELLED };
    }

    // ─── Responding ────────────────────────────────────

    /**
     * The inbox is deliberately keyed on the PERSON, not a workspace.
     *
     * That is what makes "whichever workspace accepts first owns it" fall out
     * for free: the request was never sitting in several workspaces waiting to
     * be cleaned up — it sits with the person, and accepting is what stamps a
     * workspace onto it.
     */
    async getIncoming(userId: string, query: ContactLinkRequestQueryDto) {
        return this.prisma.contactLinkRequest.findMany({
            where: {
                recipientUserId: userId,
                status: query.status
                    ? (query.status as ContactLinkRequestStatus)
                    : ContactLinkRequestStatus.PENDING,
                ...(query.status ? {} : { expiresAt: { gt: new Date() } }),
            },
            orderBy: { createdAt: 'desc' },
            include: {
                requesterWorkspace: {
                    select: {
                        id: true,
                        name: true,
                        type: true,
                        profile: {
                            select: {
                                displayName: true, legalName: true, email: true, phone: true,
                                website: true, city: true, country: true,
                            },
                        },
                    },
                },
                requesterUser: { select: { firstName: true, lastName: true, email: true } },
            },
        });
    }

    async getOutgoing(workspaceId: string, query: ContactLinkRequestQueryDto) {
        return this.prisma.contactLinkRequest.findMany({
            where: {
                requesterWorkspaceId: workspaceId,
                ...(query.status ? { status: query.status as ContactLinkRequestStatus } : {}),
            },
            orderBy: { createdAt: 'desc' },
            include: {
                recipientUser: { select: { id: true, firstName: true, lastName: true, email: true } },
            },
        });
    }

    async acceptRequest(requestId: string, userId: string, dto: AcceptContactLinkRequestDto) {
        const queued: NotificationJobData[] = [];

        const result = await this.prisma.$transaction(async (tx) => {
            const request = await tx.contactLinkRequest.findUnique({ where: { id: requestId } });
            if (!request) throw new NotFoundError('Contact request');
            if (request.recipientUserId !== userId) {
                throw new AuthorizationError('Only the recipient can respond to this request');
            }
            if (request.status !== ContactLinkRequestStatus.PENDING) {
                throw new AppError(
                    `This request is already ${request.status.toLowerCase()}`,
                    400,
                    'INVALID_STATUS',
                );
            }
            if (request.expiresAt.getTime() < Date.now()) {
                throw new AppError('This request has expired', 400, 'REQUEST_EXPIRED');
            }
            if (request.requesterWorkspaceId === dto.workspaceId) {
                throw new AppError('Choose a different workspace from the requester\'s', 400, 'SAME_WORKSPACE');
            }

            await this.assertCanShareWorkspace(tx, dto.workspaceId, userId);

            // Materialise the profile from what is already known — the
            // workspace name, and the owner's account email — before judging
            // it. Most workspaces are therefore shareable without anyone
            // filling in a form; the gate below is left in place for the case
            // where even that is not enough (an owner with no usable email, or
            // details someone deliberately cleared).
            const profile = await ensureWorkspaceProfile(tx, dto.workspaceId);

            const completeness = checkProfileCompleteness(profile);
            if (!completeness.isComplete) {
                throw new WorkspaceProfileIncompleteError(dto.workspaceId, completeness.missing);
            }

            // Same treatment for the requester, so the mirror contact created
            // on the accepter's side is not left blank just because the
            // requester's workspace predates profiles.
            const requesterProfile = await ensureWorkspaceProfile(tx, request.requesterWorkspaceId);

            const recipientType = (dto.type as ContactType | undefined)
                ?? inverseContactType(request.requestedType);

            // Claim the request BEFORE building anything on it. The status
            // filter is the atomic guard: a second accept — from another of
            // this person's workspaces, in a tab opened a minute ago — matches
            // zero rows and surfaces as INVALID_STATUS instead of minting a
            // second link. No lock, no cleanup pass over other workspaces.
            const claimed = await tx.contactLinkRequest.updateMany({
                where: { id: request.id, status: ContactLinkRequestStatus.PENDING },
                data: {
                    status: ContactLinkRequestStatus.ACCEPTED,
                    recipientWorkspaceId: dto.workspaceId,
                    recipientType,
                    respondedAt: new Date(),
                },
            });
            if (claimed.count === 0) {
                throw new AppError('This request was already answered', 409, 'INVALID_STATUS');
            }

            const pair = canonicalPair(request.requesterWorkspaceId, dto.workspaceId);
            const link = await tx.contactLink.upsert({
                where: { workspaceAId_workspaceBId: pair },
                create: { ...pair, requestId: request.id, state: ContactLinkState.ACTIVE },
                update: {
                    state: ContactLinkState.ACTIVE,
                    revokedAt: null,
                    revokedByWorkspaceId: null,
                },
            });

            // Requester's side: their record of the accepter.
            const requesterContact = await this.upsertLinkedContact(tx, {
                workspaceId: request.requesterWorkspaceId,
                linkedWorkspaceId: dto.workspaceId,
                linkId: link.id,
                type: request.requestedType,
                preferredContactId: request.requesterContactId,
                profile,
            });

            // Accepter's side: the mirror, defaulting to the inverse role.
            const recipientContact = await this.upsertLinkedContact(tx, {
                workspaceId: dto.workspaceId,
                linkedWorkspaceId: request.requesterWorkspaceId,
                linkId: link.id,
                type: recipientType,
                preferredContactId: null,
                profile: requesterProfile,
            });

            await tx.auditLog.createMany({
                data: [
                    {
                        userId,
                        workspaceId: dto.workspaceId,
                        action: AuditAction.CONTACT_LINK_ACCEPTED,
                        resource: 'contact_link',
                        resourceId: link.id,
                        details: { requestId: request.id, contactId: recipientContact.id } as any,
                    },
                    {
                        userId,
                        workspaceId: request.requesterWorkspaceId,
                        action: AuditAction.CONTACT_LINK_ACCEPTED,
                        resource: 'contact_link',
                        resourceId: link.id,
                        details: { requestId: request.id, contactId: requesterContact.id } as any,
                    },
                ],
            });

            queued.push({
                userId: request.requesterUserId,
                workspaceId: request.requesterWorkspaceId,
                type: NotificationType.CONTACT_LINK_DECIDED,
                title: `${profile!.displayName} accepted your request`,
                body: `Their contact details are now on ${requesterContact.name}.`,
                entityType: NotificationEntityType.CONTACT_LINK_REQUEST,
                entityId: request.id,
            });

            return { link, requesterContact, recipientContact };
        });

        // Dispatched only once the transaction commits — a notification for a
        // rolled-back acceptance would be a lie the requester acts on.
        for (const job of queued) NotificationsService.dispatch(job);

        return result;
    }

    async declineRequest(requestId: string, userId: string, dto: DeclineContactLinkRequestDto) {
        const request = await this.prisma.contactLinkRequest.findUnique({ where: { id: requestId } });
        if (!request) throw new NotFoundError('Contact request');
        if (request.recipientUserId !== userId) {
            throw new AuthorizationError('Only the recipient can respond to this request');
        }
        if (request.status !== ContactLinkRequestStatus.PENDING) {
            throw new AppError(
                `This request is already ${request.status.toLowerCase()}`,
                400,
                'INVALID_STATUS',
            );
        }

        const claimed = await this.prisma.contactLinkRequest.updateMany({
            where: { id: requestId, status: ContactLinkRequestStatus.PENDING },
            data: {
                status: ContactLinkRequestStatus.DECLINED,
                declinedReason: dto.reason,
                respondedAt: new Date(),
            },
        });
        if (claimed.count === 0) {
            throw new AppError('This request was already answered', 409, 'INVALID_STATUS');
        }

        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId: request.requesterWorkspaceId,
                action: AuditAction.CONTACT_LINK_DECLINED,
                resource: 'contact_link_request',
                resourceId: requestId,
            },
        });

        this.notify({
            userId: request.requesterUserId,
            workspaceId: request.requesterWorkspaceId,
            type: NotificationType.CONTACT_LINK_DECIDED,
            title: 'Contact request declined',
            body: dto.reason?.trim() || 'Your request to connect was declined.',
            entityType: NotificationEntityType.CONTACT_LINK_REQUEST,
            entityId: requestId,
        });

        return { id: requestId, status: ContactLinkRequestStatus.DECLINED };
    }

    // ─── Disconnecting ─────────────────────────────────

    /**
     * Stop sharing, both ways.
     *
     * The details each side already holds stay exactly where they are — they
     * are that workspace's own business records, and invoices and entries
     * point at them — but the rows become ordinary local contacts again and no
     * further updates flow in either direction. Symmetric on purpose: consent
     * withdrawn by one side is not consent the other still has.
     */
    async unlinkContact(workspaceId: string, contactId: string, userId: string) {
        return this.prisma.$transaction(async (tx) => {
            const contact = await tx.contact.findFirst({
                where: { id: contactId, workspaceId },
            });
            if (!contact) throw new NotFoundError('Contact');
            if (!contact.contactLinkId) {
                throw new AppError('This contact is not a connection', 400, 'NOT_LINKED');
            }

            const linkId = contact.contactLinkId;

            await tx.contactLink.update({
                where: { id: linkId },
                data: {
                    state: ContactLinkState.REVOKED,
                    revokedByWorkspaceId: workspaceId,
                    revokedAt: new Date(),
                },
            });

            await tx.contact.updateMany({
                where: { contactLinkId: linkId },
                data: {
                    linkedWorkspaceId: null,
                    contactLinkId: null,
                    linkedSnapshot: Prisma.DbNull,
                    linkedSyncedAt: null,
                },
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.CONTACT_LINK_REVOKED,
                    resource: 'contact_link',
                    resourceId: linkId,
                    details: { contactId } as any,
                },
            });

            return { contactId, linkId, state: ContactLinkState.REVOKED };
        });
    }

    // ─── Propagation ───────────────────────────────────

    /**
     * Push a workspace's edited profile out to everyone who holds it as a
     * contact. Static so the profile service can reach it without the two
     * modules importing each other — the same shape entries.service uses for
     * PeerLinksService.
     */
    static async onProfileUpdated(tx: Prisma.TransactionClient, workspaceId: string) {
        const profile = await tx.workspaceProfile.findUnique({ where: { workspaceId } });
        if (!profile) return;

        const linkedContacts = await tx.contact.findMany({
            where: {
                linkedWorkspaceId: workspaceId,
                contactLink: { state: ContactLinkState.ACTIVE },
            },
        });

        for (const contact of linkedContacts) {
            await applyProfileToContact(tx, contact, profile);
        }
    }

    // ─── Internals ─────────────────────────────────────

    private async upsertLinkedContact(
        tx: Prisma.TransactionClient,
        params: {
            workspaceId: string;
            linkedWorkspaceId: string;
            linkId: string;
            type: ContactType;
            preferredContactId: string | null;
            profile: ProfileLike | null;
        },
    ) {
        const { workspaceId, linkedWorkspaceId, linkId, type, preferredContactId, profile } = params;

        // Already connected to this workspace: that row wins, whatever else
        // was suggested. The unique index guarantees there is at most one.
        let contact = await tx.contact.findFirst({ where: { workspaceId, linkedWorkspaceId } });

        // Then the row the requester picked (or we matched by email) at request
        // time — as long as it is still here and still unattached.
        if (!contact && preferredContactId) {
            contact = await tx.contact.findFirst({
                where: { id: preferredContactId, workspaceId, contactLinkId: null },
            });
        }

        // Then anything already recorded under the same email.
        if (!contact && profile?.email) {
            contact = await tx.contact.findFirst({
                where: {
                    workspaceId,
                    contactLinkId: null,
                    email: { equals: profile.email, mode: 'insensitive' },
                },
            });
        }

        if (!contact) {
            // `name` is non-nullable, so a brand-new row has to be seeded here
            // rather than left for the sync to fill. It is recorded in the
            // snapshot at the same time — otherwise the very next sync would
            // read its own handiwork as something a human typed and stop
            // refreshing the name forever.
            const seededName = profile?.displayName ?? 'Connected contact';
            contact = await tx.contact.create({
                data: {
                    workspaceId,
                    type,
                    name: seededName,
                    linkedWorkspaceId,
                    contactLinkId: linkId,
                    linkedSnapshot: { name: seededName } as Prisma.InputJsonValue,
                },
            });
        } else {
            contact = await tx.contact.update({
                where: { id: contact.id },
                data: { linkedWorkspaceId, contactLinkId: linkId, type },
            });
        }

        if (profile) {
            contact = await applyProfileToContact(tx, contact, profile);
        }

        return contact;
    }

    private async assertCanShareWorkspace(
        tx: Prisma.TransactionClient,
        workspaceId: string,
        userId: string,
    ) {
        const workspace = await tx.workspace.findUnique({
            where: { id: workspaceId },
            select: { id: true, ownerId: true, isActive: true },
        });
        if (!workspace || !workspace.isActive) throw new NotFoundError('Workspace');

        // Owners bypass the membership table, matching the route guards.
        if (workspace.ownerId === userId) return;

        const membership = await tx.workspaceMember.findFirst({
            where: { workspaceId, userId },
            select: { role: true },
        });
        if (!membership) {
            throw new AuthorizationError('You are not a member of that workspace');
        }
        if (!hasWorkspacePermission(membership.role as WorkspaceRole, WorkspacePermission.MANAGE_REFERENCE_DATA)) {
            throw new AuthorizationError('You cannot share contact details for that workspace');
        }
    }

    private async assertLinkableContact(workspaceId: string, contactId: string) {
        const contact = await this.prisma.contact.findFirst({
            where: { id: contactId, workspaceId },
        });
        if (!contact) throw new NotFoundError('Contact');
        if (contact.contactLinkId) {
            throw new ConflictError('That contact is already connected to another workspace');
        }
        return contact;
    }

    private findContactByEmail(workspaceId: string, email: string) {
        return this.prisma.contact.findFirst({
            where: {
                workspaceId,
                contactLinkId: null,
                email: { equals: email, mode: 'insensitive' },
            },
            select: { id: true, name: true, email: true, type: true },
        });
    }

    /** Any ACTIVE link between this workspace and any workspace of that user. */
    private async findActiveLinkWithUser(workspaceId: string, userId: string) {
        const contact = await this.prisma.contact.findFirst({
            where: {
                workspaceId,
                contactLink: { state: ContactLinkState.ACTIVE },
                linkedWorkspace: {
                    OR: [
                        { ownerId: userId },
                        { members: { some: { userId } } },
                    ],
                },
            },
            select: { id: true, contactLinkId: true },
        });
        return contact ? { contactId: contact.id, linkId: contact.contactLinkId } : null;
    }

    private notify(job: NotificationJobData) {
        NotificationsService.dispatch(job);
    }
}

/**
 * Write a counterparty's profile onto the contact that mirrors it, without
 * stepping on anything a person changed by hand.
 *
 * A field is ours to refresh only if we wrote its current value — recorded in
 * `linkedSnapshot` — or if it is empty. Anything else was typed locally and is
 * left exactly as it is, which is what makes linking into an existing
 * hand-built contact safe: on the first sync the snapshot is empty, so only
 * blanks get filled and the name someone chose survives.
 */
async function applyProfileToContact(
    tx: Prisma.TransactionClient,
    contact: {
        id: string;
        name: string;
        email: string | null;
        phone: string | null;
        company: string | null;
        linkedSnapshot: Prisma.JsonValue | null;
    },
    profile: ProfileLike,
) {
    const snapshot = (contact.linkedSnapshot ?? {}) as Record<string, string | null>;
    const data: Record<string, string | null> = {};
    const nextSnapshot: Record<string, string | null> = {};

    for (const field of Object.keys(CONTACT_FIELD_SOURCES) as ContactField[]) {
        const incoming = CONTACT_FIELD_SOURCES[field](profile);
        const current = (contact as Record<string, any>)[field] as string | null;
        const isEmpty = current === null || current === undefined || current === '';
        const weWroteIt = field in snapshot && current === snapshot[field];

        if (isEmpty || weWroteIt) {
            // `name` is non-nullable; never blank it out on a profile that has
            // since dropped the field.
            if (field === 'name' && !incoming) {
                nextSnapshot[field] = snapshot[field] ?? null;
                continue;
            }
            data[field] = incoming;
            nextSnapshot[field] = incoming;
        }
        // Otherwise: a human owns this field now. It is not written, and it is
        // not recorded in the snapshot, so it stays theirs permanently.
    }

    const updated = await tx.contact.update({
        where: { id: contact.id },
        data: {
            ...data,
            linkedSnapshot: nextSnapshot as Prisma.InputJsonValue,
            linkedSyncedAt: new Date(),
        },
    });

    // Billing details ride along on the CustomerProfile that invoices already
    // read, so nothing downstream needs to know a connection exists.
    const billingAddress = buildBillingAddress(profile);
    const hasBilling = profile.taxId || billingAddress;
    if (hasBilling) {
        const existing = await tx.customerProfile.findUnique({ where: { contactId: contact.id } });
        if (!existing) {
            await tx.customerProfile.create({
                data: {
                    contactId: contact.id,
                    taxId: profile.taxId,
                    billingAddress: (billingAddress ?? Prisma.DbNull) as Prisma.InputJsonValue,
                },
            });
        } else {
            await tx.customerProfile.update({
                where: { contactId: contact.id },
                data: {
                    taxId: existing.taxId ?? profile.taxId,
                    billingAddress: (existing.billingAddress ?? billingAddress ?? Prisma.DbNull) as Prisma.InputJsonValue,
                },
            });
        }
    }

    return updated;
}

function buildBillingAddress(profile: ProfileLike) {
    const parts = {
        line1: profile.addressLine1,
        line2: profile.addressLine2,
        city: profile.city,
        state: profile.state,
        postalCode: profile.postalCode,
        country: profile.country,
    };
    return Object.values(parts).some(Boolean) ? parts : null;
}

/**
 * Hand a brand-new account the contact invites already waiting for its address.
 *
 * Someone can be invited before they have ever heard of the app: the request is
 * filed against their email and sits there. This is the moment it becomes
 * theirs — the row gains a `recipientUserId`, which is what puts it in their
 * inbox to accept or decline exactly like a request from an existing user.
 *
 * Expired invites are deliberately left alone: `getIncoming` filters them out,
 * and rewriting them here would only obscure that they were never answered.
 *
 * Runs inside the signup transaction. A failure here would roll back the
 * account itself, which is why it does nothing that can fail on bad data —
 * only a scoped update of rows already keyed on this exact address.
 */
export async function claimPendingContactInvites(
    tx: Prisma.TransactionClient,
    userId: string,
    email: string,
): Promise<number> {
    const { count } = await tx.contactLinkRequest.updateMany({
        where: {
            recipientEmail: email.trim().toLowerCase(),
            recipientUserId: null,
            status: ContactLinkRequestStatus.PENDING,
        },
        data: { recipientUserId: userId },
    });
    return count;
}

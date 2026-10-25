import { Prisma } from '@prisma/client';

/** A connection's signatory is authoritative; never guess an organisation's
 * recipient from a billing email or fan a private payment out to its members. */
export async function entryRecipient(tx: Prisma.TransactionClient, contactId: string, workspaceId: string) {
    const contact = await tx.contact.findFirst({
        where: { id: contactId, workspaceId, isActive: true, type: { not: 'STAFF' } },
        include: { contactLink: { include: { request: true } } },
    });
    if (!contact) return null;
    let userId = contact.userId;
    if (contact.contactLinkId || contact.linkedWorkspaceId) {
        const link = contact.contactLink;
        const request = link?.request;
        if (link?.state !== 'ACTIVE' || !request || request.status !== 'ACCEPTED') return null;
        userId = request.requesterWorkspaceId === workspaceId
            ? request.recipientUserId : request.requesterUserId;
        if (!userId || !contact.linkedWorkspaceId) return null;
        const representedWorkspace = await tx.workspace.findFirst({
            where: {
                id: contact.linkedWorkspaceId, isActive: true,
                OR: [{ ownerId: userId }, { type: 'BUSINESS', members: { some: { userId } } }],
            },
            select: { id: true },
        });
        if (!representedWorkspace) return null;
    }
    // Email-only matching requires a verified address. A name or phone is
    // insufficient, and an unverified signup must not receive financial data.
    const matches = await tx.user.findMany({
        where: {
            isActive: true, deletedAt: null,
            ...(userId ? { id: userId } : {
                email: { equals: contact.email?.trim() || '', mode: 'insensitive' as const },
                emailVerified: true,
            }),
        },
        select: { id: true },
        take: 2,
    });
    // Legacy case-variant email duplicates must not pick a recipient at random.
    const user = matches.length === 1 ? matches[0] : null;
    if (user && !contact.contactLinkId) {
        const disconnected = await tx.contactLink.findFirst({
            where: { state: 'REVOKED', request: { OR: [
                { requesterWorkspaceId: workspaceId, recipientUserId: user.id },
                { recipientWorkspaceId: workspaceId, requesterUserId: user.id },
            ] } },
            select: { id: true },
        });
        if (disconnected) return null;
    }
    return user?.id ?? null;
}

/** Called within the source financial transaction, after its book is locked.
 * Only manual entry creation starts delivery; edits refresh existing offers or
 * deliver a newly attached contact. Accepted/declined offers never reopen. */
export async function syncSharedEntry(tx: Prisma.TransactionClient, entryId: string) {
    const entry = await tx.entry.findUniqueOrThrow({
        where: { id: entryId },
        include: {
            cashbook: { include: { workspace: { include: { profile: true } } } },
            obligation: { select: { peerLinkId: true } },
            receivedSharedEntry: { select: { id: true } },
            createdBy: { select: { isActive: true, deletedAt: true, firstName: true, lastName: true } },
        },
    });
    // Imported entries must never bounce back. Linked loans already have a
    // settlement inbox, while API/inventory/ticket writes have their own flow.
    const eligible = entry.status === 'POSTED' && !entry.isDeleted && entry.contactId
        && entry.createdBy.isActive && !entry.createdBy.deletedAt
        && entry.cashbook.workspace.isActive && !entry.integrationApiKeyId
        && !entry.obligation?.peerLinkId && !entry.receivedSharedEntry;
    const recipientId = eligible
        ? await entryRecipient(tx, entry.contactId!, entry.cashbook.workspaceId) : null;
    const recipient = recipientId === entry.createdById ? null : recipientId;

    await tx.sharedEntry.updateMany({
        where: {
            sourceEntryId: entry.id, status: 'PENDING',
            ...(recipient ? { recipientUserId: { not: recipient } } : {}),
        },
        data: { status: 'CANCELLED', respondedAt: new Date(), responseReason: 'The source entry or its contact is no longer available for sharing.' },
    });
    if (!recipient) return;
    const snapshot = {
        sourceVersion: entry.version,
        sourceContactId: entry.contactId!,
        sourceWorkspaceId: entry.cashbook.workspaceId,
        senderName: entry.cashbook.workspace.profile?.displayName
            || (entry.cashbook.workspace.type === 'PERSONAL'
                ? `${entry.createdBy.firstName} ${entry.createdBy.lastName}`.trim() : null)
            || entry.cashbook.workspace.name,
        type: entry.type === 'INCOME' ? 'EXPENSE' as const : 'INCOME' as const,
        amount: entry.amount,
        currency: entry.cashbook.currency,
        description: entry.description,
        entryDate: entry.entryDate,
    };
    const existing = await tx.sharedEntry.findUnique({
        where: { sourceEntryId_recipientUserId: { sourceEntryId: entry.id, recipientUserId: recipient } },
    });
    if (!existing) {
        await tx.sharedEntry.create({ data: { sourceEntryId: entry.id, recipientUserId: recipient, ...snapshot } });
    } else if (existing.status === 'PENDING') {
        await tx.sharedEntry.updateMany({ where: { id: existing.id, status: 'PENDING' }, data: snapshot });
    }
}

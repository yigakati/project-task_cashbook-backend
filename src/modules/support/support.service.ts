import { injectable, inject } from 'tsyringe';
import { ContactMessageStatus, Prisma, PrismaClient } from '@prisma/client';
import { config } from '../../config';
import { sendEmail } from '../../config/email';
import { NotFoundError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';
import { contactMessageEmailTemplate } from '../../utils/emailTemplates';
import { logger } from '../../utils/logger';
import { ContactMessageDto } from './support.dto';

/**
 * Messages from the public contact page.
 *
 * Stored first, then forwarded to SUPPORT_INBOX_EMAIL with the sender as
 * Reply-To. Storing first means a message is never lost to an email outage,
 * and superadmins can work through them on the Platform page either way.
 *
 * No acknowledgement goes back to the sender: the address is unverified, and
 * sending to it would let anyone use this form to email strangers.
 */
@injectable()
export class SupportService {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    async submit(dto: ContactMessageDto) {
        const message = await this.prisma.contactMessage.create({
            data: {
                name: dto.name,
                email: dto.email,
                category: dto.category,
                subject: dto.subject,
                message: dto.message,
            },
        });

        if (config.SUPPORT_INBOX_EMAIL) {
            try {
                await sendEmail({
                    to: config.SUPPORT_INBOX_EMAIL,
                    replyTo: dto.email,
                    subject: `[${config.APP_NAME} ${dto.category}] ${dto.subject}`,
                    html: contactMessageEmailTemplate(dto),
                });
            } catch (error) {
                logger.error('[Support] Could not forward contact message', {
                    id: message.id, error: (error as Error).message,
                });
            }
        }
        return { id: message.id };
    }

    async list(params: { status?: ContactMessageStatus; search?: string; page: number; limit: number }) {
        const search = params.search?.trim();
        const where: Prisma.ContactMessageWhereInput = {
            ...(params.status && { status: params.status }),
            ...(search && {
                OR: [
                    { email: { contains: search, mode: 'insensitive' } },
                    { name: { contains: search, mode: 'insensitive' } },
                    { subject: { contains: search, mode: 'insensitive' } },
                ],
            }),
        };
        const [total, data] = await Promise.all([
            this.prisma.contactMessage.count({ where }),
            this.prisma.contactMessage.findMany({
                where,
                orderBy: { createdAt: 'desc' },
                skip: (params.page - 1) * params.limit,
                take: params.limit,
                include: { resolvedBy: { select: { firstName: true, lastName: true } } },
            }),
        ]);
        return { data, total, page: params.page, limit: params.limit };
    }

    async openCount() {
        return this.prisma.contactMessage.count({ where: { status: ContactMessageStatus.OPEN } });
    }

    async setStatus(id: string, actorId: string, dto: { status: ContactMessageStatus; note?: string }) {
        const existing = await this.prisma.contactMessage.findUnique({ where: { id } });
        if (!existing) throw new NotFoundError('Message');

        const resolved = dto.status === ContactMessageStatus.RESOLVED;
        const updated = await this.prisma.contactMessage.update({
            where: { id },
            data: {
                status: dto.status,
                resolvedAt: resolved ? new Date() : null,
                resolvedById: resolved ? actorId : null,
                ...(dto.note !== undefined && { resolutionNote: dto.note || null }),
            },
            include: { resolvedBy: { select: { firstName: true, lastName: true } } },
        });

        if (resolved) {
            await this.prisma.auditLog.create({
                data: {
                    userId: actorId,
                    action: AuditAction.CONTACT_MESSAGE_RESOLVED,
                    resource: 'contact_message',
                    resourceId: id,
                },
            });
        }
        return updated;
    }
}

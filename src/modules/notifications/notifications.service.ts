import { injectable, inject } from 'tsyringe';
import { PrismaClient, NotificationEntityType, NotificationType } from '@prisma/client';
import { NotFoundError, AuthorizationError } from '../../core/errors/AppError';
import { notificationsQueue } from '../../config/queues';
import { NotificationQueryDto, MarkReadDto } from './notifications.dto';

export interface CreateNotificationData {
    userId: string;
    workspaceId: string;
    type: NotificationType;
    title: string;
    body: string;
    taskId?: string | null;
}

export interface NotificationJobData {
    type: NotificationType;
    userId: string;
    workspaceId: string;
    taskId?: string;
    taskTitle?: string;
    /** For scheduler-triggered jobs — overdue/due-soon message. */
    customTitle?: string;
    customBody?: string;
    /** Callers that already know the wording pass it directly. */
    title?: string;
    body?: string;
    /** What the notification links to, when it is not a task. */
    entityType?: NotificationEntityType;
    entityId?: string;
    /**
     * Deterministic dedupe key.
     *
     * BullMQ retries a failed job, and the same event can be produced by more
     * than one path. With a groupKey the insert becomes an upsert on
     * (userId, type, groupKey), so a person is told once rather than four
     * times. Omitting it keeps the old behaviour: every job makes a row.
     */
    groupKey?: string;
}

@injectable()
export class NotificationsService {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) {}

    // ─── Query ────────────────────────────────────────────────
    async getUserNotifications(userId: string, workspaceId: string, query: NotificationQueryDto) {
        // Safe pagination defaults at service layer (no separate repo method, query is simple)
        const page  = Math.max(1, Number(query.page)  || 1);
        const limit = Math.min(100, Math.max(1, Number(query.limit) || 20));
        const skip  = (page - 1) * limit;

        const { isRead, type } = query;

        const where: any = { userId, workspaceId };
        if (isRead !== undefined) where.isRead = isRead;
        if (type) where.type = type;

        // Unread count ignores the isRead filter: the badge shows the whole
        // inbox's unread total even when the list itself is filtered to read
        // or unread items.
        const [notifications, total, unreadCount] = await Promise.all([
            this.prisma.notification.findMany({
                where,
                skip,
                take: limit,
                orderBy: { createdAt: 'desc' },
                include: { task: { select: { id: true, title: true } } },
            }),
            this.prisma.notification.count({ where }),
            this.prisma.notification.count({
                where: { userId, workspaceId, isRead: false },
            }),
        ]);

        const totalPages = Math.ceil(total / limit);
        return {
            data: notifications,
            unreadCount,
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

    // ─── Mutations ────────────────────────────────────────────
    async markAsRead(userId: string, workspaceId: string, dto: MarkReadDto) {
        // Ensure all IDs belong to the calling user
        const count = await this.prisma.notification.count({
            where: { id: { in: dto.ids }, userId, workspaceId },
        });
        if (count !== dto.ids.length) {
            throw new AuthorizationError('Some notifications do not belong to you');
        }

        await this.prisma.notification.updateMany({
            where: { id: { in: dto.ids } },
            data: { isRead: true, readAt: new Date() },
        });
    }

    async markAllRead(userId: string, workspaceId: string) {
        await this.prisma.notification.updateMany({
            where: { userId, workspaceId, isRead: false },
            data: { isRead: true, readAt: new Date() },
        });
    }

    async deleteNotification(notificationId: string, userId: string, workspaceId: string) {
        const n = await this.prisma.notification.findUnique({ where: { id: notificationId } });
        if (!n || n.userId !== userId || n.workspaceId !== workspaceId) {
            throw new NotFoundError('Notification');
        }
        await this.prisma.notification.delete({ where: { id: notificationId } });
    }

    // ─── Internal — used by worker ────────────────────────────
    async createNotification(data: CreateNotificationData) {
        return this.prisma.notification.create({ data });
    }

    // ─── Dispatch to queue (non-blocking) ────────────────────
    static dispatch(data: NotificationJobData): void {
        notificationsQueue.add(data.type, data).catch(() => {});
    }
}

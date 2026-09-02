/**
 * The notifications list response.
 *
 * The bell's contract: the envelope's data carries the page itself plus
 * `unreadCount` and `pagination`. The frontend once read a different shape
 * (notifications/total fields that never existed) and the bell silently
 * showed nothing — these tests pin the shape the UI actually consumes.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { resetDatabase, testPrisma } from '../setup';
import { resolveService } from '../container';
import { NotificationsService } from '../../modules/notifications/notifications.service';
import { createWorkspace, createUser } from '../factories';

const notifications = () => resolveService(NotificationsService);

async function seed(userId: string, workspaceId: string, rows: { isRead: boolean; title: string }[]) {
    for (const row of rows) {
        await testPrisma.notification.create({
            data: {
                userId,
                workspaceId,
                type: 'TASK_ASSIGNED' as any,
                title: row.title,
                body: `body for ${row.title}`,
                isRead: row.isRead,
            },
        });
    }
}

describe('getUserNotifications — the response contract', () => {
    beforeEach(resetDatabase);

    it('returns { data, unreadCount, pagination } at the envelope-data level', async () => {
        const user = await createUser();
        const workspace = await createWorkspace(user.id);
        await seed(user.id, workspace.id, [
            { isRead: false, title: 'one' },
            { isRead: false, title: 'two' },
            { isRead: true, title: 'three' },
        ]);

        const result = await notifications().getUserNotifications(user.id, workspace.id, {} as any);

        // The page itself is `data` — not `notifications`.
        expect(result.data).toHaveLength(3);
        // Unread is counted across the whole inbox, filter-independent.
        expect(result.unreadCount).toBe(2);
        expect(result.pagination.total).toBe(3);
        expect(result.pagination.totalPages).toBe(1);
        // Newest first, and every row carries title/body the UI renders.
        expect(result.data[0].title).toBe('three');
        expect(result.data[0].body).toBe('body for three');
    });

    it('unreadCount ignores the isRead filter on the list', async () => {
        const user = await createUser();
        const workspace = await createWorkspace(user.id);
        await seed(user.id, workspace.id, [
            { isRead: false, title: 'unread' },
            { isRead: true, title: 'read' },
        ]);

        const result = await notifications().getUserNotifications(
            user.id, workspace.id, { isRead: true } as any,
        );
        // Filtered to read items only — but the badge still says 1 unread.
        expect(result.data).toHaveLength(1);
        expect(result.unreadCount).toBe(1);
    });

    it('paginates and scopes to user + workspace', async () => {
        const user = await createUser();
        const workspace = await createWorkspace(user.id);
        await seed(user.id, workspace.id, [
            { isRead: false, title: 'a' },
            { isRead: false, title: 'b' },
        ]);
        const stranger = await createUser();
        await seed(stranger.id, workspace.id, [{ isRead: false, title: 'theirs' }]);

        const page1 = await notifications().getUserNotifications(
            user.id, workspace.id, { page: 1, limit: 1 } as any,
        );
        expect(page1.data).toHaveLength(1);
        expect(page1.pagination.hasNext).toBe(true);
        expect(page1.unreadCount).toBe(2);

        const page2 = await notifications().getUserNotifications(
            user.id, workspace.id, { page: 2, limit: 1 } as any,
        );
        expect(page2.data).toHaveLength(1);
        expect(page2.pagination.hasPrevious).toBe(true);
    });
});

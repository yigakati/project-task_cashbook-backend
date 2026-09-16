import { injectable, inject } from 'tsyringe';
import { PrismaClient, Prisma, TaskStatus, ProjectRole, ApprovalStatus } from '@prisma/client';
import { TasksRepository } from './tasks.repository';
import { FilesService } from '../files/files.service';
import { NotFoundError, AuthorizationError, AppError, ConflictError } from '../../core/errors/AppError';
import { AuditAction, WorkspaceRole } from '../../core/types';
import { workspaceUserCan } from '../../core/authz/workspace-access';
import { hasWorkspacePermission } from '../../core/types/workspace-permissions';
import { WorkspacePermission } from '../../core/types/workspace-permissions';
import {
    CreateTaskDto,
    UpdateTaskDto,
    AssignTaskDto,
    ChangeTaskStatusDto,
    TaskQueryDto,
    CreateTaskCommentDto,
    CreateChecklistItemDto,
    UpdateChecklistItemDto,
} from './tasks.dto';
import { notificationsQueue } from '../../config/queues';

@injectable()
export class TasksService {
    constructor(
        private repo: TasksRepository,
        @inject('PrismaClient') private prisma: PrismaClient,
        private filesService: FilesService,
    ) {}

    // ─── Helpers ──────────────────────────────────────────────
    private async getTaskInWorkspace(taskId: string, workspaceId: string) {
        const task = await this.repo.findById(taskId);
        if (!task || task.workspaceId !== workspaceId) throw new NotFoundError('Task');
        return task;
    }

    /**
     * Whether the caller may act on any task in the workspace.
     *
     * Matrix-backed, so PROJECT_MANAGER qualifies and a plain MEMBER still does
     * not. Previously this was a hand-rolled `owner || ADMIN`.
     */
    private async isWorkspaceManager(workspaceId: string, userId: string): Promise<boolean> {
        return workspaceUserCan(
            this.prisma,
            workspaceId,
            userId,
            WorkspacePermission.MANAGE_TASKS,
        );
    }

    private async isProjectManager(projectId: string, userId: string): Promise<boolean> {
        const m = await this.prisma.projectMember.findUnique({
            where: { projectId_userId: { projectId, userId } },
        });
        return m?.role === ProjectRole.PROJECT_MANAGER;
    }

    private async getProjectRole(projectId: string, userId: string): Promise<ProjectRole | null> {
        const m = await this.prisma.projectMember.findUnique({
            where: { projectId_userId: { projectId, userId } },
        });
        return m ? (m.role as ProjectRole) : null;
    }

    private async assertCanViewTask(task: any, workspaceId: string, userId: string) {
        if (await this.isWorkspaceManager(workspaceId, userId)) return;
        if (task.createdById === userId) return;
        if (task.assignments.some((a: any) => a.userId === userId)) return;
        if (task.projectId && await this.getProjectRole(task.projectId, userId)) return;
        throw new AuthorizationError('You do not have access to this task');
    }

    private async assertCanWriteTask(task: any, workspaceId: string, userId: string) {
        if (await this.isWorkspaceManager(workspaceId, userId)) return;
        if (task.createdById === userId) return;
        if (task.projectId && await this.isProjectManager(task.projectId, userId)) return;
        throw new AuthorizationError('Insufficient permissions to modify this task');
    }

    /**
     * Whether the caller may decide requests and reports on this task.
     *
     * Workspace-level APPROVE_TASK_WORK, or the per-project PROJECT_MANAGER
     * role, which delegates one project to someone who is otherwise a plain
     * member.
     */
    private async canApproveTaskWork(task: any, workspaceId: string, userId: string) {
        if (await this.can(workspaceId, userId, WorkspacePermission.APPROVE_TASK_WORK)) return true;
        return Boolean(task.projectId && await this.isProjectManager(task.projectId, userId));
    }

    private async assertCanApproveTaskWork(task: any, workspaceId: string, userId: string) {
        if (!(await this.canApproveTaskWork(task, workspaceId, userId))) {
            throw new AuthorizationError('You cannot approve work on this task');
        }
    }

    private can(workspaceId: string, userId: string, permission: WorkspacePermission) {
        return workspaceUserCan(this.prisma, workspaceId, userId, permission);
    }

    /**
     * How many incomplete tasks a person is already carrying.
     *
     * DONE is the only status that counts as finished — IN_REVIEW does not,
     * because the work can still come back.
     */
    private async countOpenAssignments(
        tx: Prisma.TransactionClient | PrismaClient,
        workspaceId: string,
        userId: string,
        excludeTaskId?: string,
    ): Promise<number> {
        return tx.task.count({
            where: {
                workspaceId,
                status: { not: TaskStatus.DONE },
                id: excludeTaskId ? { not: excludeTaskId } : undefined,
                assignments: { some: { userId } },
            },
        });
    }

    /**
     * Refuse if the person is already at their limit of unfinished work.
     *
     * Called twice on the request path — once when asking, for a good error
     * message, and once INSIDE the approval transaction, which is the one that
     * counts. Without the second check a member requests five tasks while free
     * and a manager approves all five.
     */
    private async assertHasCapacity(
        tx: Prisma.TransactionClient | PrismaClient,
        workspaceId: string,
        userId: string,
        excludeTaskId?: string,
    ) {
        const workspace = await tx.workspace.findUnique({
            where: { id: workspaceId },
            select: { maxConcurrentOpenTasks: true },
        });
        const limit = workspace?.maxConcurrentOpenTasks;
        if (limit == null) return;

        const open = await this.countOpenAssignments(tx, workspaceId, userId, excludeTaskId);
        if (open >= limit) {
            throw new ConflictError(
                limit === 1
                    ? 'You already have unfinished work. Complete it before taking on another task.'
                    : `You already have ${open} unfinished tasks, and the limit is ${limit}.`,
            );
        }
    }

    private async assertCanCreateInProject(projectId: string, workspaceId: string, userId: string) {
        const project = await this.prisma.project.findUnique({ where: { id: projectId } });
        if (!project || project.workspaceId !== workspaceId) throw new NotFoundError('Project');
        if (project.status === 'ARCHIVED') {
            throw new AppError('Cannot create tasks on an archived project', 400, 'PROJECT_ARCHIVED');
        }

        if (await this.isWorkspaceManager(workspaceId, userId)) return;
        const role = await this.getProjectRole(projectId, userId);
        if (!role) {
            throw new AuthorizationError('You must be a project member to create tasks in this project');
        }
        if (role === ProjectRole.VIEWER) {
            throw new AuthorizationError('Viewers cannot create tasks on this project');
        }
    }

    // ─── List / Get ───────────────────────────────────────────
    async getTasks(workspaceId: string, userId: string, query: TaskQueryDto) {
        const isWorkspaceManager = await this.isWorkspaceManager(workspaceId, userId);
        const { tasks, total, page, limit } = await this.repo.findByWorkspaceId(
            workspaceId,
            query,
            { userId, isWorkspaceManager },
        );
        const totalPages = Math.ceil(total / limit);
        return {
            data: tasks,
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

    async getTask(taskId: string, workspaceId: string, userId: string) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);
        await this.assertCanViewTask(task, workspaceId, userId);
        return task;
    }

    // ─── Create ───────────────────────────────────────────────
    async createTask(workspaceId: string, userId: string, dto: CreateTaskDto) {
        const ws = await this.prisma.workspace.findUnique({ where: { id: workspaceId } });
        if (!ws || !ws.isActive) throw new NotFoundError('Workspace');

        if (dto.projectId) {
            await this.assertCanCreateInProject(dto.projectId, workspaceId, userId);
        }

        const task = await this.prisma.$transaction(async (tx) => {
            const newTask = await tx.task.create({
                data: {
                    workspaceId,
                    createdById: userId,
                    projectId: dto.projectId ?? null,
                    title: dto.title,
                    description: dto.description ?? null,
                    status: dto.status ?? TaskStatus.TODO,
                    priority: dto.priority ?? 'MEDIUM',
                    dueDate: dto.dueDate ? new Date(dto.dueDate) : null,
                    estimatedTimeMinutes: dto.estimatedTimeMinutes ?? null,
                },
            });
            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.TASK_CREATED,
                    resource: 'task',
                    resourceId: newTask.id,
                    details: { title: dto.title, projectId: dto.projectId ?? null } as any,
                },
            });
            return newTask;
        });

        return task;
    }

    // ─── Update ───────────────────────────────────────────────
    async updateTask(taskId: string, workspaceId: string, userId: string, dto: UpdateTaskDto) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);
        await this.assertCanWriteTask(task, workspaceId, userId);

        if (dto.projectId !== undefined && dto.projectId) {
            await this.assertCanCreateInProject(dto.projectId, workspaceId, userId);
        }

        const data: any = {
            title: dto.title,
            description: dto.description,
            projectId: dto.projectId !== undefined ? dto.projectId : undefined,
            status: dto.status,
            priority: dto.priority,
            dueDate: dto.dueDate !== undefined ? (dto.dueDate ? new Date(dto.dueDate) : null) : undefined,
            estimatedTimeMinutes: dto.estimatedTimeMinutes,
        };
        if (dto.status === TaskStatus.DONE) {
            data.completedAt = new Date();
        } else if (dto.status) {
            data.completedAt = null;
        }

        const updated = await this.prisma.task.update({
            where: { id: taskId },
            data,
        });

        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.TASK_UPDATED,
                resource: 'task',
                resourceId: taskId,
                details: dto as any,
            },
        });

        return updated;
    }

    // ─── Change Status ────────────────────────────────────────
    async changeStatus(taskId: string, workspaceId: string, userId: string, dto: ChangeTaskStatusDto) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);

        const isAssignee = task.assignments.some((a: any) => a.userId === userId);
        if (!isAssignee) await this.assertCanWriteTask(task, workspaceId, userId);

        // IN_REVIEW is reached by submitting a report and left by deciding one.
        // Letting it be set directly would route around the review entirely.
        if (dto.status === TaskStatus.IN_REVIEW) {
            throw new AppError(
                'Submit an end-of-task report to send this for review.',
                400,
                'USE_TASK_REPORT',
            );
        }

        // An assignee marks work finished by reporting on it; only an approver
        // closes it. Managers may still set any status directly, because they
        // are the ones who would otherwise have to unpick a mistake.
        if (dto.status === TaskStatus.DONE
            && !(await this.canApproveTaskWork(task, workspaceId, userId))) {
            throw new AuthorizationError(
                'Submit an end-of-task report instead — a manager marks the task done when they approve it.',
            );
        }

        if (task.status === TaskStatus.IN_REVIEW
            && !(await this.canApproveTaskWork(task, workspaceId, userId))) {
            throw new AuthorizationError(
                'This task is awaiting review. A manager has to decide the report before it moves again.',
            );
        }

        const statusData: any = { status: dto.status };
        // completedAt when entering DONE; clear when reopening
        if (dto.status === TaskStatus.DONE) {
            statusData.completedAt = new Date();
        } else if ((task as any).completedAt || task.status === TaskStatus.DONE) {
            statusData.completedAt = null;
        }

        const updated = await this.prisma.task.update({
            where: { id: taskId },
            data: statusData,
        });

        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.TASK_STATUS_CHANGED,
                resource: 'task',
                resourceId: taskId,
                details: { status: dto.status } as any,
            },
        });

        return updated;
    }

    // ─── Delete ───────────────────────────────────────────────
    async deleteTask(taskId: string, workspaceId: string, userId: string) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);
        await this.assertCanWriteTask(task, workspaceId, userId);

        await this.prisma.$transaction(async (tx) => {
            await tx.task.delete({ where: { id: taskId } });
            await tx.auditLog.create({
                data: { userId, workspaceId, action: AuditAction.TASK_DELETED, resource: 'task', resourceId: taskId },
            });
        });
    }

    // ─── Assign (additive — never wipes existing assignees) ────
    async assignUsers(taskId: string, workspaceId: string, userId: string, dto: AssignTaskDto) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);
        await this.assertCanWriteTask(task, workspaceId, userId);

        // Deduplicate target IDs
        const targetIds = [...new Set(dto.userIds)];

        // Validate each target user
        for (const targetId of targetIds) {
            const wsM = await this.prisma.workspaceMember.findUnique({
                where: { workspaceId_userId: { workspaceId, userId: targetId } },
            });
            const ws = await this.prisma.workspace.findUnique({ where: { id: workspaceId } });
            if (!wsM && ws?.ownerId !== targetId) {
                throw new AppError(`User ${targetId} is not a workspace member`, 400, 'INVALID_OPERATION');
            }

            if (task.projectId) {
                const pm = await this.prisma.projectMember.findUnique({
                    where: { projectId_userId: { projectId: task.projectId, userId: targetId } },
                });
                if (!pm) {
                    throw new AppError(
                        `User ${targetId} is not a project member. Add them to the project first.`,
                        400,
                        'INVALID_OPERATION',
                    );
                }
            }
        }

        // Existing assignees — only insert missing rows (additive)
        const existing = await this.prisma.taskAssignment.findMany({
            where: { taskId },
            select: { userId: true },
        });
        const existingSet = new Set(existing.map((e) => e.userId));
        const toAdd = targetIds.filter((id) => !existingSet.has(id));

        if (toAdd.length === 0) {
            return this.repo.findById(taskId);
        }

        await this.prisma.$transaction(async (tx) => {
            await tx.taskAssignment.createMany({
                data: toAdd.map((uid) => ({ taskId, userId: uid, assignedBy: userId })),
                skipDuplicates: true,
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.TASK_ASSIGNED,
                    resource: 'task',
                    resourceId: taskId,
                    details: { assignedUserIds: toAdd, mode: 'additive' } as any,
                },
            });
        });

        // Notify newly assigned only
        for (const assigneeId of toAdd) {
            if (assigneeId === userId) continue;
            notificationsQueue.add('TASK_ASSIGNED', {
                type: 'TASK_ASSIGNED',
                userId: assigneeId,
                workspaceId,
                taskId,
                taskTitle: task.title,
            }).catch(() => {});
        }

        return this.repo.findById(taskId);
    }

    async unassignUser(taskId: string, workspaceId: string, userId: string, targetUserId: string) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);
        await this.assertCanWriteTask(task, workspaceId, userId);

        const assignment = await this.repo.findAssignment(taskId, targetUserId);
        if (!assignment) throw new NotFoundError('Task assignment');

        await this.prisma.$transaction(async (tx) => {
            await tx.taskAssignment.delete({
                where: { taskId_userId: { taskId, userId: targetUserId } },
            });
            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.TASK_UNASSIGNED,
                    resource: 'task',
                    resourceId: taskId,
                    details: { unassignedUserId: targetUserId } as any,
                },
            });
        });
    }

    // ─── Comments ─────────────────────────────────────────────
    async listComments(taskId: string, workspaceId: string, userId: string) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);
        await this.assertCanViewTask(task, workspaceId, userId);
        return this.prisma.taskComment.findMany({
            where: { taskId },
            orderBy: { createdAt: 'asc' },
            include: { author: { select: { id: true, firstName: true, lastName: true, email: true } } },
        });
    }

    async addComment(taskId: string, workspaceId: string, userId: string, dto: CreateTaskCommentDto) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);
        await this.assertCanViewTask(task, workspaceId, userId);

        const comment = await this.prisma.taskComment.create({
            data: { taskId, authorId: userId, body: dto.body.trim() },
            include: { author: { select: { id: true, firstName: true, lastName: true, email: true } } },
        });

        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.TASK_COMMENT_ADDED,
                resource: 'task_comment',
                resourceId: comment.id,
                details: { taskId } as any,
            },
        });

        return comment;
    }

    async deleteComment(taskId: string, commentId: string, workspaceId: string, userId: string) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);
        await this.assertCanViewTask(task, workspaceId, userId);
        const comment = await this.prisma.taskComment.findUnique({ where: { id: commentId } });
        if (!comment || comment.taskId !== taskId) throw new NotFoundError('Comment');

        const isWsManager = await this.isWorkspaceManager(workspaceId, userId);
        if (comment.authorId !== userId && !isWsManager) {
            throw new AuthorizationError('You can only delete your own comments');
        }

        await this.prisma.taskComment.delete({ where: { id: commentId } });
        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.TASK_COMMENT_DELETED,
                resource: 'task_comment',
                resourceId: commentId,
                details: { taskId } as any,
            },
        });
    }

    // ─── Checklist ────────────────────────────────────────────
    async listChecklist(taskId: string, workspaceId: string, userId: string) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);
        await this.assertCanViewTask(task, workspaceId, userId);
        return this.prisma.taskChecklistItem.findMany({
            where: { taskId },
            orderBy: { position: 'asc' },
        });
    }

    async addChecklistItem(
        taskId: string,
        workspaceId: string,
        userId: string,
        dto: CreateChecklistItemDto,
    ) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);
        await this.assertCanWriteTask(task, workspaceId, userId);

        const maxPos = await this.prisma.taskChecklistItem.aggregate({
            where: { taskId },
            _max: { position: true },
        });
        const position = dto.position ?? ((maxPos._max.position ?? -1) + 1);

        const item = await this.prisma.taskChecklistItem.create({
            data: { taskId, title: dto.title.trim(), position },
        });

        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.TASK_CHECKLIST_UPDATED,
                resource: 'task_checklist',
                resourceId: item.id,
                details: { taskId, action: 'add' } as any,
            },
        });

        return item;
    }

    async updateChecklistItem(
        taskId: string,
        itemId: string,
        workspaceId: string,
        userId: string,
        dto: UpdateChecklistItemDto,
    ) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);
        // Assignees may toggle done
        const isAssignee = task.assignments.some((a: any) => a.userId === userId);
        if (!isAssignee) await this.assertCanWriteTask(task, workspaceId, userId);

        const item = await this.prisma.taskChecklistItem.findUnique({ where: { id: itemId } });
        if (!item || item.taskId !== taskId) throw new NotFoundError('Checklist item');

        const data: any = {};
        if (dto.title !== undefined) data.title = dto.title.trim();
        if (dto.position !== undefined) data.position = dto.position;
        if (dto.isDone !== undefined) {
            data.isDone = dto.isDone;
            data.completedAt = dto.isDone ? new Date() : null;
            data.completedBy = dto.isDone ? userId : null;
        }

        const updated = await this.prisma.taskChecklistItem.update({
            where: { id: itemId },
            data,
        });

        await this.prisma.auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.TASK_CHECKLIST_UPDATED,
                resource: 'task_checklist',
                resourceId: itemId,
                details: { taskId, action: 'update', ...dto } as any,
            },
        });

        return updated;
    }

    async deleteChecklistItem(
        taskId: string,
        itemId: string,
        workspaceId: string,
        userId: string,
    ) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);
        await this.assertCanWriteTask(task, workspaceId, userId);

        const item = await this.prisma.taskChecklistItem.findUnique({ where: { id: itemId } });
        if (!item || item.taskId !== taskId) throw new NotFoundError('Checklist item');

        await this.prisma.$transaction(async (tx) => {
            await tx.taskChecklistItem.delete({ where: { id: itemId } });
            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: AuditAction.TASK_CHECKLIST_UPDATED,
                    resource: 'task_checklist',
                    resourceId: itemId,
                    details: { taskId, action: 'delete' } as any,
                },
            });
        });
    }

    /** Recent audit activity for a task (production collaboration feed). */
    /**
     * What has happened on this task, and who did it.
     *
     * Filtered in SQL rather than by pulling the workspace's last 80 audit rows
     * and sieving them in JS. That approach lost history: in a busy workspace
     * this task's own rows fall outside the window and the feed silently
     * appears empty, which is worse than slow.
     *
     * Each row carries the actor's name and the role they hold *now*. The role
     * is deliberately current rather than historical — the audit log does not
     * record what somebody was at the time, and inventing it would be a lie.
     */
    async getTaskActivity(taskId: string, workspaceId: string, userId: string) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);
        await this.assertCanViewTask(task, workspaceId, userId);

        const logs = await this.prisma.auditLog.findMany({
            where: {
                workspaceId,
                OR: [
                    // The task itself.
                    { resource: 'task', resourceId: taskId },
                    // Comments, checklist items, requests and reports record the
                    // task they belong to in `details`.
                    {
                        resource: {
                            in: ['task_comment', 'task_checklist', 'task_assignment_request', 'task_report'],
                        },
                        details: { path: ['taskId'], equals: taskId },
                    },
                ],
            },
            orderBy: { createdAt: 'desc' },
            take: 60,
            select: {
                id: true,
                action: true,
                resource: true,
                resourceId: true,
                details: true,
                createdAt: true,
                userId: true,
                user: { select: { id: true, firstName: true, lastName: true, email: true } },
            },
        });

        // One lookup for every actor in the feed, rather than a query per row.
        const actorIds = [...new Set(logs.map((log) => log.userId).filter(Boolean))] as string[];
        const [members, workspace] = await Promise.all([
            this.prisma.workspaceMember.findMany({
                where: { workspaceId, userId: { in: actorIds } },
                select: { userId: true, role: true },
            }),
            this.prisma.workspace.findUnique({
                where: { id: workspaceId },
                select: { ownerId: true },
            }),
        ]);
        const roleByUser = new Map(members.map((m) => [m.userId, m.role as WorkspaceRole]));

        return logs.map((log) => ({
            ...log,
            // The owner has no membership row, so they would otherwise show as
            // having no role at all.
            actorRole: log.userId
                ? log.userId === workspace?.ownerId
                    ? WorkspaceRole.OWNER
                    : roleByUser.get(log.userId) ?? null
                : null,
        }));
    }

    // ─── Assignment requests ──────────────────────────────────

    /**
     * Ask to take on a task you can see but are not assigned to.
     *
     * The capacity check here is for the error message; the one that decides is
     * inside `reviewAssignmentRequest`, because a member could otherwise queue
     * up requests while free and have them all approved later.
     */
    async requestAssignment(
        taskId: string,
        workspaceId: string,
        userId: string,
        dto: { message?: string },
    ) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);
        await this.assertCanViewTask(task, workspaceId, userId);

        if (task.assignments.some((a: any) => a.userId === userId)) {
            throw new ConflictError('You are already assigned to this task.');
        }
        if (task.status === TaskStatus.DONE) {
            throw new AppError('This task is already finished.', 400, 'TASK_ALREADY_DONE');
        }
        await this.assertHasCapacity(this.prisma, workspaceId, userId, taskId);

        let requestId: string;
        try {
            const created = await this.prisma.$transaction(async (tx) => {
                const request = await tx.taskAssignmentRequest.create({
                    data: { workspaceId, taskId, requesterId: userId, message: dto.message ?? null },
                });
                await tx.auditLog.create({
                    data: {
                        userId,
                        workspaceId,
                        action: AuditAction.TASK_ASSIGNMENT_REQUESTED,
                        resource: 'task_assignment_request',
                        resourceId: request.id,
                        details: { taskId } as any,
                    },
                });
                return request;
            });
            requestId = created.id;
            await this.notifyApprovers(task, workspaceId, userId, {
                type: 'TASK_ASSIGNMENT_REQUESTED',
                title: 'Someone asked to take on a task',
                body: `A request to work on "${task.title}" is waiting for your decision.`,
                entityType: 'TASK_ASSIGNMENT_REQUEST',
                entityId: created.id,
                groupKey: `task-request:${created.id}`,
            });
            return created;
        } catch (error: any) {
            // task_assignment_requests_one_pending
            if (error?.code === 'P2002') {
                throw new ConflictError('You have already asked to work on this task.');
            }
            throw error;
        }
    }

    async withdrawAssignmentRequest(requestId: string, workspaceId: string, userId: string) {
        const claimed = await this.prisma.taskAssignmentRequest.updateMany({
            where: { id: requestId, workspaceId, requesterId: userId, status: ApprovalStatus.PENDING },
            data: { status: ApprovalStatus.WITHDRAWN },
        });
        if (claimed.count === 0) {
            throw new NotFoundError('Pending request');
        }
        return this.prisma.taskAssignmentRequest.findUniqueOrThrow({ where: { id: requestId } });
    }

    async listAssignmentRequests(
        workspaceId: string,
        userId: string,
        query: { taskId?: string; status?: ApprovalStatus; mine?: boolean },
    ) {
        const canApprove = await this.can(workspaceId, userId, WorkspacePermission.APPROVE_TASK_WORK);
        return this.prisma.taskAssignmentRequest.findMany({
            where: {
                workspaceId,
                status: query.status,
                taskId: query.taskId,
                // Anyone may read their own; only approvers see everyone's.
                requesterId: canApprove && !query.mine ? undefined : userId,
            },
            include: {
                task: { select: { id: true, title: true, status: true, projectId: true } },
                requester: { select: { id: true, firstName: true, lastName: true, email: true } },
                reviewer: { select: { id: true, firstName: true, lastName: true } },
            },
            orderBy: { createdAt: 'desc' },
            take: 100,
        });
    }

    /**
     * Decide a request. Approving assigns the requester in the same transaction.
     */
    async reviewAssignmentRequest(
        requestId: string,
        workspaceId: string,
        userId: string,
        dto: { approve: boolean; reviewNote?: string },
    ) {
        const request = await this.prisma.taskAssignmentRequest.findUnique({
            where: { id: requestId },
            include: { task: { include: { assignments: true } } },
        });
        if (!request || request.workspaceId !== workspaceId) throw new NotFoundError('Request');
        await this.assertCanApproveTaskWork(request.task, workspaceId, userId);

        const decided = await this.prisma.$transaction(async (tx) => {
            // Claim it first. Two approvers deciding at once: exactly one wins.
            const claimed = await tx.taskAssignmentRequest.updateMany({
                where: { id: requestId, status: ApprovalStatus.PENDING },
                data: {
                    status: dto.approve ? ApprovalStatus.APPROVED : ApprovalStatus.REJECTED,
                    reviewerId: userId,
                    reviewNote: dto.reviewNote ?? null,
                    reviewedAt: new Date(),
                },
            });
            if (claimed.count === 0) {
                throw new ConflictError('That request has already been decided.');
            }

            if (dto.approve) {
                // Re-checked inside the transaction: the requester may have
                // picked up other work since they asked.
                await this.assertHasCapacity(tx, workspaceId, request.requesterId, request.taskId);
                await tx.taskAssignment.createMany({
                    data: [{ taskId: request.taskId, userId: request.requesterId, assignedBy: userId }],
                    skipDuplicates: true,
                });
            }

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: dto.approve
                        ? AuditAction.TASK_ASSIGNMENT_APPROVED
                        : AuditAction.TASK_ASSIGNMENT_REJECTED,
                    resource: 'task_assignment_request',
                    resourceId: requestId,
                    details: { taskId: request.taskId, requesterId: request.requesterId } as any,
                },
            });

            return tx.taskAssignmentRequest.findUniqueOrThrow({ where: { id: requestId } });
        });

        void this.dispatch({
            userId: request.requesterId,
            workspaceId,
            type: 'TASK_ASSIGNMENT_DECIDED',
            title: dto.approve ? 'You were assigned a task' : 'Your request was declined',
            body: dto.approve
                ? `You can now work on "${request.task.title}".`
                : `Your request to work on "${request.task.title}" was declined.`,
            taskId: request.taskId,
            entityType: 'TASK_ASSIGNMENT_REQUEST',
            entityId: requestId,
            groupKey: `task-request-decided:${requestId}`,
        });

        return decided;
    }

    // ─── End-of-task reports ──────────────────────────────────

    /**
     * Submit the report that ends a task. Moves it to IN_REVIEW.
     *
     * Only an assignee may report, because the report is a statement about work
     * they did. Managers who want to close a task can set DONE directly.
     */
    async submitReport(
        taskId: string,
        workspaceId: string,
        userId: string,
        dto: { summary: string; blockers?: string; minutesSpent?: number },
    ) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);
        if (!task.assignments.some((a: any) => a.userId === userId)) {
            throw new AuthorizationError('Only someone assigned to this task can report on it.');
        }
        if (task.status === TaskStatus.DONE) {
            throw new AppError('This task is already finished.', 400, 'TASK_ALREADY_DONE');
        }

        try {
            const report = await this.prisma.$transaction(async (tx) => {
                const created = await tx.taskReport.create({
                    data: {
                        workspaceId,
                        taskId,
                        authorId: userId,
                        summary: dto.summary,
                        blockers: dto.blockers ?? null,
                        minutesSpent: dto.minutesSpent ?? null,
                    },
                });
                await tx.task.update({
                    where: { id: taskId },
                    data: { status: TaskStatus.IN_REVIEW, completedAt: null },
                });
                await tx.auditLog.create({
                    data: {
                        userId,
                        workspaceId,
                        action: AuditAction.TASK_REPORT_SUBMITTED,
                        resource: 'task_report',
                        resourceId: created.id,
                        details: { taskId } as any,
                    },
                });
                return created;
            });

            await this.notifyApprovers(task, workspaceId, userId, {
                type: 'TASK_REPORT_SUBMITTED',
                title: 'A task is ready for review',
                body: `"${task.title}" has been reported complete and is waiting for your review.`,
                entityType: 'TASK_REPORT',
                entityId: report.id,
                groupKey: `task-report:${report.id}`,
            });
            return report;
        } catch (error: any) {
            // task_reports_one_live_per_task
            if (error?.code === 'P2002') {
                throw new ConflictError('A report for this task is already awaiting review.');
            }
            throw error;
        }
    }

    async listReports(
        taskId: string,
        workspaceId: string,
        userId: string,
    ) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);
        await this.assertCanViewTask(task, workspaceId, userId);
        return this.prisma.taskReport.findMany({
            where: { workspaceId, taskId },
            include: {
                author: { select: { id: true, firstName: true, lastName: true, email: true } },
                reviewer: { select: { id: true, firstName: true, lastName: true } },
            },
            orderBy: { createdAt: 'desc' },
        });
    }

    /**
     * Decide a report. Approving is the only route into DONE; rejecting sends
     * the task back to IN_PROGRESS with the reviewer's note attached.
     */
    async reviewReport(
        reportId: string,
        workspaceId: string,
        userId: string,
        dto: { approve: boolean; reviewNote?: string },
    ) {
        const report = await this.prisma.taskReport.findUnique({
            where: { id: reportId },
            include: { task: true },
        });
        if (!report || report.workspaceId !== workspaceId) throw new NotFoundError('Report');
        await this.assertCanApproveTaskWork(report.task, workspaceId, userId);

        if (!dto.approve && !dto.reviewNote?.trim()) {
            throw new AppError(
                'Say why the report is being sent back, so the assignee knows what to fix.',
                400,
                'REVIEW_NOTE_REQUIRED',
            );
        }

        const decided = await this.prisma.$transaction(async (tx) => {
            const claimed = await tx.taskReport.updateMany({
                where: { id: reportId, status: ApprovalStatus.PENDING, version: report.version },
                data: {
                    status: dto.approve ? ApprovalStatus.APPROVED : ApprovalStatus.REJECTED,
                    reviewerId: userId,
                    reviewNote: dto.reviewNote ?? null,
                    reviewedAt: new Date(),
                    version: { increment: 1 },
                },
            });
            if (claimed.count === 0) {
                throw new ConflictError('That report has already been decided.');
            }

            await tx.task.update({
                where: { id: report.taskId },
                data: dto.approve
                    ? { status: TaskStatus.DONE, completedAt: new Date() }
                    : { status: TaskStatus.IN_PROGRESS, completedAt: null },
            });

            await tx.auditLog.create({
                data: {
                    userId,
                    workspaceId,
                    action: dto.approve
                        ? AuditAction.TASK_REPORT_APPROVED
                        : AuditAction.TASK_REPORT_REJECTED,
                    resource: 'task_report',
                    resourceId: reportId,
                    details: { taskId: report.taskId } as any,
                },
            });

            return tx.taskReport.findUniqueOrThrow({ where: { id: reportId } });
        });

        void this.dispatch({
            userId: report.authorId,
            workspaceId,
            type: 'TASK_REPORT_DECIDED',
            title: dto.approve ? 'Your report was approved' : 'Your report was sent back',
            body: dto.approve
                ? `"${report.task.title}" is now marked done.`
                : `"${report.task.title}" needs more work: ${dto.reviewNote}`,
            taskId: report.taskId,
            entityType: 'TASK_REPORT',
            entityId: reportId,
            groupKey: `task-report-decided:${reportId}`,
        });

        return decided;
    }

    // ─── Attachments ──────────────────────────────────────────

    /**
     * Attach a file to a task.
     *
     * View-level, deliberately: the same people who may comment may attach.
     * A photo of the thing you are describing is the same contribution as a
     * sentence about it, and requiring write access would mean only managers
     * could add evidence to a task they are not doing.
     */
    async attachToTask(
        taskId: string,
        workspaceId: string,
        userId: string,
        file: Express.Multer.File,
    ) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);
        await this.assertCanViewTask(task, workspaceId, userId);
        return this.filesService.uploadOwnedAttachment(workspaceId, { taskId }, userId, file);
    }

    async listTaskAttachments(taskId: string, workspaceId: string, userId: string) {
        const task = await this.getTaskInWorkspace(taskId, workspaceId);
        await this.assertCanViewTask(task, workspaceId, userId);
        return this.filesService.listOwnedAttachments({ taskId });
    }

    /**
     * Attach evidence to an end-of-task report.
     *
     * Only the author, and only while it is still under review — a report that
     * has been decided is a record of what was reviewed, and adding to it
     * afterwards would change what somebody already signed off.
     */
    async attachToReport(
        reportId: string,
        workspaceId: string,
        userId: string,
        file: Express.Multer.File,
    ) {
        const report = await this.prisma.taskReport.findUnique({ where: { id: reportId } });
        if (!report || report.workspaceId !== workspaceId) throw new NotFoundError('Report');
        if (report.authorId !== userId) {
            throw new AuthorizationError('Only the author can attach to this report');
        }
        if (report.status !== ApprovalStatus.PENDING) {
            throw new ConflictError('That report has already been reviewed.');
        }
        return this.filesService.uploadOwnedAttachment(workspaceId, { taskReportId: reportId }, userId, file);
    }

    async listReportAttachments(reportId: string, workspaceId: string, userId: string) {
        const report = await this.prisma.taskReport.findUnique({
            where: { id: reportId },
            include: { task: { include: { assignments: true } } },
        });
        if (!report || report.workspaceId !== workspaceId) throw new NotFoundError('Report');
        await this.assertCanViewTask(report.task, workspaceId, userId);
        return this.filesService.listOwnedAttachments({ taskReportId: reportId });
    }

    // ─── Notification plumbing ────────────────────────────────

    /** Fire-and-forget: a failed notification must never fail the write. */
    private dispatch(data: Record<string, unknown>) {
        return notificationsQueue.add(data.type as string, data).catch(() => { });
    }

    /**
     * Tell whoever can decide this task's work.
     *
     * Workspace approvers plus, when the task belongs to a project, that
     * project's managers — a delegated project manager would otherwise never
     * hear about a request they are the right person to decide.
     */
    private async notifyApprovers(
        task: { id: string; projectId: string | null },
        workspaceId: string,
        actorId: string,
        payload: Record<string, unknown>,
    ) {
        const [members, projectManagers] = await Promise.all([
            this.prisma.workspaceMember.findMany({
                where: { workspaceId },
                select: { userId: true, role: true },
            }),
            task.projectId
                ? this.prisma.projectMember.findMany({
                    where: { projectId: task.projectId, role: ProjectRole.PROJECT_MANAGER },
                    select: { userId: true },
                })
                : Promise.resolve([]),
        ]);
        const workspace = await this.prisma.workspace.findUnique({
            where: { id: workspaceId },
            select: { ownerId: true },
        });

        const recipients = new Set<string>();
        if (workspace?.ownerId) recipients.add(workspace.ownerId);
        for (const m of members) {
            if (hasWorkspacePermission(m.role as WorkspaceRole, WorkspacePermission.APPROVE_TASK_WORK)) {
                recipients.add(m.userId);
            }
        }
        for (const pm of projectManagers) recipients.add(pm.userId);
        recipients.delete(actorId);

        await Promise.all(
            [...recipients].map((userId) =>
                this.dispatch({ ...payload, userId, workspaceId, taskId: task.id }),
            ),
        );
    }
}

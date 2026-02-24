import { injectable } from 'tsyringe';
import { AccountCategoriesRepository } from './account-categories.repository';
import { CreateAccountCategoryBody, UpdateAccountCategoryBody } from './account-categories.dto';
import { AppError, NotFoundError, ConflictError } from '../../core/errors/AppError';
import { AuditAction } from '../../core/types';
import { getPrismaClient } from '../../config/database';

@injectable()
export class AccountCategoriesService {
    constructor(private repository: AccountCategoriesRepository) { }

    async createCategory(workspaceId: string, userId: string, data: CreateAccountCategoryBody) {
        const existing = await this.repository.findByNameAndWorkspace(data.name, workspaceId);
        if (existing) {
            throw new ConflictError('Account category with this name already exists in this workspace');
        }

        const category = await this.repository.create({
            workspaceId,
            name: data.name
        });

        await getPrismaClient().auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.ACCOUNT_CATEGORY_CREATED || 'ACCOUNT_CATEGORY_CREATED',
                resource: 'account_category',
                resourceId: category.id,
                details: { name: category.name } as any
            }
        });

        return category;
    }

    async getWorkspaceCategories(workspaceId: string) {
        return this.repository.findAllByWorkspace(workspaceId);
    }

    async updateCategory(id: string, workspaceId: string, userId: string, data: UpdateAccountCategoryBody) {
        const category = await this.repository.findById(id);
        if (!category || category.workspaceId !== workspaceId) {
            throw new NotFoundError('Account Category');
        }

        if (data.name && data.name !== category.name) {
            const existing = await this.repository.findByNameAndWorkspace(data.name, workspaceId);
            if (existing) {
                throw new ConflictError('Account category with this name already exists in this workspace');
            }
        }

        const updated = await this.repository.update(id, data);

        await getPrismaClient().auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.ACCOUNT_CATEGORY_UPDATED || 'ACCOUNT_CATEGORY_UPDATED',
                resource: 'account_category',
                resourceId: category.id,
                details: { old: { name: category.name }, new: data } as any
            }
        });

        return updated;
    }

    async deleteCategory(id: string, workspaceId: string, userId: string) {
        const category = await this.repository.findById(id);
        if (!category || category.workspaceId !== workspaceId) {
            throw new NotFoundError('Account Category');
        }

        // Typically, we nullify the category on transactions rather than blocking deletion for categories
        // The schema has `onDelete: SetNull` for accountCategoryId, so DB handles the cascade natively
        // We'll just execute the delete

        await this.repository.delete(id);

        await getPrismaClient().auditLog.create({
            data: {
                userId,
                workspaceId,
                action: AuditAction.ACCOUNT_CATEGORY_DELETED || 'ACCOUNT_CATEGORY_DELETED',
                resource: 'account_category',
                resourceId: id,
                details: { name: category.name } as any
            }
        });
    }
}

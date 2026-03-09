import 'reflect-metadata';
import { container } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { getPrismaClient } from './database';
import { getRedisClient } from './redis';

// ─── Infrastructure Singletons ─────────────────────────
container.register<PrismaClient>('PrismaClient', {
    useFactory: () => getPrismaClient(),
});

container.register<Redis>('RedisClient', {
    useFactory: () => getRedisClient(),
});

// ─── Repositories ──────────────────────────────────────
import { AuthRepository } from '../modules/auth/auth.repository';
import { CashbooksRepository } from '../modules/cashbooks/cashbooks.repository';
import { CategoriesRepository } from '../modules/categories/categories.repository';
import { ContactsRepository } from '../modules/contacts/contacts.repository';
import { EntriesRepository } from '../modules/entries/entries.repository';
import { MembersRepository } from '../modules/members/members.repository';
import { PaymentModesRepository } from '../modules/payment-modes/payment-modes.repository';
import { UsersRepository } from '../modules/users/users.repository';
import { WorkspacesRepository } from '../modules/workspaces/workspaces.repository';
import { InventoryRepository } from '../modules/inventory/inventory.repository';

container.registerSingleton(AuthRepository);
container.registerSingleton(CashbooksRepository);
container.registerSingleton(CategoriesRepository);
container.registerSingleton(ContactsRepository);
container.registerSingleton(EntriesRepository);
container.registerSingleton(MembersRepository);
container.registerSingleton(PaymentModesRepository);
container.registerSingleton(UsersRepository);
container.registerSingleton(WorkspacesRepository);
container.registerSingleton(InventoryRepository);

// ─── Services ──────────────────────────────────────────
import { AuthService } from '../modules/auth/auth.service';
import { CashbooksService } from '../modules/cashbooks/cashbooks.service';
import { CategoriesService } from '../modules/categories/categories.service';
import { ContactsService } from '../modules/contacts/contacts.service';
import { EntriesService } from '../modules/entries/entries.service';
import { FilesService } from '../modules/files/files.service';
import { StorageService } from '../modules/files/storage.service';
import { MembersService } from '../modules/members/members.service';
import { PaymentModesService } from '../modules/payment-modes/payment-modes.service';
import { ReportsService } from '../modules/reports/reports.service';
import { UsersService } from '../modules/users/users.service';
import { WorkspacesService } from '../modules/workspaces/workspaces.service';
import { InvitesService } from '../modules/invites/invites.service';
import { MinioCleanupJob } from '../jobs/s3Cleanup';
import { InventoryService } from '../modules/inventory/inventory.service';

container.registerSingleton(AuthService);
container.registerSingleton(CashbooksService);
container.registerSingleton(CategoriesService);
container.registerSingleton(ContactsService);
container.registerSingleton(EntriesService);
container.registerSingleton(StorageService);
container.registerSingleton(FilesService);
container.registerSingleton(MembersService);
container.registerSingleton(PaymentModesService);
container.registerSingleton(ReportsService);
container.registerSingleton(UsersService);
container.registerSingleton(WorkspacesService);
container.registerSingleton(InvitesService);
container.registerSingleton(MinioCleanupJob);
container.registerSingleton(InventoryService);

// ─── Controllers ───────────────────────────────────────
import { AuthController } from '../modules/auth/auth.controller';
import { CashbooksController } from '../modules/cashbooks/cashbooks.controller';
import { CategoriesController } from '../modules/categories/categories.controller';
import { ContactsController } from '../modules/contacts/contacts.controller';
import { EntriesController } from '../modules/entries/entries.controller';
import { FilesController } from '../modules/files/files.controller';
import { MembersController } from '../modules/members/members.controller';
import { PaymentModesController } from '../modules/payment-modes/payment-modes.controller';
import { ReportsController } from '../modules/reports/reports.controller';
import { UsersController } from '../modules/users/users.controller';
import { WorkspacesController } from '../modules/workspaces/workspaces.controller';
import { AdminController } from '../modules/admin/admin.controller';
import { AuditController } from '../modules/audit/audit.controller';
import { InvitesController } from '../modules/invites/invites.controller';
import { InventoryController } from '../modules/inventory/inventory.controller';

container.registerSingleton(AuthController);
container.registerSingleton(CashbooksController);
container.registerSingleton(CategoriesController);
container.registerSingleton(ContactsController);
container.registerSingleton(EntriesController);
container.registerSingleton(FilesController);
container.registerSingleton(MembersController);
container.registerSingleton(PaymentModesController);
container.registerSingleton(ReportsController);
container.registerSingleton(UsersController);
container.registerSingleton(WorkspacesController);
container.registerSingleton(AdminController);
container.registerSingleton(AuditController);
container.registerSingleton(InvitesController);
container.registerSingleton(InventoryController);

export { container };

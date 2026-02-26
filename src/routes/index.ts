import { Router } from 'express';
import authRoutes from '../modules/auth/auth.routes';
import usersRoutes from '../modules/users/users.routes';
import workspacesRoutes from '../modules/workspaces/workspaces.routes';
import membersRoutes from '../modules/members/members.routes';
import cashbooksRoutes from '../modules/cashbooks/cashbooks.routes';
import entriesRoutes from '../modules/entries/entries.routes';
import categoriesRoutes from '../modules/categories/categories.routes';
import contactsRoutes from '../modules/contacts/contacts.routes';
import paymentModesRoutes from '../modules/payment-modes/payment-modes.routes';
import filesRoutes from '../modules/files/files.routes';
import reportsRoutes from '../modules/reports/reports.routes';
import auditRoutes from '../modules/audit/audit.routes';
import adminRoutes from '../modules/admin/admin.routes';
import invitesRoutes from '../modules/invites/invites.routes';
import accountTypesRoutes from '../modules/account-types/account-types.routes';
import accountCategoriesRoutes from '../modules/account-categories/account-categories.routes';
import accountsRoutes from '../modules/accounts/accounts.routes';
import accountTransactionsRoutes from '../modules/account-transactions/account-transactions.routes';

const router = Router();

// API v1 routes
router.use('/auth', authRoutes);
router.use('/users', usersRoutes);
router.use('/workspaces', workspacesRoutes);
router.use('/workspaces/:workspaceId/members', membersRoutes);
router.use('/workspaces/:workspaceId/account-types', accountTypesRoutes);
router.use('/workspaces/:workspaceId/account-categories', accountCategoriesRoutes);
router.use('/workspaces/:workspaceId/accounts', accountsRoutes);
router.use('/workspaces/:workspaceId/accounts/:accountId/transactions', accountTransactionsRoutes);
router.use('/cashbooks', cashbooksRoutes);
router.use('/entries', entriesRoutes);
router.use('/categories', categoriesRoutes);
router.use('/contacts', contactsRoutes);
router.use('/payment-modes', paymentModesRoutes);
router.use('/files', filesRoutes);
router.use('/reports', reportsRoutes);
router.use('/audit', auditRoutes);
router.use('/admin', adminRoutes);
router.use('/invites', invitesRoutes);

export default router;

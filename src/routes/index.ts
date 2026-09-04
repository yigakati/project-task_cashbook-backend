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
import ledgerReportsRoutes from '../modules/ledger-reports/ledger-reports.routes';
import chartOfAccountsRoutes from '../modules/chart-of-accounts/chart-of-accounts.routes';
import auditRoutes from '../modules/audit/audit.routes';
import platformRoutes from '../modules/platform/platform.routes';
import invitesRoutes from '../modules/invites/invites.routes';
import { obligationsRouter } from '../modules/cashbook-obligations/obligations.routes';
import {
    peerLinksCashbookRouter,
    peerLinksRouter,
    workspaceObligationsRouter,
} from '../modules/peer-links/peer-links.routes';
import accountTypesRoutes from '../modules/account-types/account-types.routes';
import accountCategoriesRoutes from '../modules/account-categories/account-categories.routes';
import accountsRoutes from '../modules/accounts/accounts.routes';
import accountTransactionsRoutes from '../modules/account-transactions/account-transactions.routes';
import inventoryRoutes from '../modules/inventory/inventory.routes';
import { unitsOfMeasureRouter } from '../modules/inventory/units-of-measure.routes';
import { agreementsRouter } from '../modules/inventory/agreements.routes';
import catalogRoutes from '../modules/catalog/catalog.routes';
import invoicingRoutes from '../modules/invoicing/invoicing.routes';
import projectsRoutes from '../modules/projects/projects.routes';
import tasksRoutes from '../modules/tasks/tasks.routes';
import ticketingRoutes from '../modules/ticketing/ticketing.routes';
import timeTrackingRoutes from '../modules/time-tracking/time-tracking.routes';
import expenseClaimsRoutes from '../modules/expense-claims/expense-claims.routes';
import attendanceRoutes from '../modules/attendance/attendance.routes';
import meAttendanceRoutes from '../modules/time-tracking/me-attendance.routes';
import notificationsRoutes from '../modules/notifications/notifications.routes';
import apiKeysRoutes from '../modules/api-keys/api-keys.routes';
import integrationRoutes from '../modules/integration/integration.routes';

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
router.use('/workspaces/:workspaceId/inventory', inventoryRoutes);
router.use('/workspaces/:workspaceId/units-of-measure', unitsOfMeasureRouter);
// Person-scoped for everything after the proposal — see agreements.routes.ts.
router.use('/agreements', agreementsRouter);
// Proposal routes are workspace-scoped: the goods must be the sender's, and
// requireWorkspaceMember reads req.params.workspaceId, so the same router is
// mounted with mergeParams on the workspace path as well.
router.use('/workspaces/:workspaceId/agreements', agreementsRouter);
router.use('/workspaces/:workspaceId/catalog', catalogRoutes);
router.use('/workspaces/:workspaceId/invoices', invoicingRoutes);
router.use('/workspaces/:workspaceId/projects', projectsRoutes);
router.use('/workspaces/:workspaceId/tasks', tasksRoutes);
// Answers 404 unless a superadmin has unlocked TICKETING for the workspace.
router.use('/workspaces/:workspaceId/ticketing', ticketingRoutes);
router.use('/workspaces/:workspaceId/expense-claims', expenseClaimsRoutes);
router.use('/workspaces/:workspaceId/attendance', attendanceRoutes);
router.use('/workspaces/:workspaceId/time-tracking', timeTrackingRoutes);
// Person-scoped, not workspace-scoped — see me-attendance.routes.ts.
router.use('/me/attendance', meAttendanceRoutes);
router.use('/workspaces/:workspaceId/notifications', notificationsRoutes);
router.use('/cashbooks', cashbooksRoutes);
router.use('/cashbooks/:cashbookId/obligations', obligationsRouter);
router.use('/cashbooks/:cashbookId/peer-links', peerLinksCashbookRouter);
// Person-scoped, not workspace-scoped — a user's peer link inbox follows them
// across workspaces, like /me/attendance.
router.use('/peer-links', peerLinksRouter);
router.use('/entries', entriesRoutes);
router.use('/categories', categoriesRoutes);
router.use('/contacts', contactsRoutes);
router.use('/payment-modes', paymentModesRoutes);
router.use('/files', filesRoutes);
router.use('/reports', reportsRoutes);
router.use('/workspaces/:workspaceId/ledger-reports', ledgerReportsRoutes);
router.use('/workspaces/:workspaceId/chart-of-accounts', chartOfAccountsRoutes);
router.use('/audit', auditRoutes);
// Superadmin surface. Replaced the old /admin module, which duplicated all of
// this without audit logging.
router.use('/platform', platformRoutes);
router.use('/invites', invitesRoutes);

// ─── Workspace-wide obligations (Obligations page) ─────
router.use('/workspaces/:workspaceId/obligations', workspaceObligationsRouter);

// ─── Developer API Keys ───────────────────────────────
// Scoped to a workspace; requires MANAGE_API_KEYS permission (see api-keys.routes.ts).
router.use('/workspaces/:workspaceId/api-keys', apiKeysRoutes);

// ─── External Integration (API Key auth, not cookie JWT) ──
// Callers present X-API-Key header. No session required.
router.use('/integrate', integrationRoutes);

export default router;

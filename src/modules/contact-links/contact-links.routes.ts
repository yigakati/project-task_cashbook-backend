import { Router } from 'express';
import { container } from 'tsyringe';
import { ContactLinksController } from './contact-links.controller';
import { WorkspaceProfileController } from '../workspace-profile/workspace-profile.controller';
import { authenticate } from '../../middlewares/authenticate';
import { validate } from '../../middlewares/validate';
import { requireWorkspaceMember } from '../../middlewares/authorize';
import { WorkspacePermission } from '../../core/types/workspace-permissions';
import { updateWorkspaceProfileSchema } from '../workspace-profile/workspace-profile.dto';
import {
    lookupRecipientSchema,
    createContactLinkRequestSchema,
    acceptContactLinkRequestSchema,
    declineContactLinkRequestSchema,
    contactLinkRequestQuerySchema,
} from './contact-links.dto';

/**
 * Connecting contacts, split across two mounts for the same reason peer links
 * are:
 *
 *   /workspaces/:workspaceId/contact-links   acting AS a workspace — searching,
 *                                            sending, cancelling, disconnecting
 *   /contact-links                           the person's own inbox. Scoped to
 *                                            the user on purpose: a request is
 *                                            addressed to them, and which of
 *                                            their workspaces answers is the
 *                                            decision they make by accepting.
 */
export const contactLinksWorkspaceRouter = Router({ mergeParams: true });
export const contactLinksRouter = Router();

const controller = container.resolve(ContactLinksController);
const profileController = container.resolve(WorkspaceProfileController);

// ─── Workspace-scoped ──────────────────────────────────

contactLinksWorkspaceRouter.use(authenticate as any);

contactLinksWorkspaceRouter.get(
    '/lookup',
    requireWorkspaceMember(WorkspacePermission.MANAGE_REFERENCE_DATA) as any,
    validate(lookupRecipientSchema, 'query'),
    controller.lookup.bind(controller) as any,
);

contactLinksWorkspaceRouter.get(
    '/requests',
    requireWorkspaceMember(WorkspacePermission.VIEW_WORKSPACE) as any,
    validate(contactLinkRequestQuerySchema, 'query'),
    controller.getOutgoing.bind(controller) as any,
);

contactLinksWorkspaceRouter.post(
    '/requests',
    requireWorkspaceMember(WorkspacePermission.MANAGE_REFERENCE_DATA) as any,
    validate(createContactLinkRequestSchema),
    controller.createRequest.bind(controller) as any,
);

contactLinksWorkspaceRouter.post(
    '/requests/:requestId/cancel',
    requireWorkspaceMember(WorkspacePermission.MANAGE_REFERENCE_DATA) as any,
    controller.cancelRequest.bind(controller) as any,
);

contactLinksWorkspaceRouter.post(
    '/contacts/:contactId/unlink',
    requireWorkspaceMember(WorkspacePermission.MANAGE_REFERENCE_DATA) as any,
    controller.unlink.bind(controller) as any,
);

// ─── The workspace's own details ───────────────────────
//
// Mounted here rather than in its own module: this is the half of the exchange
// a workspace gives away, and it is edited from the same settings screen.

contactLinksWorkspaceRouter.get(
    '/profile',
    requireWorkspaceMember(WorkspacePermission.VIEW_WORKSPACE) as any,
    profileController.get.bind(profileController) as any,
);

contactLinksWorkspaceRouter.patch(
    '/profile',
    requireWorkspaceMember(WorkspacePermission.UPDATE_WORKSPACE) as any,
    validate(updateWorkspaceProfileSchema),
    profileController.update.bind(profileController) as any,
);

// ─── Person-scoped inbox ───────────────────────────────

contactLinksRouter.use(authenticate as any);

contactLinksRouter.get(
    '/requests/incoming',
    validate(contactLinkRequestQuerySchema, 'query'),
    controller.getIncoming.bind(controller) as any,
);

contactLinksRouter.post(
    '/requests/:requestId/accept',
    validate(acceptContactLinkRequestSchema),
    controller.accept.bind(controller) as any,
);

contactLinksRouter.post(
    '/requests/:requestId/decline',
    validate(declineContactLinkRequestSchema),
    controller.decline.bind(controller) as any,
);

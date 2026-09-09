import { injectable, inject } from 'tsyringe';
import { PrismaClient, ReferralStatus, WorkspaceType } from '@prisma/client';
import { NotFoundError } from '../../core/errors/AppError';
import { config } from '../../config';

@injectable()
export class ReferralsService {
    constructor(@inject('PrismaClient') private prisma: PrismaClient) { }

    /**
     * An agent's own view of what they have brought in.
     *
     * Reachable only from the agent's PERSONAL workspace, and only by its
     * owner. Being a referral agent is a property of the person, not of any
     * business they happen to belong to — surfacing it inside a shared
     * business workspace would put one member's earnings in front of their
     * colleagues, which is nobody else's business.
     *
     * Everything that fails — not an agent, not their workspace, not a
     * personal one — answers 404 rather than 403. A workspace that has no
     * referral section should not be able to prove one exists.
     */
    async getAgentOverview(workspaceId: string, userId: string) {
        const workspace = await this.prisma.workspace.findUnique({
            where: { id: workspaceId },
            select: { id: true, type: true, ownerId: true },
        });

        if (
            !workspace
            || workspace.type !== WorkspaceType.PERSONAL
            || workspace.ownerId !== userId
        ) {
            throw new NotFoundError('Referral programme');
        }

        const agent = await this.prisma.referralAgent.findUnique({
            where: { userId },
            select: { id: true, code: true, isActive: true, appointedAt: true },
        });
        if (!agent || !agent.isActive) {
            throw new NotFoundError('Referral programme');
        }

        const [signedUp, verified, referrals] = await Promise.all([
            this.prisma.referral.count({
                where: { agentId: agent.id, status: ReferralStatus.SIGNED_UP },
            }),
            this.prisma.referral.count({
                where: { agentId: agent.id, status: ReferralStatus.VERIFIED },
            }),
            this.prisma.referral.findMany({
                where: { agentId: agent.id },
                orderBy: { attributedAt: 'desc' },
                take: 200,
                select: {
                    id: true,
                    status: true,
                    source: true,
                    signupMethod: true,
                    attributedAt: true,
                    verifiedAt: true,
                    // First name only, and no email: the agent needs to see
                    // that a referral landed, not a contactable list of the
                    // people behind them.
                    referredUser: { select: { firstName: true, createdAt: true } },
                },
            }),
        ]);

        return {
            code: agent.code,
            shareLink: buildShareLink(agent.code),
            appointedAt: agent.appointedAt,
            totals: { signedUp, verified, all: signedUp + verified },
            referrals,
        };
    }

    /** Whether to show the section at all, without revealing anything else. */
    async isActiveAgent(userId: string): Promise<boolean> {
        const agent = await this.prisma.referralAgent.findUnique({
            where: { userId },
            select: { isActive: true },
        });
        return Boolean(agent?.isActive);
    }
}

/**
 * The link an agent shares. Points at the signup page with the code attached,
 * so it survives whichever method the person then signs up with.
 */
export function buildShareLink(code: string): string {
    const base = config.APP_URL?.replace(/\/+$/, '') || '';
    return `${base}/signup?ref=${encodeURIComponent(code)}`;
}

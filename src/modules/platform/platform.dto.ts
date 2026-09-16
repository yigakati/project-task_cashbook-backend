import { z } from 'zod';

/**
 * Unlocking a module for one organisation.
 *
 * `feature` is an enum rather than a free string so a typo cannot silently
 * create a flag nothing reads — the guard looks up an exact FeatureKey, and a
 * misspelled row would leave the org locked out with no error anywhere.
 */
export const setWorkspaceFeatureSchema = z.object({
    feature: z.enum(['TICKETING']),
    enabled: z.boolean(),
});

export type SetWorkspaceFeatureDto = z.infer<typeof setWorkspaceFeatureSchema>;

/**
 * Appointing or revoking a referral agent.
 *
 * Revoking sets the flag false rather than deleting the agent: the referrals
 * already credited to them still have to point somewhere, and their history is
 * the whole point of the programme.
 */
export const setReferralAgentSchema = z.object({
    isActive: z.boolean(),
    notes: z.string().trim().max(500).optional(),
});

export type SetReferralAgentDto = z.infer<typeof setReferralAgentSchema>;

/**
 * A platform-wide switch. Applies to every workspace at once — see
 * PlatformSettingsService for why manual contact entry belongs here rather
 * than in the per-workspace feature grants.
 */
export const updatePlatformSettingsSchema = z.object({
    manualContactsEnabled: z.boolean().optional(),
    /** The storage allowance every workspace gets unless it has its own. */
    defaultStorageQuotaGb: z.number().positive().max(1024).optional(),
}).refine(
    (v) => v.manualContactsEnabled !== undefined || v.defaultStorageQuotaGb !== undefined,
    { message: 'Nothing to update' },
);

export type UpdatePlatformSettingsDto = z.infer<typeof updatePlatformSettingsSchema>;

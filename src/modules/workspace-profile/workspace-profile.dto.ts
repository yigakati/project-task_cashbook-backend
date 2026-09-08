import { z } from 'zod';

const optionalText = (max: number) => z.string().trim().max(max).nullable().optional();

export const updateWorkspaceProfileSchema = z.object({
    displayName: z.string().trim().min(1, 'A display name is required').max(200).optional(),
    legalName: optionalText(200),
    email: z.union([z.string().email('Invalid email address'), z.literal('')]).nullable().optional(),
    phone: optionalText(30),
    website: optionalText(200),
    taxId: optionalText(100),
    registrationNo: optionalText(100),
    addressLine1: optionalText(200),
    addressLine2: optionalText(200),
    city: optionalText(100),
    state: optionalText(100),
    postalCode: optionalText(30),
    country: optionalText(100),
    billingEmail: z.union([z.string().email('Invalid billing email'), z.literal('')]).nullable().optional(),
    paymentDetails: z.record(z.string(), z.any()).nullable().optional(),
});

export type UpdateWorkspaceProfileDto = z.infer<typeof updateWorkspaceProfileSchema>;

/**
 * The minimum a workspace must state about itself before it can be handed to
 * someone else as a contact: a name to show, and one way to reach it.
 *
 * Everything billing-related is deliberately outside this gate. A connection is
 * useful long before anyone has a tax id or a registered address, and demanding
 * them up front would stop people accepting a request for no good reason.
 */
export const REQUIRED_PROFILE_FIELDS = ['displayName', 'emailOrPhone'] as const;

export interface ProfileCompleteness {
    isComplete: boolean;
    missing: string[];
}

export function checkProfileCompleteness(
    profile: { displayName?: string | null; email?: string | null; phone?: string | null } | null,
): ProfileCompleteness {
    const missing: string[] = [];
    if (!profile?.displayName?.trim()) missing.push('displayName');
    if (!profile?.email?.trim() && !profile?.phone?.trim()) missing.push('emailOrPhone');
    return { isComplete: missing.length === 0, missing };
}

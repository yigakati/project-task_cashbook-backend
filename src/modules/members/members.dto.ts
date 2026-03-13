import { z } from 'zod';

export const inviteMemberSchema = z.object({
    email: z.string().email('Invalid email address'),
    role: z.enum(['ADMIN', 'MEMBER']).default('MEMBER'),
});

export const updateMemberRoleSchema = z.object({
    role: z.enum(['ADMIN', 'MEMBER']),
});

export const importMembersSchema = z.object({
    sourceWorkspaceId: z.string().uuid('Invalid source workspace ID'),
    members: z.array(
        z.object({
            userId: z.string().uuid('Invalid user ID'),
            role: z.enum(['ADMIN', 'MEMBER']).default('MEMBER'),
        })
    ).min(1, 'At least one member must be selected for import'),
});

export type InviteMemberDto = z.infer<typeof inviteMemberSchema>;
export type UpdateMemberRoleDto = z.infer<typeof updateMemberRoleSchema>;
export type ImportMembersDto = z.infer<typeof importMembersSchema>;

import { z } from 'zod';

export const inviteIdParamSchema = z.object({
    inviteId: z.string().uuid('Invalid invitation ID'),
}).passthrough();

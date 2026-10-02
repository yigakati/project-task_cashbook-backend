import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import { UsersRepository } from './users.repository';
import { NotFoundError } from '../../core/errors/AppError';
import { UpdateProfileDto } from './users.dto';
import {
    isPlatformSettingEnabled,
    PLATFORM_SETTINGS,
} from '../platform/platform-settings.service';

@injectable()
export class UsersService {
    constructor(
        private usersRepository: UsersRepository,
        @inject('PrismaClient') private prisma: PrismaClient,
    ) { }

    async getProfile(userId: string) {
        const user = await this.usersRepository.findById(userId);
        if (!user) {
            throw new NotFoundError('User');
        }

        // Platform-wide switches the client needs in order to show the right
        // actions. Carried on the profile it already loads, so gating a button
        // costs no extra request — and the endpoints enforce them regardless.
        const [manualContactsEnabled, pendingDeletion] = await Promise.all([
            isPlatformSettingEnabled(this.prisma, PLATFORM_SETTINGS.MANUAL_CONTACTS),
            // Signing in during the grace period has to offer the way back.
            this.prisma.accountDeletionRequest.findFirst({
                where: { userId, status: { in: ['SCHEDULED', 'BLOCKED', 'PROCESSING'] } },
                select: { id: true, status: true, scheduledFor: true },
            }),
        ]);

        return {
            ...this.toProfileResponse(user),
            platform: { manualContactsEnabled },
            pendingDeletion,
        };
    }

    async updateProfile(userId: string, dto: UpdateProfileDto) {
        const user = await this.usersRepository.findById(userId);
        if (!user) {
            throw new NotFoundError('User');
        }

        const updated = await this.usersRepository.updateProfile(userId, dto);
        return this.toProfileResponse(updated);
    }

    /**
     * `hasPassword` and `linkedProviders` are what the account-settings page
     * uses to decide "set up password" vs. "change password", and to show
     * which of Google/OC are connected — never the raw hash or the
     * join-table shape.
     */
    private toProfileResponse<T extends { passwordHash: string | null; linkedIdentities: { provider: string }[] }>(
        user: T,
    ) {
        const { passwordHash, linkedIdentities, ...rest } = user;
        return {
            ...rest,
            hasPassword: Boolean(passwordHash),
            linkedProviders: linkedIdentities.map((identity) => identity.provider),
        };
    }
}

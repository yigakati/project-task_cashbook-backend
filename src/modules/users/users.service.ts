import { injectable } from 'tsyringe';
import { UsersRepository } from './users.repository';
import { NotFoundError } from '../../core/errors/AppError';
import { UpdateProfileDto } from './users.dto';

@injectable()
export class UsersService {
    constructor(private usersRepository: UsersRepository) { }

    async getProfile(userId: string) {
        const user = await this.usersRepository.findById(userId);
        if (!user) {
            throw new NotFoundError('User');
        }
        return this.toProfileResponse(user);
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

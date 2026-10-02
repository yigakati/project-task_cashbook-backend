/**
 * Carries out account deletions whose grace period is over, and expires
 * confirmation links nobody used.
 *
 * A plain setInterval like the other schedulers. Safe on every replica: each
 * request is claimed with a conditional update before any work starts, so
 * two replicas can never process the same one.
 */
import { container } from 'tsyringe';
import { AccountDeletionService } from '../modules/account-deletion/account-deletion.service';
import { logger } from '../utils/logger';

const INTERVAL_MS = 60 * 60 * 1000; // hourly

async function run(): Promise<void> {
    try {
        const processed = await container.resolve(AccountDeletionService).processDue();
        if (processed > 0) logger.info('[AccountDeletion] Processed due deletions', { processed });
    } catch (error) {
        logger.error('[AccountDeletion] Scheduler pass failed', { error: (error as Error).message });
    }
}

export function startAccountDeletionScheduler(): NodeJS.Timeout {
    logger.info('[AccountDeletion] Starting deletion scheduler (interval: 60 min)');
    void run();
    return setInterval(run, INTERVAL_MS);
}

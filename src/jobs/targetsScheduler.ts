/**
 * Starts the next period of repeating targets, sends target alerts (behind
 * pace, reached, period ended) and the evening reminders to record.
 *
 * Hourly, like the other schedulers, and safe on every replica: each
 * rollover and alert is claimed with a conditional update before it happens.
 */
import { container } from 'tsyringe';
import { TargetsService } from '../modules/targets/targets.service';
import { logger } from '../utils/logger';

const INTERVAL_MS = 60 * 60 * 1000;

async function run(): Promise<void> {
    try {
        const { rolled, alerted, reminded } = await container.resolve(TargetsService).processScheduled();
        if (rolled > 0 || alerted > 0 || reminded > 0) logger.info('[Targets] Scheduled pass', { rolled, alerted, reminded });
    } catch (error) {
        logger.error('[Targets] Scheduled pass failed', { error: (error as Error).message });
    }
}

export function startTargetsScheduler(): NodeJS.Timeout {
    logger.info('[Targets] Starting targets scheduler (interval: 60 min)');
    void run();
    return setInterval(run, INTERVAL_MS);
}

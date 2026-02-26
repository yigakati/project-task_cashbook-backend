import { logger } from '../utils/logger';
import { createEmailWorker } from './email.worker';
// import { createReportsWorker } from './reports.worker';

/**
 * Bootstrap all BullMQ workers.
 * Call this from server.ts after the app starts.
 */
export function startWorkers() {
    logger.info('🚀 Starting BullMQ workers...');

    const emailWorker = createEmailWorker();
    // const reportsWorker = createReportsWorker();

    logger.info('✅ Email worker started (concurrency: 5)');
    // logger.info('✅ Reports worker started (concurrency: 2)');

    // Return workers for graceful shutdown
    return { emailWorker };
}

/**
 * Gracefully shut down all workers.
 */
export async function stopWorkers(workers: ReturnType<typeof startWorkers>) {
    logger.info('Shutting down BullMQ workers...');
    await Promise.all([
        workers.emailWorker.close(),
        // workers.reportsWorker.close(),
    ]);
    logger.info('✅ All workers stopped');
}

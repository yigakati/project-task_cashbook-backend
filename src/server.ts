import 'reflect-metadata';
import './config/container';
import app from './app';
import { config } from './config';
import { logger } from './utils/logger';
import { getPrismaClient } from './config/database';
import { getRedisClient } from './config/redis';
import { ensureBucket } from './config/minio';
import { startWorkers, stopWorkers } from './workers';
import { startDeadlineScheduler } from './jobs/deadlineScheduler';
import { startMaintenanceScheduler } from './jobs/maintenanceScheduler';
import { startAttendanceScheduler } from './jobs/attendanceScheduler';
import { startAccountDeletionScheduler } from './jobs/accountDeletionScheduler';
import { verifyEmailTransport } from './config/email';
import { PlatformService } from './modules/platform/platform.service';

const PORT = config.PORT;

async function bootstrap() {
    try {
        // Test database connection
        const prisma = getPrismaClient();
        await prisma.$connect();
        logger.info('✅ Database connected');

        // Test Redis connection
        try {
            const redis = getRedisClient();
            await redis.ping();
            logger.info('✅ Redis connected');
        } catch (redisError) {
            logger.warn('⚠️  Redis connection failed, some features may be degraded', { error: redisError });
        }

        // Ensure MinIO bucket exists
        try {
            await ensureBucket();
        } catch (minioError) {
            logger.warn('⚠️  MinIO connection failed, file features may be degraded', { error: minioError });
        }

        // Make superadmin grants match SUPER_ADMIN_EMAILS. Non-fatal: a failure
        // here must not stop the API from serving.
        try {
            const { container } = await import('tsyringe');
            const result = await container.resolve(PlatformService).reconcileSuperAdmins();
            logger.info('Superadmin reconciliation complete', {
                configured: result.configured.length,
                promoted: result.promoted.length,
                demoted: result.demoted.length,
            });
        } catch (error) {
            logger.warn('⚠️  Superadmin reconciliation failed', { error });
        }

        // Start BullMQ workers
        let workers: ReturnType<typeof startWorkers> | null = null;
        let schedulerInterval: NodeJS.Timeout | null = null;
        let maintenanceInterval: NodeJS.Timeout | null = null;
        let attendanceInterval: NodeJS.Timeout | null = null;
        let accountDeletionInterval: NodeJS.Timeout | null = null;
        try {
            workers = startWorkers();
            // One clear line at boot beats discovering the problem from a user
            // whose invite never arrived. Deliberately not awaited into the
            // startup path — a slow SMTP host must not delay accepting traffic.
            void verifyEmailTransport();
            schedulerInterval = startDeadlineScheduler();
            maintenanceInterval = startMaintenanceScheduler();
            attendanceInterval = startAttendanceScheduler();
            accountDeletionInterval = startAccountDeletionScheduler();
        } catch (workerError) {
            logger.warn('⚠️  Failed to start workers, background jobs will not process', { error: workerError });
        }

        // Start HTTP server
        const server = app.listen(PORT, () => {
            logger.info(`🚀 Server running on port ${PORT} in ${config.NODE_ENV} mode`);
        });

        // ─── Graceful Shutdown ─────────────────────────────
        const shutdown = async (signal: string) => {
            logger.info(`${signal} received. Starting graceful shutdown...`);

            server.close(async () => {
                logger.info('HTTP server closed');

                try {
                    await prisma.$disconnect();
                    logger.info('Database disconnected');
                } catch (err) {
                    logger.error('Error disconnecting database', { error: err });
                }

                try {
                    const redis = getRedisClient();
                    redis.disconnect();
                    logger.info('Redis disconnected');
                } catch (err) {
                    logger.error('Error disconnecting Redis', { error: err });
                }

                // Stop BullMQ workers and scheduler
                if (schedulerInterval) clearInterval(schedulerInterval);
                if (maintenanceInterval) clearInterval(maintenanceInterval);
                if (attendanceInterval) clearInterval(attendanceInterval);
                if (accountDeletionInterval) clearInterval(accountDeletionInterval);
                if (workers) {
                    try {
                        await stopWorkers(workers);
                    } catch (err) {
                        logger.error('Error stopping workers', { error: err });
                    }
                }

                logger.info('Graceful shutdown complete');
                process.exit(0);
            });

            // Force shutdown after 30 seconds
            setTimeout(() => {
                logger.error('Forced shutdown after timeout');
                process.exit(1);
            }, 30000);
        };

        process.on('SIGTERM', () => shutdown('SIGTERM'));
        process.on('SIGINT', () => shutdown('SIGINT'));

        // Handle unhandled rejections
        process.on('unhandledRejection', (reason, promise) => {
            logger.error('Unhandled rejection', { reason, promise });
        });

        process.on('uncaughtException', (error) => {
            logger.error('Uncaught exception', { error });
            process.exit(1);
        });
    } catch (error) {
        logger.error('Failed to start server', { error });
        process.exit(1);
    }
}

bootstrap();

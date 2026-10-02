import { Worker, Job } from 'bullmq';
import { bullmqConnection } from '../config/queues';
import { getEmailTransporter, isEmailConfigured } from '../config/email';
import { config } from '../config';
import { logger } from '../utils/logger';

export interface EmailJobData {
    to: string;
    subject: string;
    html: string;
    replyTo?: string;
    attachments?: Array<{
        filename: string;
        content: string; // base64-encoded
        contentType: string;
    }>;
}

/**
 * BullMQ Email Worker.
 * Processes email jobs from the 'email' queue using nodemailer.
 */
export function createEmailWorker(): Worker<EmailJobData> {
    const worker = new Worker<EmailJobData>(
        'email',
        async (job: Job<EmailJobData>) => {
            const { to, subject, html, replyTo, attachments } = job.data;

            logger.info('Processing email job', { jobId: job.id, to, subject });

            // A job queued while SMTP was configured can still be picked up
            // after it was removed. Discard it with a clear reason instead of
            // failing three times against blank credentials.
            if (!isEmailConfigured()) {
                logger.warn('Discarding email job: SMTP is not configured', {
                    jobId: job.id, to, subject,
                });
                return;
            }

            const transport = getEmailTransporter();

            const mailAttachments = attachments?.map((att) => ({
                filename: att.filename,
                content: Buffer.from(att.content, 'base64'),
                contentType: att.contentType,
            }));

            await transport.sendMail({
                from: `"${config.EMAIL_FROM_NAME}" <${config.EMAIL_FROM}>`,
                to,
                subject,
                html,
                replyTo,
                attachments: mailAttachments,
            });

            logger.info('Email sent successfully', { jobId: job.id, to, subject });
        },
        {
            connection: bullmqConnection,
            concurrency: 5,
            limiter: {
                max: 10,
                duration: 1000,
            },
        }
    );

    worker.on('failed', (job, err) => {
        logger.error('Email job failed', {
            jobId: job?.id,
            to: job?.data?.to,
            error: err.message,
            attemptsMade: job?.attemptsMade,
        });
    });

    worker.on('completed', (job) => {
        logger.debug('Email job completed', { jobId: job.id });
    });

    return worker;
}

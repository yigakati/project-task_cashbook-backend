/**
 * Runs ONCE per vitest run, in the main process, before any worker starts.
 *
 * Responsibilities, in order:
 *   1. stamp a run id into process.env — every pool worker inherits it, so
 *      they all derive the same private-database name for their thread;
 *   2. make sure the base database exists (self-bootstrapping: a fresh
 *      checkout needs only a running Postgres, not a manual createdb);
 *   3. `prisma migrate deploy` exactly once per run — the single-threaded
 *      harness used to spawn this per test file (~1-3s × 51 files of pure
 *      overhead), which was the largest fixed cost in the suite;
 *   4. truncate the base so it is a PRISTINE template — schema and migration
 *      history only, no rows. Workers clone it with CREATE DATABASE ...
 *      TEMPLATE, which copies tables, triggers, functions and sequences in a
 *      few hundred milliseconds;
 *   5. drop worker databases orphaned by runs that crashed before teardown.
 *
 * Teardown drops this run's worker databases. DROP ... WITH (FORCE) survives
 * a lingering pool connection, so it does not depend on shutdown ordering.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { PrismaClient } from '@prisma/client';
import {
    ROOT,
    adminUrlFor,
    baseDbName,
    isPidAlive,
    loadTestEnv,
    testRunId,
    truncatePublicTables,
    workerDbPid,
} from './test-db';

const execFileAsync = promisify(execFile);

function quoteIdent(name: string): string {
    if (name.includes('"')) {
        throw new Error(`Refusing to use database name "${name}" as a SQL identifier`);
    }
    return `"${name}"`;
}

function isAlreadyExistsError(e: unknown): boolean {
    const message = e instanceof Error ? e.message : String(e);
    return message.includes('already exists') || message.includes('42P04');
}

async function dropDatabases(
    admin: PrismaClient,
    pattern: string,
    base: string,
    keepAlivePids = false,
): Promise<void> {
    const stale = await admin.$queryRawUnsafe(
        `SELECT datname FROM pg_database WHERE datname LIKE $1`,
        pattern,
    );
    for (const row of stale as Array<{ datname: string }>) {
        const pid = workerDbPid(row.datname, base);
        // keepAlivePids=false drops every match (teardown of our own run);
        // otherwise only databases whose creating process is gone.
        if (keepAlivePids && pid !== null && isPidAlive(pid)) continue;
        await admin.$executeRawUnsafe(`DROP DATABASE ${quoteIdent(row.datname)} WITH (FORCE)`);
    }
}

export default async function globalSetup() {
    loadTestEnv();

    const testUrl = process.env.DATABASE_URL_TEST;
    if (!testUrl) {
        throw new Error(
            'DATABASE_URL_TEST is not set. Copy .env.test.example to .env.test and point it at a ' +
                'throwaway Postgres database. Tests refuse to run against DATABASE_URL to avoid ' +
                'truncating development data.',
        );
    }
    if (testUrl === process.env.DATABASE_URL) {
        throw new Error(
            'DATABASE_URL_TEST must differ from DATABASE_URL. The test harness truncates every ' +
                'table between tests.',
        );
    }

    const runId = testRunId();
    // Pool workers inherit the main process env, so this reaches setup.ts in
    // every worker and makes them all derive the same database name.
    process.env.__CASHBOOK_TEST_RUN_ID = runId;

    const base = baseDbName(testUrl);
    const admin = new PrismaClient({ datasources: { db: { url: adminUrlFor(testUrl) } } });

    try {
        // Self-bootstrap: create the base database if this is a fresh machine.
        // CREATE DATABASE cannot run inside a transaction; Prisma sends single
        // raw statements outside one, which is why this works at all.
        try {
            await admin.$executeRawUnsafe(`CREATE DATABASE ${quoteIdent(base)}`);
        } catch (e) {
            if (!isAlreadyExistsError(e)) throw e;
        }

        // The one and only migration pass per run.
        await execFileAsync('npx', ['prisma', 'migrate', 'deploy'], {
            cwd: ROOT,
            env: { ...process.env, DATABASE_URL: testUrl },
        });

        // A pristine template: any leftover rows from an old-harness run (or a
        // crashed one) would otherwise be cloned into every worker.
        const template = new PrismaClient({ datasources: { db: { url: testUrl } } });
        try {
            await truncatePublicTables(template);
        } finally {
            await template.$disconnect();
        }

        // Worker databases of runs that died before their teardown ran.
        await dropDatabases(admin, `${base}\\_w%`, base, true);
    } finally {
        await admin.$disconnect();
    }

    return async () => {
        const admin = new PrismaClient({ datasources: { db: { url: adminUrlFor(testUrl) } } });
        try {
            await dropDatabases(admin, `${base}\\_w%_${runId}`, base);
        } finally {
            await admin.$disconnect();
        }
    };
}

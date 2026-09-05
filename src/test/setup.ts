/**
 * Per-worker test harness setup.
 *
 * Every vitest pool thread gets its own private Postgres database — a clone of
 * the migrated template built once per run by global-setup.ts. Because
 * nothing is shared between workers, test FILES run in parallel and each
 * worker runs its files one at a time; the TRUNCATE-based reset that used to
 * coordinate 51 serialized files now only wipes one worker's own database.
 *
 * This file is re-evaluated per test file (vitest restarts the module
 * context), so everything that must persist across files lives on globalThis:
 * the PrismaClient instance and the clone-creation promise.
 */
import 'reflect-metadata';
import { afterAll, beforeAll } from 'vitest';
import { PrismaClient } from '@prisma/client';
import {
    adminUrlFor,
    baseDbName,
    loadTestEnv,
    truncatePublicTables,
    workerUrlFor,
} from './test-db';

loadTestEnv();

const TEST_DATABASE_URL = process.env.DATABASE_URL_TEST;
if (!TEST_DATABASE_URL) {
    throw new Error(
        'DATABASE_URL_TEST is not set. Copy .env.test.example to .env.test and point it at a ' +
        'throwaway Postgres database. Tests refuse to run against DATABASE_URL to avoid ' +
        'truncating development data.',
    );
}

// Everything downstream (config/index.ts, PrismaClient, services) reads DATABASE_URL.
// Derived values are computed at module scope because const-narrowing of
// TEST_DATABASE_URL does not follow into hoisted function bodies.
const WORKER_URL = workerUrlFor(TEST_DATABASE_URL);
const WORKER_DB_NAME = baseDbName(WORKER_URL);
const ADMIN_URL = adminUrlFor(TEST_DATABASE_URL);
const BASE_DB_NAME = baseDbName(TEST_DATABASE_URL);
process.env.DATABASE_URL = WORKER_URL;
process.env.NODE_ENV = 'test';

// bcrypt at the production cost (12 rounds, ~300ms/call) makes any
// register/login path CPU-bound. Security of the hash is not under test, so
// the cheapest standard cost runs instead. Must be set before config/index.ts
// is imported by any service, which is why it happens here and not in a test.
process.env.BCRYPT_SALT_ROUNDS = process.env.BCRYPT_SALT_ROUNDS ?? '4';

interface WorkerState {
    prisma?: PrismaClient;
    cloning?: Promise<void>;
}

// Survives the per-file module reset; unique per worker thread.
const state: WorkerState = (() => {
    const g = globalThis as typeof globalThis & { __CASHBOOK_TEST_WORKER?: WorkerState };
    if (!g.__CASHBOOK_TEST_WORKER) g.__CASHBOOK_TEST_WORKER = {};
    return g.__CASHBOOK_TEST_WORKER;
})();

function quoteIdent(name: string): string {
    if (name.includes('"')) {
        throw new Error(`Refusing to use database name "${name}" as a SQL identifier`);
    }
    return `"${name}"`;
}

/**
 * Create this worker's private database from the migrated template.
 *
 * Worker startups overlap: up to maxThreads clones begin together, and
 * Postgres refuses a CREATE DATABASE whose template has other backends
 * reading it (SQLSTATE 55006, "source database is being accessed by other
 * users"). Each worker clones to its OWN name, so there is no conflict to
 * avoid — only the shared template read to take turns on. The losers retry
 * briefly; the winner's copy takes a few hundred milliseconds.
 */
async function createFromTemplate(admin: PrismaClient): Promise<void> {
    const maxAttempts = 6;
    for (let attempt = 1; ; attempt++) {
        try {
            await admin.$executeRawUnsafe(
                `CREATE DATABASE ${quoteIdent(WORKER_DB_NAME)} TEMPLATE ${quoteIdent(BASE_DB_NAME)}`,
            );
            return;
        } catch (e) {
            const message = e instanceof Error ? e.message : String(e);
            const templateBusy = message.includes('55006')
                || message.includes('being accessed by other users');
            if (!templateBusy || attempt >= maxAttempts) throw e;
            await new Promise((resolve) => setTimeout(resolve, 250 * attempt));
        }
    }
}

/**
 * Create this worker's private database by cloning the migrated template.
 *
 * Guarded by a promise on globalThis so concurrent imports of setup.ts (one
 * per test file, if vitest ever collects files in parallel inside a worker)
 * cannot race the CREATE. DROP ... IF EXISTS first because a crashed earlier
 * run of this same worker id + run id can leave one behind — global-setup
 * only cleans up databases whose creating process is dead.
 */
function ensureWorkerDatabase(): Promise<void> {
    if (state.cloning) return state.cloning;

    state.cloning = (async () => {
        const admin = new PrismaClient({ datasources: { db: { url: ADMIN_URL } } });
        try {
            await admin.$executeRawUnsafe(`DROP DATABASE IF EXISTS ${quoteIdent(WORKER_DB_NAME)} WITH (FORCE)`);
            await createFromTemplate(admin);
        } finally {
            await admin.$disconnect();
        }
    })().catch((e) => {
        // A failed clone must not be cached as a success for later files.
        state.cloning = undefined;
        throw e;
    });

    return state.cloning;
}

export const testPrisma: PrismaClient = (() => {
    if (state.prisma) return state.prisma;
    const client = new PrismaClient({
        datasources: { db: { url: WORKER_URL } },
        log: ['warn', 'error'],
    });
    state.prisma = client;
    return client;
})();

/**
 * Wipe all data in THIS worker's database. Runs once per test file in
 * beforeAll below; individual files add their own beforeEach(resetDatabase)
 * where tests need a clean slate per case.
 */
export async function resetDatabase(): Promise<void> {
    await truncatePublicTables(testPrisma);
}

beforeAll(async () => {
    await ensureWorkerDatabase();
    await resetDatabase();
}, 120_000);

afterAll(async () => {
    // The client is cached on globalThis and reused by the next file in this
    // worker; global-setup's teardown drops the database WITH (FORCE), so a
    // pooled connection lingering here is harmless.
    await testPrisma.$disconnect().catch(() => { });
});

/**
 * Shared plumbing for the test-database lifecycle. Imported by BOTH
 * global-setup.ts (main vitest process) and setup.ts (per worker), so it must
 * not import anything that reads DATABASE_URL at module scope.
 *
 * Layout per run:
 *
 *   {base}                     the template — migrated once per run by
 *                              global-setup, then kept pristine (no test ever
 *                              connects to it directly).
 *   {base}_w{poolId}_{runId}   one clone per worker thread, created by
 *                              TEMPLATE on the worker's first test file and
 *                              dropped by global-setup teardown.
 *
 * Cloning (rather than re-migrating) gives each worker a fully isolated
 * database — schema, triggers, sequences and all — in a few hundred
 * milliseconds, which is what makes file-level parallelism safe: nothing
 * coordinates through TRUNCATE any more, because nothing is shared.
 */
import 'reflect-metadata';
import { config as loadEnv } from 'dotenv';
import path from 'node:path';

export const ROOT = path.resolve(__dirname, '..', '..');

/**
 * .env.test wins over .env so a stray DATABASE_URL can never point tests at
 * dev data. Loaded with override so the test file's values stomp whatever the
 * developer's shell exported; .env is then loaded WITHOUT override so it only
 * fills gaps. Idempotent enough to call from both global-setup and setup.
 */
export function loadTestEnv(): void {
    for (const file of ['.env.test', '.env']) {
        loadEnv({ path: path.join(ROOT, file), override: file === '.env.test' });
    }
}

/** Parsed test-database URL. Throws early with the raw value if unparseable. */
export function parseTestDatabaseUrl(url: string): URL {
    try {
        return new URL(url);
    } catch {
        throw new Error(`DATABASE_URL_TEST is not a valid URL: ${url}`);
    }
}

/** The database name segment of a Postgres URL, e.g. "cashbook_test". */
export function baseDbName(url: string): string {
    return decodeURIComponent(parseTestDatabaseUrl(url).pathname.replace(/^\//, ''));
}

/** Same server/credentials, pointed at the "postgres" maintenance database. */
export function adminUrlFor(url: string): string {
    const parsed = parseTestDatabaseUrl(url);
    parsed.pathname = '/postgres';
    return parsed.toString();
}

/**
 * Identify the current vitest run across all worker threads. The main process
 * stamps it into process.env in global-setup; pool workers inherit their env
 * from the main process, so every worker derives the same id. The embedded pid
 * lets a LATER run recognise databases orphaned by a crashed one (see
 * dropDeadWorkerDatabases in global-setup.ts).
 */
export function testRunId(): string {
    const inherited = process.env.__CASHBOOK_TEST_RUN_ID;
    if (inherited && /^[0-9]+x[0-9a-z]+$/.test(inherited)) return inherited;
    return `${process.pid}x${Date.now().toString(36)}`;
}

/** VITEST_POOL_ID is tinypool's 1-based thread id; stable for a thread's life. */
function poolId(): number {
    const raw = process.env.VITEST_POOL_ID ?? '1';
    return /^\d+$/.test(raw) && Number(raw) > 0 ? Number(raw) : 1;
}

/**
 * The URL a worker's Prisma clients connect to: its private clone, plus a
 * connection cap so N workers × (test client + any lazily-created app client)
 * stay well inside Postgres' max_connections. Tests fan out up to ~12 parallel
 * transactions; 10 leaves headroom while queueing the excess.
 */
export function workerUrlFor(url: string): string {
    const parsed = parseTestDatabaseUrl(url);
    parsed.pathname = `/${encodeURIComponent(`${baseDbName(url)}_w${poolId()}_${testRunId()}`)}`;
    parsed.searchParams.set('connection_limit', '10');
    return parsed.toString();
}

/** Extract the embedded pid from a worker-database name, or null if not ours. */
export function workerDbPid(dbName: string, base: string): number | null {
    const escaped = base.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const m = dbName.match(new RegExp(`^${escaped}_w(\\d+)_(\\d+)x[0-9a-z]+$`));
    return m ? Number(m[2]) : null;
}

/** Is a pid still alive? ESRCH means dead; EPERM means alive but not ours. */
export function isPidAlive(pid: number): boolean {
    try {
        process.kill(pid, 0);
        return true;
    } catch (e) {
        return (e as NodeJS.ErrnoException).code === 'EPERM';
    }
}

/** Tables never cleared between tests (none yet — kept for future reference data). */
const PRESERVED_TABLES = new Set<string>([]);

/**
 * Public-schema table list, cached on globalThis so it survives the per-file
 * module reset inside a worker (vitest re-imports setup.ts for every test
 * file; a module-level cache would re-query each time).
 */
async function tableNames(prisma: {
    $queryRaw: (query: TemplateStringsArray) => Promise<Array<{ tablename: string }>>;
}): Promise<string[]> {
    const g = globalThis as typeof globalThis & { __CASHBOOK_TEST_TABLES?: string[] };
    if (g.__CASHBOOK_TEST_TABLES) return g.__CASHBOOK_TEST_TABLES;

    const rows = await prisma.$queryRaw`
        SELECT tablename FROM pg_tables
        WHERE schemaname = 'public' AND tablename NOT LIKE '_prisma%'
    `;
    const names = rows
        .map((r) => r.tablename)
        .filter((t) => !PRESERVED_TABLES.has(t));
    g.__CASHBOOK_TEST_TABLES = names;
    return names;
}

/**
 * Wipe all data. The SET LOCAL + TRUNCATE pair runs in ONE transaction
 * (Prisma's array form) on ONE connection, so the ledger's append-only escape
 * hatch genuinely applies to the truncate. The old harness issued the two
 * statements as separate awaits outside a transaction — SET LOCAL then
 * applied only to its own implicit transaction on whichever pooled
 * connection served it, which worked only because no trigger fires on
 * TRUNCATE.
 */
export async function truncatePublicTables(prisma: {
    $queryRaw: (query: TemplateStringsArray) => Promise<Array<{ tablename: string }>>;
    $executeRawUnsafe: (query: string) => Promise<number>;
    $transaction: (ops: Promise<unknown>[]) => Promise<unknown>;
}): Promise<void> {
    const tables = await tableNames(prisma);
    if (tables.length === 0) return;
    const list = tables.map((t) => `"public"."${t}"`).join(', ');
    await prisma.$transaction([
        prisma.$executeRawUnsafe(`SET LOCAL app.allow_ledger_maintenance = 'on'`),
        prisma.$executeRawUnsafe(`TRUNCATE TABLE ${list} RESTART IDENTITY CASCADE`),
    ]);
}

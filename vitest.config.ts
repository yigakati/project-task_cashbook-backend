import { defineConfig } from 'vitest/config';
import swc from 'unplugin-swc';
import path from 'node:path';

/**
 * SWC transform and the `@` alias are duplicated into each project below on
 * purpose: inline `projects` each get their own Vite server and do NOT
 * inherit root-level plugins or resolve.alias from this file.
 */
const swcPlugin = () =>
    swc.vite({
        module: { type: 'es6' },
        jsc: {
            target: 'es2022',
            parser: { syntax: 'typescript', decorators: true },
            transform: { decoratorMetadata: true, legacyDecorator: true },
        },
    });

const atAlias = { '@': path.resolve(__dirname, 'src') };

export default defineConfig({
    test: {
        projects: [
            {
                // Pure unit tests — no database, no env validation, no setup
                // file. Historically these were serialized behind every
                // integration file by singleThread: true, adding ~10s of
                // migration spawn per file for tests that touch nothing.
                // A file belongs here only if it imports NOTHING that reaches
                // test/setup, config/index.ts or Prisma — idempotency.test.ts
                // looks middleware-ish but writes real rows.
                test: {
                    name: 'unit',
                    environment: 'node',
                    include: [
                        'src/core/finance/money.test.ts',
                        'src/core/finance/obligation-interest.test.ts',
                        'src/core/time/workspace-clock.test.ts',
                        'src/core/types/workspace-permissions.test.ts',
                        'src/core/ledger/rules/entry.rules.test.ts',
                        'src/middlewares/validate.test.ts',
                        'src/modules/ticketing/pricing.test.ts',
                    ],
                    coverage: {
                        provider: 'v8',
                        include: ['src/core/**', 'src/modules/**'],
                        exclude: ['**/*.dto.ts', '**/*.routes.ts', '**/*.test.ts', 'src/test/**'],
                    },
                },
                plugins: [swcPlugin()],
                resolve: { alias: atAlias },
            },
            {
                // Integration tests. Each pool thread clones the migrated
                // template database (global-setup.ts + setup.ts), so files
                // run in parallel across workers with zero coordination.
                test: {
                    name: 'integration',
                    environment: 'node',
                    include: ['src/**/*.test.ts'],
                    exclude: [
                        'src/core/finance/money.test.ts',
                        'src/core/finance/obligation-interest.test.ts',
                        'src/core/time/workspace-clock.test.ts',
                        'src/core/types/workspace-permissions.test.ts',
                        'src/core/ledger/rules/entry.rules.test.ts',
                        'src/middlewares/validate.test.ts',
                        'src/modules/ticketing/pricing.test.ts',
                    ],
                    globalSetup: ['src/test/global-setup.ts'],
                    setupFiles: ['src/test/setup.ts'],
                    testTimeout: 30_000,
                    hookTimeout: 120_000,
                    // A worker's first file pays ~0.5s to clone its database;
                    // later files in the same worker reuse it. maxThreads=4
                    // keeps 4 × (test client + app client) × pool comfortably
                    // inside Postgres' max_connections while giving ~4× the
                    // throughput of the old serialized harness.
                    pool: 'threads',
                    poolOptions: {
                        threads: { maxThreads: 4 },
                    },
                    fileParallelism: true,
                    coverage: {
                        provider: 'v8',
                        include: ['src/core/**', 'src/modules/**'],
                        exclude: ['**/*.dto.ts', '**/*.routes.ts', '**/*.test.ts', 'src/test/**'],
                    },
                },
                plugins: [swcPlugin()],
                resolve: { alias: atAlias },
            },
        ],
    },
});

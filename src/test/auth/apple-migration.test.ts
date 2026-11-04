import { afterEach, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { testPrisma as db } from '../setup';

const schemas: string[] = [];
afterEach(async () => {
    for (const schema of schemas.splice(0))
        await db.$executeRawUnsafe(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
});
async function sql(schema: string, source: string) {
    const url = new URL(process.env.DATABASE_URL!);
    await new Promise<void>((resolve, reject) => {
        const child = spawn('psql', ['-X', '-q', '-v', 'ON_ERROR_STOP=1'], {
            env: {
                ...process.env,
                PGHOST: url.hostname,
                PGPORT: url.port || '5432',
                PGUSER: decodeURIComponent(url.username),
                PGPASSWORD: decodeURIComponent(url.password),
                PGDATABASE: decodeURIComponent(url.pathname.slice(1)),
            },
            stdio: ['pipe', 'pipe', 'pipe'],
        });
        let error = '';
        child.stdout.resume();
        child.stderr.on('data', (data) => {
            error += data;
        });
        child.on('error', reject);
        child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(error))));
        child.stdin.end(`SET search_path TO "${schema}", public;\n${source}`);
    });
}
describe('Apple migration', () => {
    it.each([false, true])(
        'preserves existing identities and dependent balances (populated=%s)',
        async (populated) => {
            const schema = `apple_migration_${randomUUID().replace(/-/g, '')}`;
            schemas.push(schema);
            const id = randomUUID();
            await db.$executeRawUnsafe(`CREATE SCHEMA "${schema}"`);
            await sql(
                schema,
                `
            CREATE TYPE "AuthProvider" AS ENUM ('LOCAL', 'GOOGLE', 'OC');
            CREATE TABLE linked_identities (id UUID PRIMARY KEY, provider "AuthProvider", provider_id TEXT);
            CREATE TABLE financial_history (id UUID PRIMARY KEY, identity_id UUID REFERENCES linked_identities(id), amount NUMERIC(20,4));
            ${populated ? `INSERT INTO linked_identities VALUES ('${id}', 'GOOGLE', 'stable-sub'); INSERT INTO financial_history VALUES ('${randomUUID()}', '${id}', 123.125);` : ''}
        `,
            );
            await sql(
                schema,
                await readFile('prisma/migrations/0040_apple_auth/migration.sql', 'utf8'),
            );
            const identities = await db.$queryRawUnsafe(
                `SELECT id, provider::text, provider_id FROM "${schema}".linked_identities`,
            );
            expect(identities).toEqual(
                populated ? [{ id, provider: 'GOOGLE', provider_id: 'stable-sub' }] : [],
            );
            expect(
                await db.$queryRawUnsafe(`SELECT amount::text FROM "${schema}".financial_history`),
            ).toEqual(populated ? [{ amount: '123.1250' }] : []);
            const apple = randomUUID();
            await sql(
                schema,
                `INSERT INTO linked_identities VALUES ('${apple}', 'APPLE', 'apple-sub'); INSERT INTO apple_credentials VALUES ('${apple}', 'ios', 'encrypted-ios', now()), ('${apple}', 'web', 'encrypted-web', now()); DELETE FROM linked_identities WHERE id = '${apple}';`,
            );
            expect(
                await db.$queryRawUnsafe(
                    `SELECT count(*)::int AS count FROM "${schema}".apple_credentials`,
                ),
            ).toEqual([{ count: 0 }]);
        },
    );
});

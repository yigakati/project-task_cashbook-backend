import { afterEach, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { testPrisma as db } from '../../test/setup';
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
describe('invoice template migration', () => {
    it.each([false, true])(
        'preserves existing IDs, financial values and prior item order (populated=%s)',
        async (populated) => {
            const schema = `invoice_migration_${randomUUID().replace(/-/g, '')}`;
            schemas.push(schema);
            await db.$executeRawUnsafe(`CREATE SCHEMA "${schema}"`);
            await sql(
                schema,
                `CREATE TABLE invoice_settings (id INTEGER PRIMARY KEY, template TEXT); CREATE TABLE invoices (id INTEGER PRIMARY KEY, total_amount NUMERIC(20,4), amount_due NUMERIC(20,4)); CREATE TABLE invoice_items (id INTEGER PRIMARY KEY, invoice_id INTEGER REFERENCES invoices(id), name TEXT); ${populated ? "INSERT INTO invoice_settings VALUES (1, 'modern'); INSERT INTO invoices VALUES (7, 123.125, 23.125); INSERT INTO invoice_items VALUES (20, 7, 'Second'), (10, 7, 'First');" : ''}`,
            );
            await sql(
                schema,
                await readFile('prisma/migrations/0041_invoice_templates/migration.sql', 'utf8'),
            );
            expect(
                await db.$queryRawUnsafe(
                    `SELECT id, template, version, customization FROM "${schema}".invoice_settings`,
                ),
            ).toEqual(
                populated ? [{ id: 1, template: 'modern', version: 1, customization: {} }] : [],
            );
            expect(
                await db.$queryRawUnsafe(
                    `SELECT id, total_amount::text, amount_due::text, payment_terms FROM "${schema}".invoices`,
                ),
            ).toEqual(
                populated
                    ? [
                          {
                              id: 7,
                              total_amount: '123.1250',
                              amount_due: '23.1250',
                              payment_terms: null,
                          },
                      ]
                    : [],
            );
            expect(
                await db.$queryRawUnsafe(
                    `SELECT id, name, position FROM "${schema}".invoice_items ORDER BY position`,
                ),
            ).toEqual(
                populated
                    ? [
                          { id: 10, name: 'First', position: 0 },
                          { id: 20, name: 'Second', position: 1 },
                      ]
                    : [],
            );
        },
    );
});

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

/** Feed SQL over stdin; credentials never appear in command arguments/logs. */
async function sql(schema: string, source: string): Promise<void> {
    const url = new URL(process.env.DATABASE_URL!);
    const env = {
        ...process.env,
        PGHOST: url.hostname,
        PGPORT: url.port || '5432',
        PGUSER: decodeURIComponent(url.username),
        PGPASSWORD: decodeURIComponent(url.password),
        PGDATABASE: decodeURIComponent(url.pathname.slice(1)),
    };
    return new Promise((resolve, reject) => {
        const child = spawn('psql', ['-X', '-q', '-v', 'ON_ERROR_STOP=1'], {
            env,
            stdio: ['pipe', 'pipe', 'pipe'],
        });
        let errors = '';
        child.stdout.resume();
        child.stderr.on('data', (chunk) => {
            errors += chunk.toString();
        });
        child.on('error', reject);
        child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(errors))));
        child.stdin.end(`SET search_path TO "${schema}", public;\n${source}`);
    });
}
async function legacy() {
    const schema = `housing_migration_${randomUUID().replace(/-/g, '')}`;
    schemas.push(schema);
    await db.$executeRawUnsafe(`CREATE SCHEMA "${schema}"`);
    const old = await readFile('prisma/migrations/0037_housing_tenancies/migration.sql', 'utf8');
    const units = old.match(/CREATE TABLE "housing_units" \([\s\S]*?\n\);/)![0];
    await sql(
        schema,
        `
        CREATE TABLE workspaces (id UUID PRIMARY KEY);
        ${units}
        CREATE UNIQUE INDEX housing_units_workspace_id_name_key ON housing_units(workspace_id, name);
        CREATE TABLE housing_tenancies (
            id UUID PRIMARY KEY, unit_id UUID NOT NULL, workspace_id UUID NOT NULL,
            CONSTRAINT housing_tenancies_unit_id_fkey FOREIGN KEY (unit_id) REFERENCES housing_units(id)
        );
        CREATE TABLE rent_payments (id UUID PRIMARY KEY, tenancy_id UUID REFERENCES housing_tenancies(id), amount DECIMAL(20,4));
        CREATE TABLE attachments (id UUID PRIMARY KEY, housing_unit_id UUID REFERENCES housing_units(id), s3_key TEXT);
    `,
    );
    const workspace = randomUUID();
    await sql(schema, `INSERT INTO workspaces VALUES ('${workspace}');`);
    return { schema, workspace };
}
const migration = () => readFile('prisma/migrations/0039_housing_properties/migration.sql', 'utf8');

describe('housing properties migration', () => {
    it('migrates an empty database', async () => {
        const f = await legacy();
        await sql(f.schema, await migration());
        expect(
            await db.$queryRawUnsafe(
                `SELECT count(*)::int AS count FROM "${f.schema}".housing_properties`,
            ),
        ).toEqual([{ count: 0 }]);
    });

    it('groups only exact named/addressed matches, separates currencies/ambiguous units and preserves dependencies', async () => {
        const f = await legacy();
        const ids = Array.from({ length: 6 }, () => randomUUID());
        const tenancy = randomUUID();
        await sql(
            f.schema,
            `
            INSERT INTO housing_units (id, workspace_id, name, property_name, address, currency, monthly_rent, updated_at) VALUES
                ('${ids[0]}', '${f.workspace}', 'A1', 'Sunrise', 'Ntinda', 'UGX', 100.125, now()),
                ('${ids[1]}', '${f.workspace}', 'A2', 'Sunrise', 'Ntinda', 'UGX', 200, now()),
                ('${ids[2]}', '${f.workspace}', 'A3', 'Sunrise', 'Ntinda', 'USD', 100, now()),
                ('${ids[3]}', '${f.workspace}', 'A4', 'Sunrise', NULL, 'UGX', 100, now()),
                ('${ids[4]}', '${f.workspace}', 'A5', 'Sunrise', NULL, 'UGX', 100, now()),
                ('${ids[5]}', '${f.workspace}', 'A6', NULL, 'Ntinda', 'UGX', 100, now());
            INSERT INTO housing_tenancies VALUES ('${tenancy}', '${ids[0]}', '${f.workspace}');
            INSERT INTO rent_payments VALUES ('${randomUUID()}', '${tenancy}', 35.125);
            INSERT INTO attachments VALUES ('${randomUUID()}', '${ids[0]}', 'private-photo.webp');
        `,
        );
        await sql(f.schema, await migration());
        const rows = await db.$queryRawUnsafe<Array<{ id: string; property_id: string }>>(
            `SELECT id, property_id FROM "${f.schema}".housing_units ORDER BY name`,
        );
        expect(rows.map((r) => r.id)).toEqual(ids);
        expect(rows[0].property_id).toBe(rows[1].property_id);
        expect(new Set(rows.map((r) => r.property_id)).size).toBe(5);
        const names = await db.$queryRawUnsafe<Array<{ name: string }>>(
            `SELECT name FROM "${f.schema}".housing_properties`,
        );
        expect(new Set(names.map((n) => n.name.toLowerCase())).size).toBe(5);
        expect(
            await db.$queryRawUnsafe(`SELECT amount::text FROM "${f.schema}".rent_payments`),
        ).toEqual([{ amount: '35.1250' }]);
        expect(
            await db.$queryRawUnsafe(
                `SELECT housing_unit_id, s3_key FROM "${f.schema}".attachments`,
            ),
        ).toEqual([{ housing_unit_id: ids[0], s3_key: 'private-photo.webp' }]);
    });

    it('rolls back completely with an actionable conflict instead of relabeling existing units', async () => {
        const f = await legacy();
        await sql(
            f.schema,
            `INSERT INTO housing_units (id, workspace_id, name, property_name, address, currency, monthly_rent, updated_at) VALUES
            ('${randomUUID()}', '${f.workspace}', 'A1', 'Sunrise', 'Ntinda', 'UGX', 100, now()),
            ('${randomUUID()}', '${f.workspace}', 'a1', 'Sunrise', 'Ntinda', 'UGX', 100, now());`,
        );
        await expect(sql(f.schema, await migration())).rejects.toThrow('duplicate unit label');
        expect(
            await db.$queryRawUnsafe(
                `SELECT name FROM "${f.schema}".housing_units ORDER BY name COLLATE "C"`,
            ),
        ).toEqual([{ name: 'A1' }, { name: 'a1' }]);
        expect(
            await db.$queryRawUnsafe(
                `SELECT to_regclass('"${f.schema}".housing_properties')::text AS name`,
            ),
        ).toEqual([{ name: null }]);
    });
});

import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { testPrisma } from '../../test/setup';

describe('invoice artwork migration', () => {
    it('adds optional artwork without changing saved designs, logos or versions', async () => {
        const schema = `artwork_${randomUUID().replace(/-/g, '')}`;
        const sql = readFileSync('prisma/migrations/0042_invoice_artwork/migration.sql', 'utf8');
        await testPrisma.$transaction(async (tx) => {
            await tx.$executeRawUnsafe(`CREATE SCHEMA "${schema}"`);
            await tx.$executeRawUnsafe(`SET LOCAL search_path TO "${schema}"`);
            await tx.$executeRawUnsafe(
                'CREATE TABLE invoice_settings (id TEXT PRIMARY KEY, template TEXT, logo_key TEXT, version INTEGER)',
            );
            await tx.$executeRawUnsafe(
                "INSERT INTO invoice_settings VALUES ('saved', 'executive', 'logos/original.png', 7)",
            );
            for (const statement of sql
                .split(';')
                .map((value) => value.trim())
                .filter(Boolean))
                await tx.$executeRawUnsafe(statement);
            const rows = await tx.$queryRawUnsafe<Array<Record<string, unknown>>>(
                'SELECT * FROM invoice_settings',
            );
            expect(rows).toEqual([
                {
                    id: 'saved',
                    template: 'executive',
                    logo_key: 'logos/original.png',
                    version: 7,
                    artwork_key: null,
                    artwork_size: null,
                },
            ]);
            await tx.$executeRawUnsafe(`DROP SCHEMA "${schema}" CASCADE`);
        });
    });
});

/**
 * Chart-of-accounts provisioning semantics.
 *
 * ensureWorkspaceChartOfAccounts is called from every workspace/cashbook/
 * wallet creation path, often re-running on workspaces that already have a
 * chart. Two contracts must hold no matter how the rows get inserted:
 *
 *   1. An accountant's rename survives a re-provision — the provisioner
 *      ensures existence, it never overwrites.
 *   2. The returned system map resolves every system key, including for a
 *      currency-scoped chart (secondary currency suffixes).
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { resetDatabase, testPrisma } from '../setup';
import { createWorkspace, createUser } from '../factories';
import {
    ensureWorkspaceChartOfAccounts,
    provisionWorkspaceAccounting,
} from '../../core/ledger/coa.seed';

describe('chart of accounts provisioning', () => {
    beforeEach(resetDatabase);

    it('never disturbs an accountant’s rename on re-provision', async () => {
        const user = await createUser();
        const workspace = await createWorkspace(user.id);

        await provisionWorkspaceAccounting(testPrisma, workspace.id, 'UGX');

        // The accountant renamed a protected system account, as the UI allows.
        const renamed = await testPrisma.ledgerAccount.update({
            where: { workspaceId_code: { workspaceId: workspace.id, code: '4100' } },
            data: { name: 'Sales of Photography Services' },
        });

        // A later re-provision (new cashbook, new wallet, whatever) must be a
        // no-op on that row: same id, rename intact.
        await provisionWorkspaceAccounting(testPrisma, workspace.id, 'UGX');
        await provisionWorkspaceAccounting(testPrisma, workspace.id, 'UGX');

        const after = await testPrisma.ledgerAccount.findUniqueOrThrow({
            where: { id: renamed.id },
        });
        expect(after.name).toBe('Sales of Photography Services');

        // And no duplicate rows appeared for the same codes.
        const codes = await testPrisma.ledgerAccount.findMany({
            where: { workspaceId: workspace.id },
            select: { code: true },
        });
        expect(new Set(codes.map((c) => c.code)).size).toBe(codes.length);
    });

    it('resolves every system key, including currency-scoped charts', async () => {
        const user = await createUser();
        const workspace = await createWorkspace(user.id);

        // Base chart first, then a secondary-currency chart with suffixed codes.
        await provisionWorkspaceAccounting(testPrisma, workspace.id, 'UGX');
        const systemMap = await ensureWorkspaceChartOfAccounts(
            testPrisma,
            workspace.id,
            'USD',
            'UGX',
        );

        expect(systemMap.size).toBeGreaterThan(0);
        for (const id of systemMap.values()) {
            expect(id).toBeTruthy();
        }

        // The scoped chart landed under suffixed codes, distinct from the base.
        const usdRow = await testPrisma.ledgerAccount.findFirstOrThrow({
            where: { workspaceId: workspace.id, code: '4100-USD' },
        });
        expect(usdRow.currency).toBe('USD');
        expect(usdRow.name).toContain('(USD)');
    });

    it('is safe when two provisions race inside overlapping transactions', async () => {
        const user = await createUser();
        const workspace = await createWorkspace(user.id);

        // Two concurrent provisions of the same chart — the shape of a
        // workspace-creation transaction overlapping a cashbook creation.
        const [, second] = await Promise.all([
            ensureWorkspaceChartOfAccounts(testPrisma, workspace.id, 'UGX'),
            ensureWorkspaceChartOfAccounts(testPrisma, workspace.id, 'UGX'),
        ]);

        // Both maps resolve, and the chart has exactly one row per code.
        expect(second.size).toBeGreaterThan(0);
        const rows = await testPrisma.ledgerAccount.findMany({
            where: { workspaceId: workspace.id },
            select: { code: true },
        });
        expect(new Set(rows.map((r) => r.code)).size).toBe(rows.length);
    });
});

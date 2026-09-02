/**
 * Rent-only items and the units vocabulary.
 *
 * The rent-only creation bug: the frontend sends `defaultSellingPrice: null`
 * (not absent — explicitly null) for items that don't sell, and Zod's plain
 * `.optional()` rejects null. These tests pin the contract: null is an
 * explicit clear, cost methods belong only to items that sell, and the units
 * vocabulary behaves as the curators of unit names.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { resetDatabase, testPrisma } from '../setup';
import { resolveService } from '../container';
import { InventoryService } from '../../modules/inventory/inventory.service';
import { UnitsOfMeasureService } from '../../modules/inventory/units-of-measure.service';
import { createWorkspace, createUser } from '../factories';

const inventory = () => resolveService(InventoryService);
const units = () => resolveService(UnitsOfMeasureService);

async function fixture() {
    const user = await createUser();
    const workspace = await createWorkspace(user.id);
    return { user, workspace };
}

describe('rent-only inventory items', () => {
    beforeEach(resetDatabase);

    it('accepts an explicit null selling price — the frontend bug', async () => {
        const f = await fixture();
        // Exactly what the item form sent when "Rent only" was picked.
        const item: any = await inventory().createItem(f.workspace.id, f.user.id, {
            name: 'Projector',
            unit: 'pcs',
            commercialMode: 'RENT_ONLY',
            defaultSellingPrice: null,
            sellingPrice: null,
            defaultRentalRate: '50000',
            defaultRentalPeriodUnit: 'DAY',
            costMethod: undefined,
            allowNegativeStock: false,
        } as any);

        expect(item.commercialMode).toBe('RENT_ONLY');
        expect(item.defaultSellingPrice).toBeNull();
        expect(item.defaultRentalRate?.toString()).toBe('50000');
    });

    it('refuses a cost method on a rent-only item', async () => {
        const f = await fixture();
        await expect(inventory().createItem(f.workspace.id, f.user.id, {
            name: 'Tent',
            unit: 'pcs',
            commercialMode: 'RENT_ONLY',
            costMethod: 'FIFO',
            allowNegativeStock: false,
        } as any)).rejects.toMatchObject({ code: 'RENT_ONLY_HAS_NO_COST_METHOD' });
    });

    it('sell-only items still accept a cost method', async () => {
        const f = await fixture();
        const item: any = await inventory().createItem(f.workspace.id, f.user.id, {
            name: 'Soda',
            unit: 'bottles',
            commercialMode: 'SELL_ONLY',
            costMethod: 'FIFO',
            allowNegativeStock: false,
        } as any);
        expect(item.costMethod).toBe('FIFO');
    });

    it('defaults the cost method for sellable items that omit it', async () => {
        const f = await fixture();
        const item: any = await inventory().createItem(f.workspace.id, f.user.id, {
            name: 'Water',
            unit: 'bottles',
            commercialMode: 'SELL_ONLY',
            costMethod: undefined,
            allowNegativeStock: false,
        } as any);
        expect(item.costMethod).toBe('WEIGHTED_AVERAGE');
    });
});

describe('units of measure', () => {
    beforeEach(resetDatabase);

    it('creates, is idempotent by name, renames and propagates to items', async () => {
        const f = await fixture();

        const created = await units().create(f.workspace.id, f.user.id, 'bottles');
        // Re-creating the same name returns the same row — the picker fires
        // this on every selection.
        const again = await units().create(f.workspace.id, f.user.id, 'bottles');
        expect(again.id).toBe(created.id);

        // An item carries the unit by name…
        await inventory().createItem(f.workspace.id, f.user.id, {
            name: 'Soda', unit: 'bottles', commercialMode: 'SELL_ONLY',
            allowNegativeStock: false,
        } as any);

        // …so the rename updates it in step.
        await units().rename(created.id, f.workspace.id, f.user.id, 'crates');
        const item = await testPrisma.inventoryItem.findFirstOrThrow({
            where: { workspaceId: f.workspace.id },
        });
        expect(item.unit).toBe('crates');
    });

    it('refuses to delete a unit in use, allows when free', async () => {
        const f = await fixture();
        const unit = await units().create(f.workspace.id, f.user.id, 'pcs');

        await inventory().createItem(f.workspace.id, f.user.id, {
            name: 'Widget', unit: 'pcs', commercialMode: 'SELL_ONLY',
            allowNegativeStock: false,
        } as any);

        await expect(units().remove(unit.id, f.workspace.id, f.user.id))
            .rejects.toMatchObject({ code: 'UNIT_IN_USE' });

        const free = await units().create(f.workspace.id, f.user.id, 'metres');
        await units().remove(free.id, f.workspace.id, f.user.id);
        expect(await testPrisma.unitOfMeasure.count({ where: { workspaceId: f.workspace.id } })).toBe(1);
    });

    it('lists workspace-scoped and name-ordered', async () => {
        const f = await fixture();
        await units().create(f.workspace.id, f.user.id, 'kg');
        await units().create(f.workspace.id, f.user.id, 'pcs');

        const otherUser = await createUser();
        const otherWs = await createWorkspace(otherUser.id);
        await units().create(otherWs.id, otherUser.id, 'private-unit');

        const listed = await units().list(f.workspace.id);
        expect(listed.map((u) => u.name)).toEqual(['kg', 'pcs']);
    });
});

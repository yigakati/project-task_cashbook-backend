/**
 * Builds real service instances wired to the test database.
 *
 * Uses a child tsyringe container so registering the test PrismaClient does not
 * disturb the app container, and so services keep their real dependency graph
 * (no hand-wiring that could drift from production).
 */
import 'reflect-metadata';
import { container } from 'tsyringe';
import { testPrisma } from './setup';

const testContainer = container.createChildContainer();
testContainer.registerInstance('PrismaClient', testPrisma);

/*
 * Some services resolve collaborators lazily through the ROOT container
 * mid-transaction (e.g. InventoryService pulling EntriesService to avoid a
 * static import cycle) — `container.resolve(...)` from inside the service
 * cannot see child-container registrations. Register the test client on the
 * root as well so those lazy resolutions hit the same test database. The
 * child container above is kept so the app container stays untouched for
 * anything that never lazily resolves.
 */
container.registerInstance('PrismaClient', testPrisma);

export function resolveService<T>(token: new (...args: any[]) => T): T {
    return testContainer.resolve(token);
}

export { testContainer };

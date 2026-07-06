/**
 * STAGE 1 of the hermesadmin/hermesruntime role split.
 *
 * Design memo:
 *   hermes-personal-agent/azure/design/hermes-postgres-role-split.md
 *
 * Companion SQL migration:
 *   hermes-personal-agent/azure/sql/migrations/2026-07-05-add-hermesadmin-role.sql
 *
 * Locks in the shape + fallback behavior of the new
 * `withMaintenanceTransaction` helper on `PostgresEngine`:
 *
 *   1. Happy path — with a dedicated admin pool wired in, the helper
 *      opens a transaction on THAT pool and returns the callback's
 *      value.
 *   2. Fallback — when `GBRAIN_ADMIN_DATABASE_URL` is unset AND no
 *      admin pool has been memoised, the helper aliases to the
 *      runtime pool (`this.sql`). Behaviorally identical to today
 *      under the "hermesruntime still has BYPASSRLS" carry-over.
 *   3. Error bubble — if the admin pool rejects at `.begin()` (e.g.
 *      `role "hermesadmin" does not exist` because STAGE 1 SQL was
 *      not applied on this DB), the rejection surfaces to the
 *      caller unchanged.
 *
 * DB-free by design: pokes the private `_sql` / `_sqlAdmin` fields on
 * a bare `PostgresEngine` and calls the helper with a stub `.begin()`
 * — same runtime-poke pattern as
 * `postgres-engine-getter-selfheal.test.ts`. No live Postgres, no
 * mocks of the postgres.js tagged-template interface (which is
 * painful under bun ESM).
 */

import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import { PostgresEngine } from '../src/core/postgres-engine.ts';

type Beginable = {
  begin: (
    fn: (tx: unknown) => Promise<unknown>,
  ) => Promise<unknown>;
};

// A minimal `.begin()`-shaped stub. Records whether it was invoked so
// the fallback test can prove which pool served the transaction, and
// forwards the callback's return so happy-path assertions can inspect
// the unwrapped value.
function makeStubPool(label: string): Beginable & { calls: number } {
  const stub = {
    calls: 0,
    async begin(fn: (tx: unknown) => Promise<unknown>): Promise<unknown> {
      stub.calls++;
      // The tx handle passed to the callback is only used for its
      // identity in these tests — real callers would call `tx.unsafe(...)`
      // or `tx\`...\``, both of which live below the assertion surface.
      const tx = { __label: label };
      return await fn(tx);
    },
  };
  return stub;
}

// Reset env + engine state between tests so the lazy-init path is
// reachable from a fresh slate.
let savedAdminUrl: string | undefined;
beforeEach(() => {
  savedAdminUrl = process.env.GBRAIN_ADMIN_DATABASE_URL;
  delete process.env.GBRAIN_ADMIN_DATABASE_URL;
});
afterEach(() => {
  if (savedAdminUrl === undefined) {
    delete process.env.GBRAIN_ADMIN_DATABASE_URL;
  } else {
    process.env.GBRAIN_ADMIN_DATABASE_URL = savedAdminUrl;
  }
});

describe('PostgresEngine.withMaintenanceTransaction (STAGE 1 role split)', () => {
  it('happy path: routes through the admin pool when one is available', async () => {
    const engine = new PostgresEngine();
    const adminStub = makeStubPool('admin');
    const runtimeStub = makeStubPool('runtime');
    // Directly poke the memoised admin pool so `_ensureAdminPool`
    // short-circuits without touching the env var / opening a real
    // pool. Same field-poke pattern as
    // `postgres-engine-getter-selfheal.test.ts`.
    (engine as unknown as { _sqlAdmin: unknown })._sqlAdmin = adminStub;
    (engine as unknown as { _sql: unknown })._sql = runtimeStub;

    const result = await engine.withMaintenanceTransaction(async (tx) => {
      // The tx handle should be the one the ADMIN stub minted, not
      // the runtime stub's.
      return (tx as unknown as { __label: string }).__label;
    });

    expect(result).toBe('admin');
    expect(adminStub.calls).toBe(1);
    expect(runtimeStub.calls).toBe(0);
  });

  it('fallback: aliases to the runtime pool when GBRAIN_ADMIN_DATABASE_URL is unset', async () => {
    const engine = new PostgresEngine();
    const runtimeStub = makeStubPool('runtime');
    // No admin pool memoised, no env var → `_ensureAdminPool()`
    // returns `this.sql` (the runtime pool). This is the state STAGE 1
    // relies on to keep behavior identical to today.
    (engine as unknown as { _sql: unknown })._sql = runtimeStub;
    expect(process.env.GBRAIN_ADMIN_DATABASE_URL).toBeUndefined();

    const result = await engine.withMaintenanceTransaction(async (tx) => {
      return (tx as unknown as { __label: string }).__label;
    });

    expect(result).toBe('runtime');
    expect(runtimeStub.calls).toBe(1);
    // And no admin pool should have been memoised — a later env-var
    // flip during the same process must still be able to open a
    // dedicated pool.
    expect(
      (engine as unknown as { _sqlAdmin: unknown })._sqlAdmin,
    ).toBeNull();
  });

  it('error bubble: rejections from the admin pool surface unchanged', async () => {
    const engine = new PostgresEngine();
    // Simulate the STAGE 1 SQL migration not having been applied yet
    // on the target DB — `postgres()` connects, but the first
    // `.begin()` fails when the backend rejects the connection auth
    // or the role lookup. In practice this manifests as a
    // `role "hermesadmin" does not exist` error surfaced via
    // postgres.js's `PostgresError` class; here we assert the shape,
    // not the exact class, so the test does not depend on
    // postgres.js internals.
    const brokenAdminPool: Beginable = {
      async begin() {
        throw new Error('role "hermesadmin" does not exist');
      },
    };
    (engine as unknown as { _sqlAdmin: unknown })._sqlAdmin = brokenAdminPool;

    let thrown: unknown;
    try {
      await engine.withMaintenanceTransaction(async () => 'unreachable');
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect((thrown as Error).message).toContain('hermesadmin');
  });
});

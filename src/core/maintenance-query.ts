// STAGE 2 helper for the hermesadmin / hermesruntime role split.
//
// Design memo:
//   hermes-personal-agent/azure/design/hermes-postgres-role-split.md
// Companion SQL:
//   hermes-personal-agent/azure/sql/migrations/2026-07-05-add-hermesadmin-role.sql
// Companion helper in postgres-engine:
//   PostgresEngine.withMaintenanceTransaction<T>()
//
// This helper is the surface autopilot / cycle / calibration / backfill /
// entities / retrieval-reflex code reaches for INSTEAD of `engine.executeRaw`
// when the query is a CROSS-SOURCE MAINTENANCE READ (needs to see rows across
// every source_id, no user-facing scope binding).
//
// Behavior:
//   * On `PostgresEngine`, dispatches to `withMaintenanceTransaction` — which
//     runs the callback inside a transaction on the admin pool. When
//     `GBRAIN_ADMIN_DATABASE_URL` is UNSET, the helper's internal fallback
//     aliases the admin pool to the runtime pool. Behavior is IDENTICAL to
//     `executeRaw` under today's posture (hermesruntime + role default
//     `app.scopes='*'`). Once the env var is set (STAGE 2 completion), the
//     query routes through hermesadmin (BYPASSRLS + SUPERUSER) — which keeps
//     autopilot working AFTER a future STAGE 4 that drops the runtime role
//     default `app.scopes='*'`.
//
//   * On non-Postgres engines (SQLite, PGLite for tests, upstream gbrain
//     without the DIH fork additions), `withMaintenanceTransaction` isn't
//     defined, so we fall through to `engine.executeRaw` — behaviorally the
//     same as before this migration.
//
// Safety guarantees for the STAGE 2 migration:
//   * Zero behavior change until `GBRAIN_ADMIN_DATABASE_URL` is wired.
//   * Non-postgres engines see NO code path change (fallback is `executeRaw`).
//   * A callsite that missed migration continues to work — but its cross-source
//     read fails LOUDLY (0 rows) once STAGE 4 drops the role default, making
//     regressions easy to spot in autopilot logs.

import type { BrainEngine } from './engine.ts';

// Loose row-typing to match `engine.executeRaw`'s default.
type Row = Record<string, unknown>;

/**
 * Run a raw SQL query through the maintenance / admin pool when available,
 * falling back to `engine.executeRaw` otherwise.
 *
 * @typeParam T - Row shape (matches `engine.executeRaw<T>`).
 * @param engine - The BrainEngine instance (Postgres or SQLite / PGLite).
 * @param sql - The parameterised SQL string. Params are positional
 *   (`$1`, `$2`, …) — SAME shape as `engine.executeRaw`.
 * @param params - Optional positional params.
 * @returns The rows returned by the query.
 * @throws Whatever `withMaintenanceTransaction` or `executeRaw` throws
 *   — no error handling here; the callsite decides fail-soft vs
 *   propagate.
 */
export async function maintenanceRaw<T extends Row = Row>(
  engine: BrainEngine,
  sql: string,
  params?: unknown[],
): Promise<Array<T>> {
  const fn = (engine as unknown as {
    withMaintenanceTransaction?: <U>(cb: (tx: unknown) => Promise<U>) => Promise<U>;
  }).withMaintenanceTransaction;

  if (typeof fn === 'function') {
    // dispatch to PostgresEngine.withMaintenanceTransaction<Array<T>>
    return (await fn.call(engine, async (tx: unknown) => {
      // `tx` is a postgres.js transaction handle in the Postgres case.
      // `tx.unsafe(sql, params)` returns a Promise resolving to the rows.
      const unsafeFn = (tx as { unsafe: (s: string, p: unknown[]) => Promise<Array<T>> }).unsafe;
      const rows = await unsafeFn(sql, params ?? []);
      return rows as Array<T>;
    })) as Array<T>;
  }

  // Non-postgres fallback (SQLite, PGLite) — identical to pre-STAGE-2 code.
  return engine.executeRaw<T>(sql, params);
}

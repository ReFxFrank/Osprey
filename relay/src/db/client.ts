import { getTableName, is, sql } from 'drizzle-orm';
import { PgTable } from 'drizzle-orm/pg-core';
import { drizzle, type PostgresJsDatabase } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema.ts';

export type Db = PostgresJsDatabase<typeof schema>;
export type Tx = Parameters<Parameters<Db['transaction']>[0]>[0];

export interface DbHandle {
  readonly db: Db;
  close(): Promise<void>;
}

/** Every table carrying tenant data, derived from the schema so the list cannot drift. */
export const TENANT_TABLES: readonly string[] = (Object.values(schema) as unknown[])
  .filter((value): value is PgTable => is(value, PgTable))
  .map((table) => getTableName(table))
  .sort();

/** Postgres `unique_violation`. */
const UNIQUE_VIOLATION = '23505';

/**
 * True only for a unique violation on the named constraint. Postgres reports
 * the constraint in `constraint_name`; requiring it stops a caller swallowing
 * an unrelated collision it never reasoned about.
 *
 * The chain is walked because drizzle wraps driver errors in a
 * `DrizzleQueryError` and puts the `PostgresError` on `cause`. Matching only
 * the outermost error silently never fires, which is the same failure as not
 * catching at all but harder to see.
 */
export function isUniqueViolation(error: unknown, constraint: string): boolean {
  // Bounded rather than recursive: a malformed or self-referential cause chain
  // must not spin here.
  let current: unknown = error;
  for (let depth = 0; depth < 8; depth += 1) {
    if (typeof current !== 'object' || current === null) return false;
    const candidate = current as { code?: unknown; constraint_name?: unknown; cause?: unknown };
    if (candidate.code === UNIQUE_VIOLATION && candidate.constraint_name === constraint) return true;
    current = candidate.cause;
  }
  return false;
}

export class DatabaseRoleError extends Error {}

interface RolePrivileges {
  readonly role: string;
  readonly isSuperuser: boolean;
  readonly bypassesRls: boolean;
}

interface TableSecurity {
  readonly owner: string;
  readonly rlsEnabled: boolean;
  readonly rlsForced: boolean;
}

function requireString(row: Record<string, unknown>, key: string): string {
  const value = row[key];
  if (typeof value !== 'string') {
    throw new DatabaseRoleError(`Privilege probe returned no ${key}; cannot verify the runtime role`);
  }
  return value;
}

function requireBoolean(row: Record<string, unknown>, key: string): boolean {
  const value = row[key];
  if (typeof value !== 'boolean') {
    throw new DatabaseRoleError(`Privilege probe returned no ${key}; cannot verify the runtime role`);
  }
  return value;
}

async function readRolePrivileges(db: Db): Promise<RolePrivileges> {
  const rows = await db.execute<Record<string, unknown>>(sql`
    select
      current_user::text as role,
      current_setting('is_superuser') = 'on' as is_superuser,
      coalesce((select bool_or(rolbypassrls) from pg_roles where rolname = current_user), false) as bypasses_rls
  `);
  const row = rows[0];
  if (row === undefined) {
    throw new DatabaseRoleError('Privilege probe returned no rows; cannot verify the runtime role');
  }
  return {
    role: requireString(row, 'role'),
    // `is_superuser` is the *effective* privilege, so a role that is superuser
    // only by inheritance is caught as well.
    isSuperuser: requireBoolean(row, 'is_superuser'),
    bypassesRls: requireBoolean(row, 'bypasses_rls'),
  };
}

async function readTableSecurity(db: Db): Promise<Map<string, TableSecurity>> {
  const rows = await db.execute<Record<string, unknown>>(sql`
    select
      c.relname::text as name,
      pg_get_userbyid(c.relowner)::text as owner,
      c.relrowsecurity as rls_enabled,
      c.relforcerowsecurity as rls_forced
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind = 'r'
  `);
  const byName = new Map<string, TableSecurity>();
  for (const row of rows) {
    byName.set(requireString(row, 'name'), {
      owner: requireString(row, 'owner'),
      rlsEnabled: requireBoolean(row, 'rls_enabled'),
      rlsForced: requireBoolean(row, 'rls_forced'),
    });
  }
  return byName;
}

/**
 * Refuses to run the relay on a connection where the RLS backstop would be
 * inert. Until this existed, the policies in `schema.ts` filtered only because
 * the runtime role happened to be a non-owner: point `DATABASE_URL` at the
 * migrator's credentials — which `migrate.ts` and `drizzle.config.ts` will both
 * silently fall back to — and every policy stops applying, with nothing failing
 * and no test noticing. A security control that is inert but still looks
 * present in review is worse than none, so this is a startup failure rather
 * than a warning.
 *
 * Three independent conditions, because each goes wrong its own way: SUPERUSER
 * and BYPASSRLS skip policies outright, and a table's owner skips that table's
 * policies unless FORCE ROW LEVEL SECURITY is set (`sql/grants.sql`).
 */
export async function assertRlsBackstopIsLive(db: Db): Promise<void> {
  const role = await readRolePrivileges(db);
  if (role.isSuperuser) {
    throw new DatabaseRoleError(
      `Refusing to start: connected as '${role.role}', which is SUPERUSER and bypasses every row-level security policy. Connect as the non-owner application role (sql/roles.sql).`,
    );
  }
  if (role.bypassesRls) {
    throw new DatabaseRoleError(
      `Refusing to start: connected as '${role.role}', which has BYPASSRLS. Connect as the non-owner application role (sql/roles.sql).`,
    );
  }

  const tables = await readTableSecurity(db);
  const problems: string[] = [];
  for (const name of TENANT_TABLES) {
    const table = tables.get(name);
    if (table === undefined) {
      problems.push(`${name}: missing from the public schema`);
      continue;
    }
    if (table.owner === role.role) problems.push(`${name}: owned by the connected role`);
    if (!table.rlsEnabled) problems.push(`${name}: row level security is not enabled`);
    if (!table.rlsForced) problems.push(`${name}: FORCE ROW LEVEL SECURITY is not set`);
  }
  if (problems.length > 0) {
    throw new DatabaseRoleError(
      `Refusing to start: the row-level security backstop is not intact for role '${role.role}' — ${problems.join('; ')}. Re-run migrations so sql/grants.sql applies; DATABASE_URL_MIGRATOR must be the owner and DATABASE_URL must not be.`,
    );
  }
}

export function openDb(databaseUrl: string, max = 10): DbHandle {
  const client = postgres(databaseUrl, { max, onnotice: () => undefined });
  const db = drizzle(client, { schema });
  return {
    db,
    close: () => client.end({ timeout: 5 }),
  };
}

/**
 * Runs `fn` inside a transaction whose `app.account_id` is pinned to
 * `accountId`, which is what the RLS policies in `schema.ts` read.
 *
 * `set_config(..., is_local => true)` is the function form of `SET LOCAL`. The
 * `LOCAL` part is load-bearing: postgres.js hands connections back to a pool,
 * and a session-scoped `SET` would leak one tenant's id onto the next request
 * that happened to draw the same connection — a cross-tenant read (brief §6.7).
 */
export async function withTenant<T>(db: Db, accountId: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`select set_config('app.account_id', ${accountId}, true)`);
    return fn(tx);
  });
}

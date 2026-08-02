import { sql } from 'drizzle-orm';
import { drizzle, type PostgresJsDatabase } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema.ts';

export type Db = PostgresJsDatabase<typeof schema>;
export type Tx = Parameters<Parameters<Db['transaction']>[0]>[0];

export interface DbHandle {
  readonly db: Db;
  close(): Promise<void>;
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

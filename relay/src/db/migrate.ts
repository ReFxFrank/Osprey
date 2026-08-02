import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { drizzle } from 'drizzle-orm/postgres-js';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import postgres from 'postgres';

/**
 * Three ordered steps, run on the *owner* connection:
 *   1. `sql/roles.sql`  — create the non-owner application role.
 *   2. Drizzle migrations — tables, indexes, RLS enablement, policies. The
 *      policies name `osprey_app`, so step 1 has to precede them.
 *   3. `sql/grants.sql` — hand the role DML on the tables it just did not create.
 *
 * `DATABASE_URL_MIGRATOR` is separate from `DATABASE_URL` on purpose: if the
 * runtime ever connected with these privileges, every policy in the schema
 * would stop filtering (see `sql/roles.sql`).
 */
const here = (relative: string) => fileURLToPath(new URL(relative, import.meta.url));

export async function runMigrations(migratorUrl: string, appPassword?: string): Promise<void> {
  const client = postgres(migratorUrl, { max: 1, onnotice: () => undefined });
  try {
    await client.unsafe(await readFile(here('../../sql/roles.sql'), 'utf8'));

    // `sql/roles.sql` creates the role without a credential so the file stays
    // free of secrets; the password arrives from the environment instead. ALTER
    // ROLE cannot take a bind parameter, so the value is passed as one to
    // set_config and quoted by Postgres itself via format(%L) — hand-rolled
    // escaping of a secret into a DDL string is exactly the mistake to avoid.
    if (appPassword !== undefined && appPassword !== '') {
      await client`select set_config('osprey.app_password', ${appPassword}, false)`;
      await client.unsafe(`
        DO $$
        BEGIN
          EXECUTE format('ALTER ROLE osprey_app PASSWORD %L', current_setting('osprey.app_password'));
        END
        $$;
      `);
    }

    await migrate(drizzle(client), { migrationsFolder: here('../../drizzle') });
    await client.unsafe(await readFile(here('../../sql/grants.sql'), 'utf8'));
  } finally {
    await client.end({ timeout: 5 });
  }
}

if (import.meta.filename === process.argv[1]) {
  const url = process.env.DATABASE_URL_MIGRATOR ?? process.env.DATABASE_URL;
  if (url === undefined || url === '') {
    throw new Error('DATABASE_URL_MIGRATOR (or DATABASE_URL) must be set to run migrations');
  }
  await runMigrations(url, process.env.OSPREY_APP_PASSWORD);
  process.stdout.write('migrations applied\n');
}

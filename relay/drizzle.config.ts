import type { Config } from 'drizzle-kit';

/**
 * Migrations run as the *owner* role, the application runs as `osprey_app`.
 * Keeping those two connection strings distinct is what makes the RLS policies
 * in `src/db/schema.ts` do anything at all: a table owner bypasses every policy
 * on its own tables unless FORCE ROW LEVEL SECURITY is set, so an app that
 * connects as the owner has RLS in name only.
 */
export default {
  schema: './src/db/schema.ts',
  out: './drizzle',
  dialect: 'postgresql',
  dbCredentials: {
    url: process.env.DATABASE_URL_MIGRATOR ?? process.env.DATABASE_URL ?? '',
  },
  strict: true,
} satisfies Config;

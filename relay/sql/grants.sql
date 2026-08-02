-- Runs after the Drizzle migrations, as the owner/superuser connection.
--
-- osprey_app gets DML on the tenant tables and nothing else: no DDL, no
-- ownership, and no rights on the drizzle bookkeeping schema. Without the
-- explicit grants the role cannot read anything; with them it can read only
-- what the policies in `src/db/schema.ts` admit.

GRANT USAGE ON SCHEMA public TO osprey_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON
  accounts, devices, pairings, pairing_tokens, push_tokens, quotas, audit_relay
TO osprey_app;

-- Explicitly *not* granted: CREATE on the schema, and any privilege on
-- drizzle.__drizzle_migrations. The application must never be able to alter its
-- own schema or rewrite migration history.
REVOKE CREATE ON SCHEMA public FROM osprey_app;

-- FORCE, not merely ENABLE. `enableRLS()` in src/db/schema.ts turns policies on,
-- but Postgres exempts a table's *owner* from its own table's policies unless
-- FORCE is set. Without these lines the whole backstop rests on an assumption
-- nobody states out loud — that DATABASE_URL never names the owner — and both
-- src/db/migrate.ts and drizzle.config.ts fall back to DATABASE_URL when
-- DATABASE_URL_MIGRATOR is absent, so the two roles are one typo apart. With
-- FORCE, pointing the relay at the owner connection filters everything to zero
-- rows instead of silently disclosing every tenant.
--
-- The consequence is deliberate: the migrator role can no longer read or write
-- these tables' *rows*, only their structure. Migrations are DDL, and TRUNCATE
-- is not subject to RLS, so nothing in the migration path needs row access. A
-- future data backfill would have to run as a role holding an explicit policy.
ALTER TABLE accounts        FORCE ROW LEVEL SECURITY;
ALTER TABLE devices         FORCE ROW LEVEL SECURITY;
ALTER TABLE pairings        FORCE ROW LEVEL SECURITY;
ALTER TABLE pairing_tokens  FORCE ROW LEVEL SECURITY;
ALTER TABLE push_tokens     FORCE ROW LEVEL SECURITY;
ALTER TABLE quotas          FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_relay     FORCE ROW LEVEL SECURITY;

-- The invariants above are not left to review. `assertRlsBackstopIsLive` in
-- src/db/client.ts re-checks all of them on every boot and refuses to start
-- otherwise; `test/rls.test.ts` asserts both the state and the refusal.

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

-- A verification query, kept next to the grants so the invariant is testable:
--   SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'osprey_app';
-- must return (false, false). `test/rls.test.ts` asserts exactly this.

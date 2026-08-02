-- Runs before the Drizzle migrations, as the owner/superuser connection.
--
-- The application connects as this role and *must not* own the tables it reads.
-- Postgres exempts a table's owner from that table's row-level security unless
-- FORCE ROW LEVEL SECURITY is set, and exempts superusers and BYPASSRLS roles
-- unconditionally — so an app that connects as the owner has policies that look
-- protective in the schema and filter nothing at runtime. That is the failure
-- mode execution plan item 12 warns about, and the reason this role exists.
--
-- NOSUPERUSER / NOBYPASSRLS / NOCREATEROLE / NOCREATEDB are stated explicitly
-- rather than relied on as defaults, because the whole point of the role is the
-- absence of those attributes.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'osprey_app') THEN
    CREATE ROLE osprey_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOINHERIT;
  END IF;
END
$$;

ALTER ROLE osprey_app NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;

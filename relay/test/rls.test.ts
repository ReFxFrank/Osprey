import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createAccount, startHarness, type Account, type Harness } from './support/harness.ts';
import { openAppConnection, truncateAll } from './support/pg.ts';

/**
 * RLS is the backstop, not the mechanism (brief §6.7). These tests exist because
 * an inert policy is worse than no policy: it looks protective in review and
 * filters nothing at runtime. Everything below runs on a raw `osprey_app`
 * connection, bypassing the repository layer entirely, so a pass means the
 * database itself would refuse a cross-tenant read even if the repository were
 * removed.
 */
describe('row-level security backstop', () => {
  let h: Harness;
  let a: Account;
  let b: Account;

  beforeAll(async () => {
    h = await startHarness();
    await truncateAll();
    a = await createAccount(h, 'alpha');
    b = await createAccount(h, 'bravo');
  });

  afterAll(async () => {
    await h.close();
  });

  it('runs the application as a role that is neither superuser nor BYPASSRLS', async () => {
    const sql = openAppConnection();
    try {
      const [row] = await sql<{ rolsuper: boolean; rolbypassrls: boolean; current_user: string }[]>`
        select current_user, rolsuper, rolbypassrls from pg_roles where rolname = current_user
      `;
      expect(row?.current_user).toBe('osprey_app');
      expect(row?.rolsuper).toBe(false);
      expect(row?.rolbypassrls).toBe(false);
    } finally {
      await sql.end({ timeout: 5 });
    }
  });

  it('does not own the tables it reads', async () => {
    const sql = openAppConnection();
    try {
      const rows = await sql<{ tablename: string; tableowner: string }[]>`
        select tablename, tableowner from pg_tables where schemaname = 'public'
      `;
      // The seven tenant tables; drizzle keeps its migration bookkeeping in a
      // separate schema that osprey_app has no rights on at all.
      expect(rows.length).toBe(7);
      for (const row of rows) expect(row.tableowner).not.toBe('osprey_app');
    } finally {
      await sql.end({ timeout: 5 });
    }
  });

  it('returns nothing at all when app.account_id is unset', async () => {
    const sql = openAppConnection();
    try {
      const devices = await sql`select id from devices`;
      const pairings = await sql`select id from pairings`;
      const tokens = await sql`select id from pairing_tokens`;
      expect(devices).toHaveLength(0);
      expect(pairings).toHaveLength(0);
      expect(tokens).toHaveLength(0);
    } finally {
      await sql.end({ timeout: 5 });
    }
  });

  it('shows only the tenant named by app.account_id, and never the other', async () => {
    const sql = openAppConnection();
    try {
      await sql.begin(async (tx) => {
        await tx`select set_config('app.account_id', ${a.accountId}, true)`;
        const ids = (await tx<{ id: string }[]>`select id from devices`).map((r) => r.id);
        expect(ids.sort()).toEqual([a.agentDeviceId, a.clientDeviceId].sort());
        expect(ids).not.toContain(b.agentDeviceId);
        expect(ids).not.toContain(b.clientDeviceId);
      });
    } finally {
      await sql.end({ timeout: 5 });
    }
  });

  it('refuses to write a row into another tenant', async () => {
    const sql = openAppConnection();
    try {
      await expect(
        sql.begin(async (tx) => {
          await tx`select set_config('app.account_id', ${a.accountId}, true)`;
          await tx`
            insert into audit_relay (account_id, event, detail)
            values (${b.accountId}, 'forged', '{}'::jsonb)
          `;
        }),
      ).rejects.toThrow(/row-level security/i);
    } finally {
      await sql.end({ timeout: 5 });
    }
  });

  it('does not leak app.account_id from one pooled transaction into the next', async () => {
    // SET LOCAL, not SET: this is the check that the pooling hazard in
    // `db/client.ts` is actually handled.
    const sql = openAppConnection();
    try {
      await sql.begin(async (tx) => {
        await tx`select set_config('app.account_id', ${a.accountId}, true)`;
        expect(await tx`select id from devices`).toHaveLength(2);
      });
      const afterCommit = await sql`select id from devices`;
      expect(afterCommit).toHaveLength(0);
    } finally {
      await sql.end({ timeout: 5 });
    }
  });

  it('denies DDL to the application role', async () => {
    const sql = openAppConnection();
    try {
      await expect(sql`create table rls_probe (id int)`).rejects.toThrow(/permission denied/i);
      await expect(sql`alter table devices disable row level security`).rejects.toThrow(
        /must be owner|permission denied/i,
      );
    } finally {
      await sql.end({ timeout: 5 });
    }
  });
});

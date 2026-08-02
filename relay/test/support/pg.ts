import postgres from 'postgres';

/**
 * Test-only database plumbing. This is the one place outside `src/repo/` and
 * `src/db/` that opens a raw connection, and it is deliberately exempted from
 * the lint boundary: the tests must be able to connect *as the owner* to create
 * and truncate the database, and *as `osprey_app`* to prove that the RLS
 * backstop actually engages for the runtime role.
 */

const HOST = process.env.OSPREY_TEST_PG_HOST ?? 'localhost';
const PORT = process.env.OSPREY_TEST_PG_PORT ?? '5433';
const OWNER = process.env.OSPREY_TEST_PG_OWNER ?? 'postgres';
export const TEST_DATABASE = process.env.OSPREY_TEST_PG_DATABASE ?? 'osprey_test';

export const ownerAdminUrl = `postgres://${OWNER}@${HOST}:${PORT}/postgres`;
export const ownerUrl = `postgres://${OWNER}@${HOST}:${PORT}/${TEST_DATABASE}`;
/** The application connects as the non-owner role, exactly as it does in production. */
export const appUrl = `postgres://osprey_app@${HOST}:${PORT}/${TEST_DATABASE}`;

export const TENANT_TABLES = [
  'audit_relay',
  'push_tokens',
  'pairings',
  'pairing_tokens',
  'quotas',
  'devices',
  'accounts',
] as const;

export async function recreateDatabase(): Promise<void> {
  const admin = postgres(ownerAdminUrl, { max: 1, onnotice: () => undefined });
  try {
    await admin.unsafe(`DROP DATABASE IF EXISTS ${TEST_DATABASE} WITH (FORCE)`);
    await admin.unsafe(`CREATE DATABASE ${TEST_DATABASE}`);
  } finally {
    await admin.end({ timeout: 5 });
  }
}

/**
 * Truncation runs on the owner connection because `osprey_app` is intentionally
 * not granted TRUNCATE — giving the runtime role that privilege to make the
 * tests convenient would weaken the thing the tests exist to check.
 */
export async function truncateAll(): Promise<void> {
  const owner = postgres(ownerUrl, { max: 1, onnotice: () => undefined });
  try {
    await owner.unsafe(`TRUNCATE ${TENANT_TABLES.join(', ')} RESTART IDENTITY CASCADE`);
  } finally {
    await owner.end({ timeout: 5 });
  }
}

export function openAppConnection() {
  return postgres(appUrl, { max: 1, onnotice: () => undefined });
}

export type OwnerSql = ReturnType<typeof postgres>;

/**
 * Runs a block on the owner connection. Tests that need to inspect or age rows
 * behind the repository layer's back go through here, so the ESLint boundary
 * that forbids `postgres` imports stays in force for every other test file.
 */
export async function withOwnerSql<T>(fn: (sql: OwnerSql) => Promise<T>): Promise<T> {
  const owner = postgres(ownerUrl, { max: 1, onnotice: () => undefined });
  try {
    return await fn(owner);
  } finally {
    await owner.end({ timeout: 5 });
  }
}

import { assertRlsBackstopIsLive, openDb, type Db } from '../db/client.ts';
import { createAccountRepo, type QuotaDefaults } from './accounts.ts';
import { createAuditRepo } from './audit.ts';
import { createDeviceRepo } from './devices.ts';
import { createPairingRepo } from './pairings.ts';
import { createPairingTokenRepo } from './pairingTokens.ts';

/**
 * The single seam between routes and the database (brief §4.2, §6.7).
 *
 * Two rules hold across every module below and are what the ESLint boundaries
 * configuration exists to protect:
 *
 *  1. Nothing outside this directory imports `db/client.ts`, `db/schema.ts`,
 *     `drizzle-orm` or `postgres`.
 *  2. Every exported function takes `accountId` as its first parameter and
 *     filters on it. The single exception is
 *     `accounts.enrollAgentIntoNewAccount`, which *creates* the tenant it then
 *     operates inside — there is no function anywhere that reads or writes an
 *     existing tenant without being handed its id.
 *
 * Helpers shared between modules (`insertAudit`) also take `accountId` first,
 * with the caller's transaction second, so the ordering rule reads the same at
 * every level.
 */
export function createRepo(db: Db, quotaDefaults: QuotaDefaults) {
  return {
    accounts: createAccountRepo(db, quotaDefaults),
    audit: createAuditRepo(db),
    devices: createDeviceRepo(db),
    pairings: createPairingRepo(db),
    pairingTokens: createPairingTokenRepo(db),
  };
}

export type Repo = ReturnType<typeof createRepo>;

export interface RepoHandle {
  readonly repo: Repo;
  close(): Promise<void>;
}

/**
 * Owns the connection pool so that nothing outside this directory ever holds a
 * `Db`. The composition root asks for a repository, not a database — which is
 * what lets the lint boundary forbid `db/` imports everywhere else without
 * carving out an exception for startup code.
 *
 * Asynchronous because it will not hand back a repository until the connection
 * has been proved incapable of bypassing row-level security; a relay whose
 * backstop is inert must fail to start, not start quietly (plan item 12).
 */
export async function createRepoFromUrl(
  databaseUrl: string,
  quotaDefaults: QuotaDefaults,
  poolSize?: number,
): Promise<RepoHandle> {
  const handle = openDb(databaseUrl, poolSize);
  try {
    await assertRlsBackstopIsLive(handle.db);
  } catch (err: unknown) {
    await handle.close();
    throw err;
  }
  return { repo: createRepo(handle.db, quotaDefaults), close: handle.close };
}
export type { QuotaDefaults } from './accounts.ts';
export type { AuthenticatedDevice, DeviceSummary } from './devices.ts';
export { isUuid, parseDeviceToken, sha256Hex } from './tokens.ts';

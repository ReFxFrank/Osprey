import { randomUUID } from 'node:crypto';
import type { Db, Tx } from '../db/client.ts';
import { withTenant } from '../db/client.ts';
import { auditRelay } from '../db/schema.ts';

/**
 * Execution plan item 14: pairing success, pairing failure and unpair are the
 * highest-privilege events in the system, so they are audited rather than
 * merely logged. Events that cannot be attributed to an account (a bad
 * enrollment secret, for instance) have nowhere tenant-scoped to go and stay in
 * the structured process log — writing them to a guessed account would itself
 * be a cross-tenant write.
 */
export type AuditEvent =
  | 'account.created'
  | 'device.enrolled'
  | 'device.revoked'
  | 'pairing.token_issued'
  | 'pairing.token_rejected'
  | 'pairing.succeeded'
  | 'pairing.revoked'
  | 'ws.attached'
  | 'ws.relay_rejected';

export interface AuditEntry {
  readonly event: AuditEvent;
  readonly detail: Record<string, unknown>;
  readonly deviceId?: string | null;
  readonly remoteIp?: string | null;
}

/** Tenant-scoped insert for callers that already hold a transaction. */
export async function insertAudit(accountId: string, tx: Tx, entry: AuditEntry): Promise<void> {
  await tx.insert(auditRelay).values({
    id: randomUUID(),
    accountId,
    deviceId: entry.deviceId ?? null,
    event: entry.event,
    detail: entry.detail,
    remoteIp: entry.remoteIp ?? null,
  });
}

export function createAuditRepo(db: Db) {
  return {
    record: (accountId: string, entry: AuditEntry): Promise<void> =>
      withTenant(db, accountId, (tx) => insertAudit(accountId, tx, entry)),

    list: (accountId: string, limit = 100) =>
      withTenant(db, accountId, (tx) =>
        tx.query.auditRelay.findMany({
          where: (t, { eq }) => eq(t.accountId, accountId),
          orderBy: (t, { desc }) => desc(t.createdAt),
          limit,
        }),
      ),
  };
}

export type AuditRepo = ReturnType<typeof createAuditRepo>;

import { and, eq, isNull, or } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { withTenant } from '../db/client.ts';
import { pairings } from '../db/schema.ts';
import { insertAudit } from './audit.ts';

export interface PairingSummary {
  readonly id: string;
  readonly agentDeviceId: string;
  readonly clientDeviceId: string;
  readonly createdAt: string;
}

export function createPairingRepo(db: Db) {
  return {
    listForDevice: (accountId: string, deviceId: string): Promise<PairingSummary[]> =>
      withTenant(db, accountId, async (tx) => {
        const rows = await tx
          .select()
          .from(pairings)
          .where(
            and(
              eq(pairings.accountId, accountId),
              or(eq(pairings.agentDeviceId, deviceId), eq(pairings.clientDeviceId, deviceId)),
              isNull(pairings.revokedAt),
            ),
          );
        return rows.map((r) => ({
          id: r.id,
          agentDeviceId: r.agentDeviceId,
          clientDeviceId: r.clientDeviceId,
          createdAt: r.createdAt.toISOString(),
        }));
      }),

    /** Live-pairing check used to authorise WebSocket relaying between two devices. */
    peerIsPaired: (accountId: string, deviceId: string, peerDeviceId: string): Promise<boolean> =>
      withTenant(db, accountId, async (tx) => {
        const rows = await tx
          .select({ id: pairings.id })
          .from(pairings)
          .where(
            and(
              eq(pairings.accountId, accountId),
              isNull(pairings.revokedAt),
              or(
                and(eq(pairings.agentDeviceId, deviceId), eq(pairings.clientDeviceId, peerDeviceId)),
                and(eq(pairings.clientDeviceId, deviceId), eq(pairings.agentDeviceId, peerDeviceId)),
              ),
            ),
          )
          .limit(1);
        return rows.length > 0;
      }),

    /**
     * Soft revoke, so the record of who was ever permitted to control this host
     * survives the unpair (plan item 9). Only a participant may revoke, and the
     * caller reports both "absent" and "not a participant" as 404 — a 403 would
     * confirm that the pairing id exists (§6.7).
     */
    revoke: (
      accountId: string,
      pairingId: string,
      actor: { deviceId: string; kind: 'agent' | 'client'; remoteIp: string | null },
    ): Promise<boolean> =>
      withTenant(db, accountId, async (tx) => {
        const revoked = await tx
          .update(pairings)
          .set({ revokedAt: new Date(), revokedBy: actor.kind })
          .where(
            and(
              eq(pairings.accountId, accountId),
              eq(pairings.id, pairingId),
              isNull(pairings.revokedAt),
              or(eq(pairings.agentDeviceId, actor.deviceId), eq(pairings.clientDeviceId, actor.deviceId)),
            ),
          )
          .returning({ id: pairings.id, agentDeviceId: pairings.agentDeviceId, clientDeviceId: pairings.clientDeviceId });

        const row = revoked[0];
        if (row === undefined) return false;

        await insertAudit(accountId, tx, {
          event: 'pairing.revoked',
          deviceId: actor.deviceId,
          detail: {
            pairingId,
            revokedBy: actor.kind,
            agentDeviceId: row.agentDeviceId,
            clientDeviceId: row.clientDeviceId,
          },
          remoteIp: actor.remoteIp,
        });
        return true;
      }),
  };
}

export type PairingRepo = ReturnType<typeof createPairingRepo>;

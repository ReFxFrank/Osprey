import { and, eq, isNull, or } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { withTenant } from '../db/client.ts';
import { devices, pairings } from '../db/schema.ts';
import { insertAudit } from './audit.ts';
import { digestsEqual } from './tokens.ts';

export interface AuthenticatedDevice {
  readonly accountId: string;
  readonly deviceId: string;
  readonly kind: 'agent' | 'client';
}

export interface DeviceSummary {
  readonly id: string;
  readonly kind: 'agent' | 'client';
  readonly displayName: string;
  readonly identityPublicKey: string;
  readonly identityAlgorithm: 'ed25519' | 'p256';
  readonly noiseStaticPublicKey: string;
  readonly createdAt: string;
  readonly lastSeenAt: string | null;
}

export function createDeviceRepo(db: Db) {
  return {
    /**
     * Tenant-scoped authentication. `accountId` comes from the presented token
     * (see `tokens.ts`) and is a routing hint only — the hash comparison inside
     * the tenant is what authenticates. A token whose account id is forged
     * lands in a tenant where its hash does not exist and fails.
     */
    authenticate: (accountId: string, secretHash: string): Promise<AuthenticatedDevice | null> =>
      withTenant(db, accountId, async (tx) => {
        const rows = await tx
          .select({ id: devices.id, kind: devices.kind, hash: devices.authTokenHash })
          .from(devices)
          .where(and(eq(devices.accountId, accountId), isNull(devices.revokedAt)));
        for (const row of rows) {
          if (digestsEqual(row.hash, secretHash)) {
            return { accountId, deviceId: row.id, kind: row.kind };
          }
        }
        return null;
      }),

    touchLastSeen: (accountId: string, deviceId: string): Promise<void> =>
      withTenant(db, accountId, async (tx) => {
        await tx
          .update(devices)
          .set({ lastSeenAt: new Date() })
          .where(and(eq(devices.accountId, accountId), eq(devices.id, deviceId)));
      }),

    list: (accountId: string): Promise<DeviceSummary[]> =>
      withTenant(db, accountId, async (tx) => {
        const rows = await tx
          .select()
          .from(devices)
          .where(and(eq(devices.accountId, accountId), isNull(devices.revokedAt)))
          .orderBy(devices.createdAt);
        return rows.map((r) => ({
          id: r.id,
          kind: r.kind,
          displayName: r.displayName,
          identityPublicKey: r.identityPublicKey,
          identityAlgorithm: r.identityAlgorithm,
          noiseStaticPublicKey: r.noiseStaticPublicKey,
          createdAt: r.createdAt.toISOString(),
          lastSeenAt: r.lastSeenAt?.toISOString() ?? null,
        }));
      }),

    /**
     * Soft revoke (brief §6.1: revocation is immediate). Returns false when the
     * device is absent *or* belongs to another tenant — the caller turns both
     * into 404, because 403 would confirm the row exists (§6.7).
     */
    revoke: (
      accountId: string,
      deviceId: string,
      actor: { deviceId: string; remoteIp: string | null },
    ): Promise<boolean> =>
      withTenant(db, accountId, async (tx) => {
        const now = new Date();
        const revoked = await tx
          .update(devices)
          .set({ revokedAt: now })
          .where(and(eq(devices.accountId, accountId), eq(devices.id, deviceId), isNull(devices.revokedAt)))
          .returning({ id: devices.id, kind: devices.kind });
        if (revoked.length === 0) return false;

        await tx
          .update(pairings)
          .set({ revokedAt: now, revokedBy: 'agent' })
          .where(
            and(
              eq(pairings.accountId, accountId),
              or(eq(pairings.agentDeviceId, deviceId), eq(pairings.clientDeviceId, deviceId)),
              isNull(pairings.revokedAt),
            ),
          );

        await insertAudit(accountId, tx, {
          event: 'device.revoked',
          deviceId,
          detail: { revokedBy: actor.deviceId, kind: revoked[0]?.kind },
          remoteIp: actor.remoteIp,
        });
        return true;
      }),
  };
}

export type DeviceRepo = ReturnType<typeof createDeviceRepo>;

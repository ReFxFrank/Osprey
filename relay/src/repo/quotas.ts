import { eq } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { withTenant } from '../db/client.ts';
import { quotas } from '../db/schema.ts';

export interface Quota {
  readonly maxDevices: number;
  readonly maxPairingAttemptsPerHour: number;
  readonly turnBytesPerMonth: bigint;
}

export function createQuotaRepo(db: Db) {
  return {
    get: (accountId: string): Promise<Quota | null> =>
      withTenant(db, accountId, async (tx) => {
        const [row] = await tx.select().from(quotas).where(eq(quotas.accountId, accountId));
        if (row === undefined) return null;
        return {
          maxDevices: row.maxDevices,
          maxPairingAttemptsPerHour: row.maxPairingAttemptsPerHour,
          turnBytesPerMonth: row.turnBytesPerMonth,
        };
      }),
  };
}

export type QuotaRepo = ReturnType<typeof createQuotaRepo>;

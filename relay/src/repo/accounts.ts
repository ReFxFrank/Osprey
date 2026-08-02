import { randomUUID } from 'node:crypto';
import { sql } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { accounts, devices, quotas } from '../db/schema.ts';
import { insertAudit } from './audit.ts';
import { mintDeviceToken } from './tokens.ts';

export interface QuotaDefaults {
  readonly maxDevices: number;
  readonly maxPairingAttemptsPerHour: number;
  readonly turnBytesPerMonth: bigint;
}

export interface EnrollAgentInput {
  readonly displayName: string;
  readonly identityPublicKey: string;
  readonly identityAlgorithm: 'ed25519' | 'p256';
  readonly noiseStaticPublicKey: string;
  readonly noiseStaticSignature: string;
  readonly remoteIp: string | null;
}

export interface EnrollAgentResult {
  readonly accountId: string;
  readonly deviceId: string;
  /** Returned exactly once. Only its SHA-256 is persisted. */
  readonly deviceToken: string;
}

export function createAccountRepo(db: Db, quotaDefaults: QuotaDefaults) {
  return {
    /**
     * Brief §0.1: an account comes into existence when the first agent enrolls.
     * This is the only function in the repository layer that does not receive an
     * `accountId` — it *mints* one. It is not a tenant bypass: the id is
     * generated here, `app.account_id` is pinned to it before the first insert,
     * and every statement in the transaction is therefore already inside the
     * new tenant. Route-level abuse control for this path (enrollment secret +
     * global per-IP limit) lives in `routes/enroll.ts`, because a per-account
     * quota structurally cannot bound account creation (plan item 11).
     */
    enrollAgentIntoNewAccount: (input: EnrollAgentInput): Promise<EnrollAgentResult> =>
      db.transaction(async (tx) => {
        const accountId = randomUUID();
        await tx.execute(sql`select set_config('app.account_id', ${accountId}, true)`);

        const deviceId = randomUUID();
        const { token, secretHash } = mintDeviceToken(accountId);

        await tx.insert(accounts).values({ id: accountId, displayName: input.displayName });
        await tx.insert(quotas).values({
          accountId,
          maxDevices: quotaDefaults.maxDevices,
          maxPairingAttemptsPerHour: quotaDefaults.maxPairingAttemptsPerHour,
          turnBytesPerMonth: quotaDefaults.turnBytesPerMonth,
        });
        await tx.insert(devices).values({
          id: deviceId,
          accountId,
          kind: 'agent',
          displayName: input.displayName,
          identityPublicKey: input.identityPublicKey,
          identityAlgorithm: input.identityAlgorithm,
          noiseStaticPublicKey: input.noiseStaticPublicKey,
          noiseStaticSignature: input.noiseStaticSignature,
          authTokenHash: secretHash,
        });

        await insertAudit(accountId, tx, {
          event: 'account.created',
          deviceId,
          detail: { kind: 'agent', displayName: input.displayName },
          remoteIp: input.remoteIp,
        });
        await insertAudit(accountId, tx, {
          event: 'device.enrolled',
          deviceId,
          detail: { kind: 'agent', identityAlgorithm: input.identityAlgorithm },
          remoteIp: input.remoteIp,
        });

        return { accountId, deviceId, deviceToken: token };
      }),
  };
}

export type AccountRepo = ReturnType<typeof createAccountRepo>;

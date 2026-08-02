import { randomUUID } from 'node:crypto';
import { and, eq, gt, gte, isNull, sql } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { isUniqueViolation, withTenant } from '../db/client.ts';
import { devices, pairingTokens, pairings, quotas, ROUTING_ID_UNIQUE_INDEX } from '../db/schema.ts';
import { insertAudit } from './audit.ts';
import { mintDeviceToken } from './tokens.ts';

export interface IssueTokenInput {
  readonly agentDeviceId: string;
  readonly routingId: string;
  readonly ttlSeconds: number;
  readonly remoteIp: string | null;
}

export type IssueTokenResult =
  | { readonly ok: true; readonly tokenId: string; readonly expiresAt: string }
  | { readonly ok: false; readonly reason: 'rate_limited' | 'routing_id_taken' };

export interface RedeemInput {
  readonly routingId: string;
  readonly displayName: string;
  readonly identityPublicKey: string;
  readonly identityAlgorithm: 'ed25519' | 'p256';
  readonly noiseStaticPublicKey: string;
  readonly noiseStaticSignature: string;
  readonly remoteIp: string | null;
}

export type RedeemResult =
  | {
      readonly ok: true;
      readonly pairingId: string;
      readonly clientDeviceId: string;
      readonly agentDeviceId: string;
      readonly deviceToken: string;
    }
  /**
   * `unknown_token` means the caller never proved possession of the QR secret;
   * it is reported separately from `agent_revoked` because the two differ in
   * whether an audit row may be written. See `redeem` below.
   */
  | { readonly ok: false; readonly reason: 'unknown_token' | 'agent_revoked' | 'quota_exceeded' };

function issueWithinTenant(db: Db, accountId: string, input: IssueTokenInput): Promise<IssueTokenResult> {
  return withTenant(db, accountId, async (tx) => {
    const [quota] = await tx
      .select({ perHour: quotas.maxPairingAttemptsPerHour })
      .from(quotas)
      .where(eq(quotas.accountId, accountId));
    const perHour = quota?.perHour ?? 0;

    const windowStart = new Date(Date.now() - 3_600_000);
    const [recent] = await tx
      .select({ n: sql<number>`count(*)::int` })
      .from(pairingTokens)
      .where(and(eq(pairingTokens.accountId, accountId), gte(pairingTokens.createdAt, windowStart)));
    if ((recent?.n ?? 0) >= perHour) {
      await insertAudit(accountId, tx, {
        event: 'pairing.token_rejected',
        deviceId: input.agentDeviceId,
        detail: { reason: 'rate_limited', windowCount: recent?.n ?? 0, limit: perHour },
        remoteIp: input.remoteIp,
      });
      return { ok: false, reason: 'rate_limited' } as const;
    }

    const tokenId = randomUUID();
    const expiresAt = new Date(Date.now() + input.ttlSeconds * 1000);
    await tx.insert(pairingTokens).values({
      id: tokenId,
      accountId,
      agentDeviceId: input.agentDeviceId,
      routingId: input.routingId,
      expiresAt,
    });
    await insertAudit(accountId, tx, {
      event: 'pairing.token_issued',
      deviceId: input.agentDeviceId,
      detail: { tokenId, ttlSeconds: input.ttlSeconds },
      remoteIp: input.remoteIp,
    });
    return { ok: true, tokenId, expiresAt: expiresAt.toISOString() } as const;
  });
}

export function createPairingTokenRepo(db: Db) {
  return {
    /**
     * Stores only `routingId = SHA-256(pairing_secret)`. The secret itself never
     * reaches the relay (plan item 9c) — it is the Noise PSK, so a relay that
     * held it could complete the handshake and pair itself.
     *
     * `routing_id` is unique across every tenant, so the insert below can be
     * refused by a constraint whose other side lives in an account this
     * transaction cannot see. That is caught here and turned into a result the
     * caller can act on: letting it escape would abort the request with a
     * generic 500, which is both an unhandled database exception and a signal
     * distinguishable from success.
     */
    issue: async (accountId: string, input: IssueTokenInput): Promise<IssueTokenResult> => {
      try {
        return await issueWithinTenant(db, accountId, input);
      } catch (err: unknown) {
        if (isUniqueViolation(err, ROUTING_ID_UNIQUE_INDEX)) {
          return { ok: false, reason: 'routing_id_taken' } as const;
        }
        throw err;
      }
    },

    /**
     * Single-use redemption. The `UPDATE ... WHERE used = false AND expires_at >
     * now() RETURNING` is one statement precisely so two concurrent redemptions
     * cannot both win: the loser's UPDATE matches zero rows because the row is
     * already locked and no longer satisfies the predicate (plan item 9a). A
     * read-then-write would let a race create two pins for one QR.
     *
     * `accountId` comes from the scanned QR, and the predicate requires the
     * token to belong to it, so a hostile relay cannot route a phone's pairing
     * into another tenant's pending pairing (plan item 9b).
     *
     * Nothing before the UPDATE writes anything, and nothing before it may.
     * This route is unauthenticated and takes its tenant from the request body,
     * so any row written on the miss path is a row an anonymous caller can
     * inject into a stranger's audit log simply by knowing (or having once
     * known) their account id — which never rotates, so even a revoked
     * controller retains it. `audit_relay` is a mandated, non-suppressible
     * security control; burying real events under attacker-chosen noise defeats
     * it. Only once the UPDATE has actually claimed a row has the caller proved
     * possession of the QR secret, and only from that point does this function
     * audit. Everything earlier is the route's business to log.
     */
    redeem: (accountId: string, input: RedeemInput): Promise<RedeemResult> =>
      withTenant(db, accountId, async (tx) => {
        const now = new Date();
        const claimed = await tx
          .update(pairingTokens)
          .set({ used: true, usedAt: now })
          .where(
            and(
              eq(pairingTokens.accountId, accountId),
              eq(pairingTokens.routingId, input.routingId),
              eq(pairingTokens.used, false),
              gt(pairingTokens.expiresAt, now),
            ),
          )
          .returning({ id: pairingTokens.id, agentDeviceId: pairingTokens.agentDeviceId });

        const token = claimed[0];
        if (token === undefined) {
          /*
           * The UPDATE can miss for three different reasons, and they are not
           * equally interesting. A routing id that matches no row is the
           * floodable case an anonymous caller can generate at will, so it must
           * stay unaudited. But a routing id that *does* match a row is proof of
           * QR possession — `routing_id` is SHA-256(pairing_secret), so it
           * cannot be guessed — and an expired or already-used token is exactly
           * the replay/near-miss an audit log exists to record. Distinguishing
           * them here keeps the amplification closed while keeping the log
           * honest about real events.
           */
          const [existing] = await tx
            .select({ id: pairingTokens.id, used: pairingTokens.used, expiresAt: pairingTokens.expiresAt })
            .from(pairingTokens)
            .where(
              and(eq(pairingTokens.accountId, accountId), eq(pairingTokens.routingId, input.routingId)),
            );
          if (existing !== undefined) {
            await insertAudit(accountId, tx, {
              event: 'pairing.token_rejected',
              detail: {
                reason: existing.used ? 'token_already_used' : 'token_expired',
                tokenId: existing.id,
              },
              remoteIp: input.remoteIp,
            });
          }
          // The caller is told the same thing either way; only the log differs.
          return { ok: false, reason: 'unknown_token' } as const;
        }

        const [agent] = await tx
          .select()
          .from(devices)
          .where(and(eq(devices.accountId, accountId), eq(devices.id, token.agentDeviceId), isNull(devices.revokedAt)));
        if (agent === undefined) {
          await insertAudit(accountId, tx, {
            event: 'pairing.token_rejected',
            detail: { reason: 'agent_device_revoked', tokenId: token.id },
            remoteIp: input.remoteIp,
          });
          return { ok: false, reason: 'agent_revoked' } as const;
        }

        const [quota] = await tx
          .select({ maxDevices: quotas.maxDevices })
          .from(quotas)
          .where(eq(quotas.accountId, accountId));
        const [active] = await tx
          .select({ n: sql<number>`count(*)::int` })
          .from(devices)
          .where(and(eq(devices.accountId, accountId), isNull(devices.revokedAt)));
        if ((active?.n ?? 0) >= (quota?.maxDevices ?? 0)) {
          await insertAudit(accountId, tx, {
            event: 'pairing.token_rejected',
            detail: { reason: 'device_quota_exceeded', limit: quota?.maxDevices ?? 0 },
            remoteIp: input.remoteIp,
          });
          return { ok: false, reason: 'quota_exceeded' } as const;
        }

        const clientDeviceId = randomUUID();
        const pairingId = randomUUID();
        const { token: deviceToken, secretHash } = mintDeviceToken(accountId);

        await tx.insert(devices).values({
          id: clientDeviceId,
          accountId,
          kind: 'client',
          displayName: input.displayName,
          identityPublicKey: input.identityPublicKey,
          identityAlgorithm: input.identityAlgorithm,
          noiseStaticPublicKey: input.noiseStaticPublicKey,
          noiseStaticSignature: input.noiseStaticSignature,
          authTokenHash: secretHash,
        });
        await tx.insert(pairings).values({
          id: pairingId,
          accountId,
          agentDeviceId: agent.id,
          clientDeviceId,
          agentNoiseStaticPublicKey: agent.noiseStaticPublicKey,
          agentNoiseStaticSignature: agent.noiseStaticSignature,
          clientNoiseStaticPublicKey: input.noiseStaticPublicKey,
          clientNoiseStaticSignature: input.noiseStaticSignature,
        });
        await insertAudit(accountId, tx, {
          event: 'pairing.succeeded',
          deviceId: clientDeviceId,
          detail: { pairingId, agentDeviceId: agent.id, tokenId: token.id },
          remoteIp: input.remoteIp,
        });

        return { ok: true, pairingId, clientDeviceId, agentDeviceId: agent.id, deviceToken } as const;
      }),
  };
}

export type PairingTokenRepo = ReturnType<typeof createPairingTokenRepo>;

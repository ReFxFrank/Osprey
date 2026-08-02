import type { FastifyInstance } from 'fastify';
import type { RelayConfig } from '../config.ts';
import { deviceOf, requireDevice } from '../http/auth.ts';
import { fail, notFound } from '../http/errors.ts';
import type { RateLimiter } from '../http/rateLimit.ts';
import type { Repo } from '../repo/index.ts';
import { idParamSchema, issueTokenBodySchema, redeemBodySchema, type RedeemBody } from './schemas.ts';

export interface PairingDeps {
  readonly repo: Repo;
  readonly config: RelayConfig;
  /** Bounds anonymous redeem traffic from one source. */
  readonly redeemIpLimiter: RateLimiter;
  /** Bounds *failed* anonymous redeem traffic aimed at one tenant. */
  readonly redeemAccountLimiter: RateLimiter;
}

export function registerPairingRoutes(app: FastifyInstance, deps: PairingDeps): void {
  const authenticated = requireDevice(deps.repo);

  app.post<{ Body: { routingId: string } }>(
    '/v1/pairing/tokens',
    { schema: { body: issueTokenBodySchema }, preHandler: authenticated },
    async (request, reply) => {
      const device = deviceOf(request);
      if (device.kind !== 'agent') {
        // Only a host can offer a pairing. A client token is not permitted to
        // create one, and saying so specifically would confirm nothing useful.
        return notFound(reply);
      }
      const result = await deps.repo.pairingTokens.issue(device.accountId, {
        agentDeviceId: device.deviceId,
        routingId: request.body.routingId,
        ttlSeconds: deps.config.pairingTokenTtlSeconds,
        remoteIp: request.ip,
      });
      if (!result.ok) {
        if (result.reason === 'routing_id_taken') {
          /**
           * The rendezvous id is unique across the whole relay (see
           * `db/schema.ts`), so a collision is a namespace conflict, not a
           * tenant leak to be hidden behind a 404. It is reported rather than
           * audited: a caller can retry this forever without ever inserting a
           * pairing_tokens row, so auditing it would be an unbounded write.
           *
           * What this does disclose is that some tenant has used that exact
           * routing id. Reaching it requires already knowing the id — i.e.
           * having seen the QR — and anyone in that position can learn strictly
           * more by simply calling redeem, which reports whether the token is
           * live. A legitimate agent cannot collide: routing ids are SHA-256 of
           * 32 random bytes.
           */
          request.log.warn(
            { accountId: device.accountId, deviceId: device.deviceId },
            'pairing token rejected: routing id already taken',
          );
          return fail(reply, 'conflict', 'Routing id is already in use');
        }
        return fail(reply, 'rate_limited', 'Pairing attempt quota exceeded for this account');
      }
      return reply.code(201).send({ tokenId: result.tokenId, expiresAt: result.expiresAt });
    },
  );

  /**
   * Unauthenticated by construction: the caller is a phone that has just
   * scanned a QR and holds no relay credential yet. Its authority is the
   * `routingId` — a SHA-256 preimage only the physical scanner possesses — and
   * the `accountId` from the same QR, which pins redemption to one tenant.
   *
   * Honest limitation: because the tenant is taken from an unauthenticated
   * body, the RLS backstop cannot second-guess this one route. The isolation
   * here rests on the repository predicate (`account_id = $1 AND routing_id =
   * $2`) plus preimage resistance, not on RLS.
   *
   * Two limiters guard it, because it is the only route that lets an anonymous
   * caller name someone else's tenant. The per-IP window is charged for every
   * attempt. The per-account window is checked before any database work but
   * charged only for *failures*, so a tenant whose phones pair normally never
   * spends its own budget; only a caller that cannot produce a valid routing id
   * does. The residual is deliberate and bounded: a distributed flood can cost
   * one tenant the remainder of a one-minute pairing window.
   */
  app.post<{ Body: RedeemBody }>(
    '/v1/pairing/redeem',
    { schema: { body: redeemBodySchema } },
    async (request, reply) => {
      const remoteIp = request.ip;
      const { accountId } = request.body;
      if (!deps.redeemIpLimiter.consume(remoteIp)) {
        request.log.warn({ remoteIp }, 'pairing redeem rate limit exceeded for source ip');
        return fail(reply, 'rate_limited', 'Too many pairing attempts');
      }
      if (!deps.redeemAccountLimiter.check(accountId)) {
        request.log.warn({ remoteIp, accountId }, 'pairing redeem failure budget exhausted for account');
        return fail(reply, 'rate_limited', 'Too many pairing attempts');
      }

      const result = await deps.repo.pairingTokens.redeem(accountId, {
        routingId: request.body.routingId,
        displayName: request.body.displayName,
        identityPublicKey: request.body.identityPublicKey,
        identityAlgorithm: request.body.identityAlgorithm,
        noiseStaticPublicKey: request.body.noiseStaticPublicKey,
        noiseStaticSignature: request.body.noiseStaticSignature,
        remoteIp,
      });
      if (!result.ok) {
        // Charged after the fact, and its verdict discarded: this attempt has
        // already failed on its own merits, so the budget is being spent to
        // bound the *next* one, not to decide this one.
        deps.redeemAccountLimiter.consume(accountId);
        if (result.reason === 'quota_exceeded') {
          return fail(reply, 'rate_limited', 'Device quota exceeded for this account');
        }
        if (result.reason === 'unknown_token') {
          // The caller never proved possession of the QR secret, and `accountId`
          // is unauthenticated body input, so there is no tenant this may be
          // attributed to. It goes to the process log for the same reason a bad
          // enrollment secret does (`routes/enroll.ts`): writing it to the named
          // account would let anyone holding a stale accountId fill that
          // tenant's audit log with noise.
          request.log.warn(
            { remoteIp, accountId },
            'pairing redeem rejected: unknown, expired or already-used routing id',
          );
        }
        return notFound(reply);
      }
      return reply.code(201).send({
        pairingId: result.pairingId,
        accountId: request.body.accountId,
        deviceId: result.clientDeviceId,
        agentDeviceId: result.agentDeviceId,
        deviceToken: result.deviceToken,
      });
    },
  );

  app.delete<{ Params: { id: string } }>(
    '/v1/pairings/:id',
    { schema: { params: idParamSchema }, preHandler: authenticated },
    async (request, reply) => {
      const device = deviceOf(request);
      const revoked = await deps.repo.pairings.revoke(device.accountId, request.params.id, {
        deviceId: device.deviceId,
        kind: device.kind,
        remoteIp: request.ip,
      });
      if (!revoked) return notFound(reply);
      return reply.code(204).send();
    },
  );
}

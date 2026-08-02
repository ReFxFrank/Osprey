import type { FastifyInstance } from 'fastify';
import type { RelayConfig } from '../config.ts';
import { deviceOf, requireDevice } from '../http/auth.ts';
import { fail, notFound } from '../http/errors.ts';
import type { Repo } from '../repo/index.ts';
import { idParamSchema, issueTokenBodySchema, redeemBodySchema, type RedeemBody } from './schemas.ts';

export interface PairingDeps {
  readonly repo: Repo;
  readonly config: RelayConfig;
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
   */
  app.post<{ Body: RedeemBody }>(
    '/v1/pairing/redeem',
    { schema: { body: redeemBodySchema } },
    async (request, reply) => {
      const result = await deps.repo.pairingTokens.redeem(request.body.accountId, {
        routingId: request.body.routingId,
        displayName: request.body.displayName,
        identityPublicKey: request.body.identityPublicKey,
        identityAlgorithm: request.body.identityAlgorithm,
        noiseStaticPublicKey: request.body.noiseStaticPublicKey,
        noiseStaticSignature: request.body.noiseStaticSignature,
        remoteIp: request.ip,
      });
      if (!result.ok) {
        if (result.reason === 'quota_exceeded') {
          return fail(reply, 'rate_limited', 'Device quota exceeded for this account');
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

import { timingSafeEqual } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import type { RelayConfig } from '../config.ts';
import { fail } from '../http/errors.ts';
import type { RateLimiter } from '../http/rateLimit.ts';
import type { Repo } from '../repo/index.ts';
import { sha256Hex } from '../repo/index.ts';
import { enrollBodySchema, type EnrollBody } from './schemas.ts';

function secretMatches(presented: string, expected: string): boolean {
  // Hash both sides first so the comparison is over fixed-length buffers and
  // timingSafeEqual cannot throw on a length mismatch (which would itself be an
  // oracle for the secret's length).
  return timingSafeEqual(
    Buffer.from(sha256Hex(presented), 'hex'),
    Buffer.from(sha256Hex(expected), 'hex'),
  );
}

export interface EnrollDeps {
  readonly repo: Repo;
  readonly config: RelayConfig;
  readonly enrollLimiter: RateLimiter;
}

/**
 * Brief §0.1: no signup, no login, no email — an account exists because an
 * agent enrolled. Execution plan item 11 adds the two guards that "implicit"
 * otherwise lacks: a deploy-time shared secret, and a *global* per-IP rate
 * limit, since a per-account quota cannot bound the creation of accounts.
 */
export function registerEnrollRoutes(app: FastifyInstance, deps: EnrollDeps): void {
  app.post<{ Body: EnrollBody }>(
    '/v1/agents/enroll',
    { schema: { body: enrollBodySchema } },
    async (request, reply) => {
      const remoteIp = request.ip;
      if (!deps.enrollLimiter.consume(remoteIp)) {
        request.log.warn({ remoteIp }, 'enrollment rate limit exceeded');
        return fail(reply, 'rate_limited', 'Too many enrollment attempts');
      }

      if (!secretMatches(request.body.enrollmentSecret, deps.config.enrollmentSecret)) {
        // No tenant exists to attribute this to, so it stays in the process log
        // rather than being written into some other account's audit trail.
        request.log.warn({ remoteIp }, 'enrollment rejected: bad enrollment secret');
        return fail(reply, 'unauthorized', 'Invalid enrollment secret');
      }

      const result = await deps.repo.accounts.enrollAgentIntoNewAccount({
        displayName: request.body.displayName,
        identityPublicKey: request.body.identityPublicKey,
        identityAlgorithm: request.body.identityAlgorithm,
        noiseStaticPublicKey: request.body.noiseStaticPublicKey,
        noiseStaticSignature: request.body.noiseStaticSignature,
        remoteIp,
      });

      return reply.code(201).send({
        accountId: result.accountId,
        deviceId: result.deviceId,
        deviceToken: result.deviceToken,
      });
    },
  );
}

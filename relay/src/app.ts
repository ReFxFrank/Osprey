import websocket from '@fastify/websocket';
import Fastify, { type FastifyError, type FastifyInstance } from 'fastify';
import type { RelayConfig } from './config.ts';
import { fail } from './http/errors.ts';
import { createFixedWindowLimiter, type RateLimiter } from './http/rateLimit.ts';
import type { Repo } from './repo/index.ts';
import { registerDeviceRoutes } from './routes/devices.ts';
import { registerEnrollRoutes } from './routes/enroll.ts';
import { registerPairingRoutes } from './routes/pairing.ts';
import { registerWsRoutes } from './routes/ws.ts';
import { SocketHub } from './ws/hub.ts';

export interface RouteInfo {
  readonly method: string;
  readonly url: string;
  readonly websocket: boolean;
}

export interface RelayApp {
  readonly app: FastifyInstance;
  readonly hub: SocketHub;
  readonly enrollLimiter: RateLimiter;
  /**
   * Every route this instance registered. Exposed so the cross-tenant suite can
   * enumerate the surface instead of hard-coding it: a route added without a
   * corresponding tenant assertion fails CI rather than shipping untested
   * (brief §6.7, gate criterion 5).
   */
  readonly routes: readonly RouteInfo[];
}

export function quotaDefaultsFrom(config: RelayConfig) {
  return {
    maxDevices: config.defaultMaxDevices,
    maxPairingAttemptsPerHour: config.defaultMaxPairingAttemptsPerHour,
    turnBytesPerMonth: config.defaultTurnBytesPerMonth,
  };
}

export async function buildApp(config: RelayConfig, repo: Repo): Promise<RelayApp> {
  const app = Fastify({
    logger: { level: config.logLevel },
    /**
     * Exactly one hop, never `true`. `trustProxy: true` makes `request.ip` the
     * *leftmost* X-Forwarded-For entry, which is whatever the client typed —
     * so an attacker rotating that header gets a fresh rate-limit bucket per
     * request, and the enrollment limiter is the only structural bound on
     * account creation (execution plan item 11). With `1`, Fastify trusts only
     * the socket peer and takes the rightmost entry: the address Caddy itself
     * observed and appended. Any entries the client forged sit to the left of
     * it and are ignored.
     *
     * This is correct only because Caddy is the sole ingress — the relay
     * container publishes no host port (see docker-compose.yml).
     */
    trustProxy: 1,
    bodyLimit: 256 * 1024,
  });

  const hub = new SocketHub();
  const enrollLimiter = createFixedWindowLimiter(config.enrollRateLimitPerHour, 3_600_000);
  const redeemIpLimiter = createFixedWindowLimiter(config.redeemRateLimitPerMinute, 60_000);
  const redeemAccountLimiter = createFixedWindowLimiter(config.redeemRateLimitPerMinute, 60_000);

  const routes: RouteInfo[] = [];
  app.addHook('onRoute', (routeOptions) => {
    const methods = Array.isArray(routeOptions.method) ? routeOptions.method : [routeOptions.method];
    const websocketRoute = (routeOptions as { websocket?: boolean }).websocket === true;
    for (const method of methods) {
      routes.push({ method, url: routeOptions.url, websocket: websocketRoute });
    }
  });

  await app.register(websocket, { options: { maxPayload: 256 * 1024 } });

  app.setErrorHandler((error: FastifyError, request, reply) => {
    if (error.validation !== undefined) {
      return fail(reply, 'bad_request', error.message);
    }
    request.log.error({ err: error }, 'unhandled route error');
    return fail(reply, 'internal', 'Internal error');
  });

  app.setNotFoundHandler((_request, reply) => fail(reply, 'not_found', 'Not found'));

  app.get('/healthz', async (_request, reply) => reply.send({ status: 'ok' }));

  registerEnrollRoutes(app, { repo, config, enrollLimiter });
  registerPairingRoutes(app, { repo, config, redeemIpLimiter, redeemAccountLimiter });
  registerDeviceRoutes(app, {
    repo,
    onDeviceRevoked: (accountId, deviceId) => hub.drop(accountId, deviceId, 'device revoked'),
  });
  registerWsRoutes(app, { repo, hub });

  await app.ready();
  return { app, hub, enrollLimiter, routes };
}

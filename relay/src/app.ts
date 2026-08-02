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
    // Caddy terminates TLS and is the only thing in front of the relay, so its
    // forwarding headers are the authority on client IP — which the enrollment
    // limiter keys on.
    trustProxy: true,
    bodyLimit: 256 * 1024,
  });

  const hub = new SocketHub();
  const enrollLimiter = createFixedWindowLimiter(config.enrollRateLimitPerHour, 3_600_000);

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
  registerPairingRoutes(app, { repo, config });
  registerDeviceRoutes(app, {
    repo,
    onDeviceRevoked: (accountId, deviceId) => hub.drop(accountId, deviceId, 'device revoked'),
  });
  registerWsRoutes(app, { repo, hub });

  await app.ready();
  return { app, hub, enrollLimiter, routes };
}

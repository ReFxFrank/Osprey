import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { WebSocket } from 'ws';
import { deviceOf, requireDevice } from '../http/auth.ts';
import type { AuthenticatedDevice, Repo } from '../repo/index.ts';
import { parseClientFrame } from '../ws/frames.ts';
import type { SocketHub } from '../ws/hub.ts';

export interface WsDeps {
  readonly repo: Repo;
  readonly hub: SocketHub;
}

function send(socket: WebSocket, value: unknown): void {
  if (socket.readyState !== socket.OPEN) return;
  socket.send(JSON.stringify(value));
}

async function handleFrame(
  deps: WsDeps,
  device: AuthenticatedDevice,
  socket: WebSocket,
  raw: unknown,
): Promise<void> {
  const parsed = parseClientFrame(raw);
  if (!parsed.ok) {
    send(socket, { t: 'error', code: 'bad_request', message: parsed.message });
    return;
  }
  if (parsed.frame.t === 'ping') {
    send(socket, { t: 'pong' });
    return;
  }

  const { to, payload } = parsed.frame;
  // Both the pairing lookup and the socket lookup are scoped to this device's
  // account, so a device id belonging to another tenant is indistinguishable
  // from one that does not exist (§6.7).
  const paired = await deps.repo.pairings.peerIsPaired(device.accountId, device.deviceId, to);
  if (!paired) {
    await deps.repo.audit.record(device.accountId, {
      event: 'ws.relay_rejected',
      deviceId: device.deviceId,
      detail: { reason: 'not_paired', to },
    });
    send(socket, { t: 'error', code: 'not_found', message: 'Not found' });
    return;
  }

  const peer = deps.hub.get(device.accountId, to);
  if (peer === undefined) {
    send(socket, { t: 'error', code: 'not_found', message: 'Peer is not connected' });
    return;
  }
  send(peer, { t: 'relay', from: device.deviceId, payload });
}

function registerAttachRoute(app: FastifyInstance, deps: WsDeps, path: string, kind: 'agent' | 'client'): void {
  app.get(path, { websocket: true, preHandler: requireDevice(deps.repo) }, (socket: WebSocket, request: FastifyRequest) => {
    const device = deviceOf(request);
    if (device.kind !== kind) {
      socket.close(4003, 'wrong endpoint for this device kind');
      return;
    }

    deps.hub.attach(device.accountId, device.deviceId, socket);
    void deps.repo.devices
      .touchLastSeen(device.accountId, device.deviceId)
      .catch((err: unknown) => request.log.error({ err }, 'failed to update last_seen_at'));
    void deps.repo.audit
      .record(device.accountId, {
        event: 'ws.attached',
        deviceId: device.deviceId,
        detail: { kind },
        remoteIp: request.ip,
      })
      .catch((err: unknown) => request.log.error({ err }, 'failed to write ws.attached audit row'));

    socket.on('message', (raw: unknown) => {
      // A rejected promise here would be an unhandled rejection triggered by
      // remote input, so every failure is logged and the socket survives.
      void handleFrame(deps, device, socket, raw).catch((err: unknown) => {
        request.log.error({ err, deviceId: device.deviceId }, 'websocket frame handling failed');
        send(socket, { t: 'error', code: 'internal', message: 'Frame could not be processed' });
      });
    });

    socket.on('error', (err: unknown) => {
      request.log.warn({ err, deviceId: device.deviceId }, 'websocket error');
    });

    socket.on('close', () => {
      deps.hub.detach(device.accountId, device.deviceId, socket);
    });
  });
}

export function registerWsRoutes(app: FastifyInstance, deps: WsDeps): void {
  registerAttachRoute(app, deps, '/v1/agent', 'agent');
  registerAttachRoute(app, deps, '/v1/client', 'client');
}

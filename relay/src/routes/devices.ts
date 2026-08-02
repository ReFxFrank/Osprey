import type { FastifyInstance } from 'fastify';
import { deviceOf, requireDevice } from '../http/auth.ts';
import { notFound } from '../http/errors.ts';
import type { Repo } from '../repo/index.ts';
import { idParamSchema } from './schemas.ts';

export interface DeviceDeps {
  readonly repo: Repo;
  /** Called after a successful revoke so any live socket for that device drops immediately (§6.1). */
  readonly onDeviceRevoked: (accountId: string, deviceId: string) => void;
}

export function registerDeviceRoutes(app: FastifyInstance, deps: DeviceDeps): void {
  const authenticated = requireDevice(deps.repo);

  app.get('/v1/devices', { preHandler: authenticated }, async (request, reply) => {
    const device = deviceOf(request);
    const devices = await deps.repo.devices.list(device.accountId);
    return reply.send({ devices });
  });

  app.delete<{ Params: { id: string } }>(
    '/v1/devices/:id',
    { schema: { params: idParamSchema }, preHandler: authenticated },
    async (request, reply) => {
      const device = deviceOf(request);
      // Revoking a device registration is the host-side act; a client revokes
      // its own pairing instead. A client asking for this gets 404 rather than
      // 403 for the same reason a foreign tenant does — 403 would confirm the
      // target exists (§6.7).
      if (device.kind !== 'agent') return notFound(reply);

      const revoked = await deps.repo.devices.revoke(device.accountId, request.params.id, {
        deviceId: device.deviceId,
        remoteIp: request.ip,
      });
      if (!revoked) return notFound(reply);
      deps.onDeviceRevoked(device.accountId, request.params.id);
      return reply.code(204).send();
    },
  );
}

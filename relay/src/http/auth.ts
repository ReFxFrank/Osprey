import type { FastifyReply, FastifyRequest } from 'fastify';
import type { AuthenticatedDevice, Repo } from '../repo/index.ts';
import { parseDeviceToken } from '../repo/index.ts';
import { fail } from './errors.ts';

declare module 'fastify' {
  interface FastifyRequest {
    device?: AuthenticatedDevice;
  }
}

function bearer(request: FastifyRequest): string | null {
  const header = request.headers.authorization;
  if (typeof header !== 'string') return null;
  const [scheme, value] = header.split(' ');
  if (scheme?.toLowerCase() !== 'bearer' || value === undefined || value === '') return null;
  return value;
}

/** Resolves the caller's device without sending a reply; used by the WebSocket routes. */
export async function resolveDevice(repo: Repo, request: FastifyRequest): Promise<AuthenticatedDevice | null> {
  const token = bearer(request);
  if (token === null) return null;
  const parsed = parseDeviceToken(token);
  if (parsed === null) return null;
  return repo.devices.authenticate(parsed.accountId, parsed.secretHash);
}

export function requireDevice(repo: Repo) {
  return async function preHandler(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const device = await resolveDevice(repo, request);
    if (device === null) {
      await fail(reply, 'unauthorized', 'Missing or invalid device token');
      return;
    }
    request.device = device;
  };
}

/**
 * Handlers run only after `requireDevice`, but TypeScript cannot see that
 * ordering, so this converts the optional into a hard failure instead of a
 * non-null assertion that would be a silent authentication bypass if a route
 * were ever registered without the hook.
 */
export function deviceOf(request: FastifyRequest): AuthenticatedDevice {
  const device = request.device;
  if (device === undefined) {
    throw new Error('Route reached without requireDevice preHandler');
  }
  return device;
}

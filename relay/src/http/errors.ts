import type { FastifyReply } from 'fastify';

/** Mirrors the `ErrorCode` enum in `proto/messages.toml` so one vocabulary spans both planes. */
export type ErrorCode =
  | 'bad_request'
  | 'unauthorized'
  | 'not_found'
  | 'conflict'
  | 'rate_limited'
  | 'internal';

const STATUS: Record<ErrorCode, number> = {
  bad_request: 400,
  unauthorized: 401,
  not_found: 404,
  conflict: 409,
  rate_limited: 429,
  internal: 500,
};

export interface ErrorBody {
  readonly error: { readonly code: ErrorCode; readonly message: string };
}

export function fail(reply: FastifyReply, code: ErrorCode, message: string): FastifyReply {
  return reply.code(STATUS[code]).send({ error: { code, message } } satisfies ErrorBody);
}

/**
 * Brief §6.7 is explicit: a resource belonging to another tenant must answer
 * 404, never 403. 403 confirms the id exists, which is itself the cross-tenant
 * leak. Every "not yours" path in this codebase routes through here so the
 * distinction cannot be reintroduced one handler at a time.
 */
export function notFound(reply: FastifyReply): FastifyReply {
  return fail(reply, 'not_found', 'Not found');
}

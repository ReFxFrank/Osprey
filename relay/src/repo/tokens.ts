import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_RE.test(value);
}

/**
 * Relay-plane bearer token. The account id is carried in the token itself so
 * that authentication is a tenant-scoped lookup: `auth` derives the tenant from
 * the presented id and then matches the hash *within* that tenant. Without
 * this, authentication would be the one global `SELECT` in the system, which is
 * precisely the shape §6.7 forbids. A forged account id simply fails the hash
 * comparison — the id is a routing hint, never a credential.
 */
export interface ParsedDeviceToken {
  readonly accountId: string;
  readonly secretHash: string;
}

export function mintDeviceToken(accountId: string): { token: string; secretHash: string } {
  const secret = randomBytes(32).toString('base64url');
  return { token: `${accountId}.${secret}`, secretHash: sha256Hex(secret) };
}

export function parseDeviceToken(token: string): ParsedDeviceToken | null {
  const separator = token.indexOf('.');
  if (separator <= 0) return null;
  const accountId = token.slice(0, separator);
  const secret = token.slice(separator + 1);
  if (!isUuid(accountId) || secret.length === 0) return null;
  return { accountId, secretHash: sha256Hex(secret) };
}

/** Constant-time comparison of two equal-length hex digests. */
export function digestsEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

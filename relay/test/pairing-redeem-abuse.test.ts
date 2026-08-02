import { randomBytes } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  fakePeerMaterial,
  pairingSecret,
  startHarness,
  TEST_ENROLLMENT_SECRET,
  type Harness,
} from './support/harness.ts';
import { truncateAll, withOwnerSql } from './support/pg.ts';

/**
 * `POST /v1/pairing/redeem` is the relay's one unauthenticated route that names
 * a tenant, and it takes that tenant from the request body. Everything here is
 * about what an anonymous caller who knows nothing but an account id — which
 * never rotates, so a revoked controller still has one — can make it do.
 */

const CADDY_OBSERVED = '198.51.100.20';

/** The header shape Caddy produces: its own observation appended on the right. */
function fromIp(ip: string): Record<string, string> {
  return { 'x-forwarded-for': `203.0.113.7, ${ip}` };
}

function randomRoutingId(): string {
  return randomBytes(32).toString('hex');
}

async function enrollAgent(h: Harness, label: string) {
  const res = await h.app.inject({
    method: 'POST',
    url: '/v1/agents/enroll',
    payload: { enrollmentSecret: TEST_ENROLLMENT_SECRET, ...fakePeerMaterial('agent', label) },
  });
  expect(res.statusCode).toBe(201);
  return res.json() as { accountId: string; deviceId: string; deviceToken: string };
}

function issue(h: Harness, token: string, routingId: string) {
  return h.app.inject({
    method: 'POST',
    url: '/v1/pairing/tokens',
    headers: { authorization: `Bearer ${token}` },
    payload: { routingId },
  });
}

function redeem(h: Harness, accountId: string, routingId: string, ip = CADDY_OBSERVED, label = 'phone') {
  return h.app.inject({
    method: 'POST',
    url: '/v1/pairing/redeem',
    headers: fromIp(ip),
    payload: { accountId, routingId, ...fakePeerMaterial('client', label) },
  });
}

async function auditRowCount(): Promise<number> {
  return withOwnerSql(async (owner) => {
    const [row] = await owner<{ n: string }[]>`select count(*)::text as n from audit_relay`;
    return Number.parseInt(row?.n ?? '0', 10);
  });
}

describe('unauthenticated redeem abuse', () => {
  let h: Harness;

  beforeEach(async () => {
    await truncateAll();
  });
  afterEach(async () => {
    if (h !== undefined) await h.close();
  });

  /**
   * The write-amplification regression. Every one of these requests names a
   * real tenant and fails; not one of them may leave a row behind. Before the
   * fix each miss probed for the account and, on a hit, wrote a
   * `pairing.token_rejected` row into that tenant's audit_relay — an anonymous,
   * unbounded, permanent append into someone else's security log.
   */
  it('writes nothing to the victim tenant when flooded with bogus routing ids', async () => {
    h = await startHarness({ OSPREY_REDEEM_RATE_LIMIT_PER_MINUTE: '1000' });
    const victim = await enrollAgent(h, 'victim');
    const before = await auditRowCount();

    const codes = new Set<number>();
    for (let i = 0; i < 200; i += 1) {
      const res = await redeem(h, victim.accountId, randomRoutingId(), `198.51.100.${i % 200}`);
      codes.add(res.statusCode);
    }

    expect([...codes]).toEqual([404]);
    expect(await auditRowCount()).toBe(before);
  });

  it('answers a bogus routing id for a non-existent account identically', async () => {
    h = await startHarness({ OSPREY_REDEEM_RATE_LIMIT_PER_MINUTE: '1000' });
    const victim = await enrollAgent(h, 'victim');
    const real = await redeem(h, victim.accountId, randomRoutingId());
    const fake = await redeem(h, '00000000-0000-4000-8000-000000000000', randomRoutingId());
    expect(real.statusCode).toBe(404);
    expect(fake.statusCode).toBe(404);
    expect(real.json()).toEqual(fake.json());
  });

  it('rate limits anonymous redeems per source ip', async () => {
    h = await startHarness({ OSPREY_REDEEM_RATE_LIMIT_PER_MINUTE: '3' });
    const victim = await enrollAgent(h, 'victim');

    const codes: number[] = [];
    for (let i = 0; i < 5; i += 1) {
      codes.push((await redeem(h, victim.accountId, randomRoutingId())).statusCode);
    }
    expect(codes).toEqual([404, 404, 404, 429, 429]);
  });

  it('rate limits failed redeems aimed at one account even from many source ips', async () => {
    h = await startHarness({ OSPREY_REDEEM_RATE_LIMIT_PER_MINUTE: '3' });
    const victim = await enrollAgent(h, 'victim');

    const codes: number[] = [];
    for (let i = 0; i < 5; i += 1) {
      // A distinct source address each time, so only the per-account window can
      // be what stops this.
      codes.push((await redeem(h, victim.accountId, randomRoutingId(), `198.51.100.${i}`)).statusCode);
    }
    expect(codes).toEqual([404, 404, 404, 429, 429]);
  });

  /**
   * The per-account window is reachable by third parties, so it must not be
   * spendable by the tenant's own successful pairings — otherwise the limiter
   * would deny service to exactly the people it protects.
   */
  it('does not charge a tenant for its own successful redemptions', async () => {
    h = await startHarness({ OSPREY_REDEEM_RATE_LIMIT_PER_MINUTE: '2' });
    const agent = await enrollAgent(h, 'agent');

    const codes: number[] = [];
    for (let i = 0; i < 5; i += 1) {
      const { routingId } = pairingSecret();
      expect((await issue(h, agent.deviceToken, routingId)).statusCode).toBe(201);
      codes.push((await redeem(h, agent.accountId, routingId, `198.51.100.${i}`, `phone-${i}`)).statusCode);
    }
    expect(codes).toEqual([201, 201, 201, 201, 201]);
  });
});

describe('routing id collision across tenants', () => {
  let h: Harness;

  beforeEach(async () => {
    await truncateAll();
    h = await startHarness();
  });
  afterEach(async () => {
    await h.close();
  });

  /**
   * `pairing_tokens_routing_id_key` is global on purpose — an ambiguous
   * rendezvous id would be worse — but that means tenant B's insert can be
   * refused by a row in tenant A that B cannot see. Left unhandled the
   * exception reached the generic error handler as `500 {"code":"internal"}`,
   * which is both an unhandled database exception and a signal distinguishable
   * from success.
   */
  it('reports a taken routing id as a handled conflict, never a 500', async () => {
    const a = await enrollAgent(h, 'alpha');
    const b = await enrollAgent(h, 'bravo');
    const { routingId } = pairingSecret();

    expect((await issue(h, a.deviceToken, routingId)).statusCode).toBe(201);

    const collision = await issue(h, b.deviceToken, routingId);
    expect(collision.statusCode).not.toBe(500);
    expect(collision.statusCode).toBe(409);
    expect(collision.json()).toMatchObject({ error: { code: 'conflict' } });
  });

  it('rolls the refused transaction back and leaves both tenants usable', async () => {
    const a = await enrollAgent(h, 'alpha');
    const b = await enrollAgent(h, 'bravo');
    const { routingId } = pairingSecret();
    await issue(h, a.deviceToken, routingId);
    expect((await issue(h, b.deviceToken, routingId)).statusCode).toBe(409);

    await withOwnerSql(async (owner) => {
      const rows = await owner<{ account_id: string }[]>`
        select account_id from pairing_tokens where routing_id = ${routingId}
      `;
      expect(rows).toHaveLength(1);
      expect(rows[0]?.account_id).toBe(a.accountId);
    });

    // The aborted transaction must not have poisoned the pooled connection, and
    // must not have consumed B's pairing quota by leaving a row behind.
    const { routingId: fresh } = pairingSecret();
    expect((await issue(h, b.deviceToken, fresh)).statusCode).toBe(201);
    expect((await redeem(h, a.accountId, routingId)).statusCode).toBe(201);
  });

  it('does not audit a collision into either tenant', async () => {
    const a = await enrollAgent(h, 'alpha');
    const b = await enrollAgent(h, 'bravo');
    const { routingId } = pairingSecret();
    await issue(h, a.deviceToken, routingId);
    const before = await auditRowCount();

    for (let i = 0; i < 20; i += 1) {
      expect((await issue(h, b.deviceToken, routingId)).statusCode).toBe(409);
    }
    expect(await auditRowCount()).toBe(before);
  });
});

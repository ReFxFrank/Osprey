import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  fakePeerMaterial,
  pairingSecret,
  startHarness,
  TEST_ENROLLMENT_SECRET,
  type Harness,
} from './support/harness.ts';
import { truncateAll, withOwnerSql } from './support/pg.ts';

async function enrollAgent(h: Harness, label: string) {
  const res = await h.app.inject({
    method: 'POST',
    url: '/v1/agents/enroll',
    payload: { enrollmentSecret: TEST_ENROLLMENT_SECRET, ...fakePeerMaterial('agent', label) },
  });
  expect(res.statusCode).toBe(201);
  return res.json() as { accountId: string; deviceId: string; deviceToken: string };
}

async function issue(h: Harness, token: string, routingId: string) {
  return h.app.inject({
    method: 'POST',
    url: '/v1/pairing/tokens',
    headers: { authorization: `Bearer ${token}` },
    payload: { routingId },
  });
}

function redeem(h: Harness, accountId: string, routingId: string, label = 'phone') {
  return h.app.inject({
    method: 'POST',
    url: '/v1/pairing/redeem',
    payload: { accountId, routingId, ...fakePeerMaterial('client', label) },
  });
}

describe('pairing token lifecycle', () => {
  let h: Harness;

  beforeAll(async () => {
    h = await startHarness();
  });
  afterAll(async () => {
    await h.close();
  });
  beforeEach(async () => {
    await truncateAll();
  });

  it('stores only the routing id, never the pairing secret', async () => {
    const agent = await enrollAgent(h, 'agent');
    const { secret, routingId } = pairingSecret();
    expect((await issue(h, agent.deviceToken, routingId)).statusCode).toBe(201);

    await withOwnerSql(async (owner) => {
      const rows = await owner`select * from pairing_tokens`;
      expect(rows).toHaveLength(1);
      const serialised = JSON.stringify(rows[0]);
      expect(serialised).toContain(routingId);
      // The Noise PSK must be unrecoverable from a full database dump: a relay
      // operator holding the secret could complete the handshake and pair itself.
      expect(serialised).not.toContain(secret);
    });
  });

  it('is single use — the second redeem of the same routing id is 404', async () => {
    const agent = await enrollAgent(h, 'agent');
    const { routingId } = pairingSecret();
    await issue(h, agent.deviceToken, routingId);

    expect((await redeem(h, agent.accountId, routingId, 'phone-1')).statusCode).toBe(201);
    const second = await redeem(h, agent.accountId, routingId, 'phone-2');
    expect(second.statusCode).toBe(404);
    expect(second.statusCode).not.toBe(403);
  });

  it('redeems atomically — concurrent redemptions produce exactly one pairing', async () => {
    const agent = await enrollAgent(h, 'agent');
    const { routingId } = pairingSecret();
    await issue(h, agent.deviceToken, routingId);

    const attempts = await Promise.all(
      Array.from({ length: 8 }, (_, i) => redeem(h, agent.accountId, routingId, `racer-${i}`)),
    );
    const winners = attempts.filter((r) => r.statusCode === 201);
    const losers = attempts.filter((r) => r.statusCode === 404);
    expect(winners).toHaveLength(1);
    expect(losers).toHaveLength(7);

    await withOwnerSql(async (owner) => {
      const pairings = await owner`select id from pairings`;
      const clients = await owner`select id from devices where kind = 'client'`;
      expect(pairings).toHaveLength(1);
      expect(clients).toHaveLength(1);
    });
  });

  it('rejects an expired token', async () => {
    const agent = await enrollAgent(h, 'agent');
    const { routingId } = pairingSecret();
    await issue(h, agent.deviceToken, routingId);

    // Age the row past the 120-second window rather than sleeping for it.
    await withOwnerSql(async (owner) => {
      await owner`update pairing_tokens set expires_at = now() - interval '1 second'`;
    });

    const res = await redeem(h, agent.accountId, routingId);
    expect(res.statusCode).toBe(404);
  });

  it('issues tokens with the 120-second expiry the brief fixes', async () => {
    const agent = await enrollAgent(h, 'agent');
    const { routingId } = pairingSecret();
    const before = Date.now();
    const res = await issue(h, agent.deviceToken, routingId);
    const { expiresAt } = res.json() as { expiresAt: string };
    const ttlMs = new Date(expiresAt).getTime() - before;
    // The window is measured from when the handler ran, which is a few
    // milliseconds after `before`, so the upper bound carries that slack.
    expect(ttlMs).toBeGreaterThan(118_000);
    expect(ttlMs).toBeLessThan(125_000);
  });

  it('refuses to issue a token to a client device', async () => {
    const agent = await enrollAgent(h, 'agent');
    const { routingId } = pairingSecret();
    await issue(h, agent.deviceToken, routingId);
    const redeemed = await redeem(h, agent.accountId, routingId);
    const client = redeemed.json() as { deviceToken: string };

    const { routingId: second } = pairingSecret();
    const res = await issue(h, client.deviceToken, second);
    expect(res.statusCode).toBe(404);
  });

  it('enforces the per-account pairing attempt quota', async () => {
    const h2 = await startHarness({ OSPREY_DEFAULT_MAX_PAIRING_ATTEMPTS_PER_HOUR: '3' });
    try {
      const agent = await enrollAgent(h2, 'agent');
      const codes: number[] = [];
      for (let i = 0; i < 5; i += 1) {
        const { routingId } = pairingSecret();
        codes.push((await issue(h2, agent.deviceToken, routingId)).statusCode);
      }
      expect(codes).toEqual([201, 201, 201, 429, 429]);
    } finally {
      await h2.close();
    }
  });

  it('rejects a token whose agent device has been revoked', async () => {
    const agent = await enrollAgent(h, 'agent');
    const { routingId } = pairingSecret();
    await issue(h, agent.deviceToken, routingId);

    await withOwnerSql(async (owner) => {
      await owner`update devices set revoked_at = now() where id = ${agent.deviceId}`;
    });

    expect((await redeem(h, agent.accountId, routingId)).statusCode).toBe(404);
  });

  it('records pairing success and revocation in audit_relay', async () => {
    const agent = await enrollAgent(h, 'agent');
    const { routingId } = pairingSecret();
    await issue(h, agent.deviceToken, routingId);
    const redeemed = await redeem(h, agent.accountId, routingId);
    const { pairingId, deviceToken } = redeemed.json() as { pairingId: string; deviceToken: string };
    await h.app.inject({
      method: 'DELETE',
      url: `/v1/pairings/${pairingId}`,
      headers: { authorization: `Bearer ${deviceToken}` },
    });

    await withOwnerSql(async (owner) => {
      const rows = await owner<{ event: string }[]>`select event from audit_relay order by created_at`;
      const events = rows.map((r) => r.event);
      expect(events).toContain('account.created');
      expect(events).toContain('pairing.token_issued');
      expect(events).toContain('pairing.succeeded');
      expect(events).toContain('pairing.revoked');
    });
  });

  /**
   * The audit log is a mandated, non-suppressible control, so what may write to
   * it is part of its definition. A rejection is only attributable to a tenant
   * once the caller has proved possession of the QR secret — which is exactly
   * the moment the redeem UPDATE claims a row.
   */
  it('audits a rejection only after the caller has claimed the token row', async () => {
    const agent = await enrollAgent(h, 'agent');
    const { routingId } = pairingSecret();
    await issue(h, agent.deviceToken, routingId);
    await withOwnerSql(async (owner) => {
      await owner`update devices set revoked_at = now() where id = ${agent.deviceId}`;
    });

    expect((await redeem(h, agent.accountId, routingId)).statusCode).toBe(404);

    await withOwnerSql(async (owner) => {
      const rows = await owner<{ event: string; detail: { reason?: string } }[]>`
        select event, detail from audit_relay where event = 'pairing.token_rejected'
      `;
      expect(rows).toHaveLength(1);
      expect(rows[0]?.detail.reason).toBe('agent_device_revoked');
    });
  });

  /**
   * Suppressing the miss-path audit write is what closed the amplification, but
   * over-suppressing it blinds the log to real replays. A routing id is
   * SHA-256(pairing_secret), so a caller presenting one that matches a stored
   * row has proved QR possession and cannot be an anonymous flooder.
   */
  it('audits a replayed token but stays silent for a routing id that matches nothing', async () => {
    const agent = await enrollAgent(h, 'agent');
    const { routingId } = pairingSecret();
    await issue(h, agent.deviceToken, routingId);
    await withOwnerSql(async (owner) => {
      await owner`update pairing_tokens set expires_at = now() - interval '1 hour' where routing_id = ${routingId}`;
    });

    // Correct routing id, but the token is past its TTL: a real near-miss.
    expect((await redeem(h, agent.accountId, routingId)).statusCode).toBe(404);

    const auditedReasons = async () =>
      withOwnerSql(async (owner) => {
        const rows = await owner<{ detail: { reason?: string } }[]>`
          select detail from audit_relay where event = 'pairing.token_rejected'
        `;
        return rows.map((r) => r.detail.reason);
      });

    expect(await auditedReasons()).toEqual(['token_expired']);

    // A flood of routing ids matching no row must not add anything.
    for (let i = 0; i < 25; i += 1) {
      await redeem(h, agent.accountId, pairingSecret().routingId);
    }
    expect(await auditedReasons()).toEqual(['token_expired']);
  });
});

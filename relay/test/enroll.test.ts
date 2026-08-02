import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { fakePeerMaterial, startHarness, TEST_ENROLLMENT_SECRET, type Harness } from './support/harness.ts';
import { truncateAll } from './support/pg.ts';

/**
 * Execution plan item 11: implicit account creation (brief §0.1) is an unbounded
 * minting surface unless it is guarded outside the tenant, because per-account
 * quotas cannot bound the creation of accounts.
 */
describe('agent enrollment guards', () => {
  let h: Harness;

  beforeEach(async () => {
    await truncateAll();
  });
  afterEach(async () => {
    if (h !== undefined) await h.close();
  });

  it('rejects a wrong enrollment secret with 401 and creates nothing', async () => {
    h = await startHarness();
    const res = await h.app.inject({
      method: 'POST',
      url: '/v1/agents/enroll',
      payload: { enrollmentSecret: 'x'.repeat(40), ...fakePeerMaterial('agent', 'intruder') },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toMatchObject({ error: { code: 'unauthorized' } });
  });

  it('rejects a body with no enrollment secret at the schema layer', async () => {
    h = await startHarness();
    const res = await h.app.inject({
      method: 'POST',
      url: '/v1/agents/enroll',
      payload: fakePeerMaterial('agent', 'intruder'),
    });
    expect(res.statusCode).toBe(400);
  });

  /**
   * Caddy is the only ingress and appends the address it observed to the right
   * of whatever the client sent, so this is the header shape the relay actually
   * receives. `CADDY_OBSERVED` is the real client; everything to its left is
   * client-controlled text.
   */
  const CADDY_OBSERVED = '198.51.100.20';
  const forwardedFor = (clientSupplied?: string) => ({
    'x-forwarded-for': clientSupplied === undefined ? CADDY_OBSERVED : `${clientSupplied}, ${CADDY_OBSERVED}`,
  });

  it('applies a global per-IP rate limit that no tenant can raise', async () => {
    h = await startHarness({ OSPREY_ENROLL_RATE_LIMIT_PER_HOUR: '2' });
    const codes: number[] = [];
    for (let i = 0; i < 4; i += 1) {
      const res = await h.app.inject({
        method: 'POST',
        url: '/v1/agents/enroll',
        // Stated explicitly rather than left to the injected socket address:
        // the header is the input the limiter keys on, so a test that omits it
        // is not testing the limiter under the conditions it runs in.
        headers: forwardedFor(),
        payload: { enrollmentSecret: TEST_ENROLLMENT_SECRET, ...fakePeerMaterial('agent', `a${i}`) },
      });
      codes.push(res.statusCode);
    }
    expect(codes).toEqual([201, 201, 429, 429]);
  });

  /**
   * The regression. With `trustProxy: true`, `request.ip` is the *leftmost*
   * X-Forwarded-For entry — pure client input — so rotating it hands the caller
   * a fresh bucket per request and the only structural bound on account
   * creation (execution plan item 11) evaporates.
   */
  it('cannot be bypassed by rotating a client-supplied X-Forwarded-For', async () => {
    h = await startHarness({ OSPREY_ENROLL_RATE_LIMIT_PER_HOUR: '2' });
    const codes: number[] = [];
    for (let i = 0; i < 8; i += 1) {
      const res = await h.app.inject({
        method: 'POST',
        url: '/v1/agents/enroll',
        headers: forwardedFor(`203.0.113.${i}`),
        payload: { enrollmentSecret: TEST_ENROLLMENT_SECRET, ...fakePeerMaterial('agent', `spoof${i}`) },
      });
      codes.push(res.statusCode);
    }
    expect(codes).toEqual([201, 201, 429, 429, 429, 429, 429, 429]);
  });

  it('ignores forged hops however many the caller stacks up', async () => {
    h = await startHarness({ OSPREY_ENROLL_RATE_LIMIT_PER_HOUR: '1' });
    const codes: number[] = [];
    for (let i = 0; i < 3; i += 1) {
      const res = await h.app.inject({
        method: 'POST',
        url: '/v1/agents/enroll',
        headers: forwardedFor(`10.0.0.${i}, 172.16.0.${i}, 192.0.2.${i}`),
        payload: { enrollmentSecret: TEST_ENROLLMENT_SECRET, ...fakePeerMaterial('agent', `stack${i}`) },
      });
      codes.push(res.statusCode);
    }
    expect(codes).toEqual([201, 429, 429]);
  });

  it('counts rejected attempts against the rate limit too', async () => {
    h = await startHarness({ OSPREY_ENROLL_RATE_LIMIT_PER_HOUR: '2' });
    const bad = await h.app.inject({
      method: 'POST',
      url: '/v1/agents/enroll',
      payload: { enrollmentSecret: 'x'.repeat(40), ...fakePeerMaterial('agent', 'bad') },
    });
    expect(bad.statusCode).toBe(401);

    const codes: number[] = [];
    for (let i = 0; i < 2; i += 1) {
      const res = await h.app.inject({
        method: 'POST',
        url: '/v1/agents/enroll',
        payload: { enrollmentSecret: TEST_ENROLLMENT_SECRET, ...fakePeerMaterial('agent', `a${i}`) },
      });
      codes.push(res.statusCode);
    }
    // Rate limiting a brute-force attempt is the entire point; the limiter must
    // be consumed before the secret is checked, not after.
    expect(codes).toEqual([201, 429]);
  });

  it('provisions a quota row with the configured defaults on the new account', async () => {
    h = await startHarness({ OSPREY_DEFAULT_MAX_DEVICES: '4' });
    const res = await h.app.inject({
      method: 'POST',
      url: '/v1/agents/enroll',
      payload: { enrollmentSecret: TEST_ENROLLMENT_SECRET, ...fakePeerMaterial('agent', 'agent') },
    });
    expect(res.statusCode).toBe(201);
    const { accountId, deviceToken } = res.json() as { accountId: string; deviceToken: string };
    expect(deviceToken.startsWith(`${accountId}.`)).toBe(true);

    const list = await h.app.inject({
      method: 'GET',
      url: '/v1/devices',
      headers: { authorization: `Bearer ${deviceToken}` },
    });
    expect(list.statusCode).toBe(200);
    expect((list.json() as { devices: unknown[] }).devices).toHaveLength(1);
  });

  it('refuses to start without an enrollment secret', async () => {
    await expect(startHarness({ OSPREY_ENROLLMENT_SECRET: '' })).rejects.toThrow(
      /OSPREY_ENROLLMENT_SECRET/,
    );
  });

  it('refuses an enrollment secret short enough to brute force', async () => {
    await expect(startHarness({ OSPREY_ENROLLMENT_SECRET: 'short' })).rejects.toThrow(/at least 32/);
  });
});

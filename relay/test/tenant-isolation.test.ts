import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { RouteInfo } from '../src/app.ts';
import {
  createAccount,
  fakePeerMaterial,
  pairingSecret,
  startHarness,
  TEST_ENROLLMENT_SECRET,
  type Account,
  type Harness,
} from './support/harness.ts';
import { truncateAll } from './support/pg.ts';
import { openWs, type WsClient } from './support/ws.ts';

/**
 * Gate P0 criterion 5 / brief §6.7. Two accounts, every endpoint, 404 — never
 * 403, because 403 confirms the resource exists and existence is exactly what
 * must not leak across tenants.
 *
 * The route table is enumerated from the running Fastify instance rather than
 * transcribed here. The `covers` key of each case below is matched against that
 * enumeration, and the final test asserts the two sets are equal — so adding a
 * route without adding a tenant assertion fails CI.
 */

interface TenantCase {
  readonly name: string;
  /** `${METHOD} ${url}` keys from the live route table that this case exercises. */
  readonly covers: readonly string[];
  run(ctx: { h: Harness; a: Account; b: Account; wsUrl: string }): Promise<void>;
}

/**
 * Routes that own no tenant resource. Each needs a stated reason, so the
 * exemption list cannot quietly become a place to hide an untested endpoint.
 */
const EXEMPT: Record<string, string> = {
  'GET /healthz': 'Liveness probe. Reads nothing, returns a constant, and is reachable unauthenticated by design.',
};

const cases: TenantCase[] = [
  {
    name: 'enroll never joins an existing tenant, even when a foreign device token is presented',
    covers: ['POST /v1/agents/enroll'],
    async run({ h, a, b }) {
      const res = await h.app.inject({
        method: 'POST',
        url: '/v1/agents/enroll',
        headers: { authorization: `Bearer ${b.agentToken}` },
        payload: { enrollmentSecret: TEST_ENROLLMENT_SECRET, ...fakePeerMaterial('agent', 'intruder') },
      });
      expect(res.statusCode).toBe(201);
      const body = res.json() as { accountId: string };
      expect(body.accountId).not.toBe(a.accountId);
      expect(body.accountId).not.toBe(b.accountId);

      // And B's device list is unchanged by it.
      const list = await h.app.inject({
        method: 'GET',
        url: '/v1/devices',
        headers: { authorization: `Bearer ${b.agentToken}` },
      });
      const devices = (list.json() as { devices: { id: string }[] }).devices;
      expect(devices).toHaveLength(2);
    },
  },
  {
    name: 'a pairing token issued by A cannot be redeemed into B',
    covers: ['POST /v1/pairing/tokens', 'POST /v1/pairing/redeem'],
    async run({ h, a, b }) {
      const { routingId } = pairingSecret();
      const issued = await h.app.inject({
        method: 'POST',
        url: '/v1/pairing/tokens',
        headers: { authorization: `Bearer ${a.agentToken}` },
        payload: { routingId },
      });
      expect(issued.statusCode).toBe(201);

      const foreign = await h.app.inject({
        method: 'POST',
        url: '/v1/pairing/redeem',
        payload: { accountId: b.accountId, routingId, ...fakePeerMaterial('client', 'thief') },
      });
      expect(foreign.statusCode).toBe(404);
      expect(foreign.statusCode).not.toBe(403);

      // The token is still redeemable by its real tenant, proving the 404 came
      // from the tenant predicate and not from the token being consumed.
      const rightful = await h.app.inject({
        method: 'POST',
        url: '/v1/pairing/redeem',
        payload: { accountId: a.accountId, routingId, ...fakePeerMaterial('client', 'phone-2') },
      });
      expect(rightful.statusCode).toBe(201);
    },
  },
  {
    name: 'GET /v1/devices returns only the caller’s tenant',
    covers: ['GET /v1/devices'],
    async run({ h, a, b }) {
      const res = await h.app.inject({
        method: 'GET',
        url: '/v1/devices',
        headers: { authorization: `Bearer ${a.agentToken}` },
      });
      expect(res.statusCode).toBe(200);
      const ids = (res.json() as { devices: { id: string }[] }).devices.map((d) => d.id);
      expect(ids).toContain(a.agentDeviceId);
      expect(ids).toContain(a.clientDeviceId);
      expect(ids).not.toContain(b.agentDeviceId);
      expect(ids).not.toContain(b.clientDeviceId);
    },
  },
  {
    name: 'DELETE /v1/pairings/:id is 404 for a foreign pairing and 204 for its own',
    covers: ['DELETE /v1/pairings/:id'],
    async run({ h, a, b }) {
      const foreign = await h.app.inject({
        method: 'DELETE',
        url: `/v1/pairings/${b.pairingId}`,
        headers: { authorization: `Bearer ${a.clientToken}` },
      });
      expect(foreign.statusCode).toBe(404);
      expect(foreign.statusCode).not.toBe(403);

      const own = await h.app.inject({
        method: 'DELETE',
        url: `/v1/pairings/${a.pairingId}`,
        headers: { authorization: `Bearer ${a.clientToken}` },
      });
      expect(own.statusCode).toBe(204);

      // B's pairing survived A's attempt.
      const bStillWorks = await h.app.inject({
        method: 'DELETE',
        url: `/v1/pairings/${b.pairingId}`,
        headers: { authorization: `Bearer ${b.clientToken}` },
      });
      expect(bStillWorks.statusCode).toBe(204);
    },
  },
  {
    name: 'DELETE /v1/devices/:id is 404 for a foreign device and 204 for its own',
    covers: ['DELETE /v1/devices/:id'],
    async run({ h, a, b }) {
      const foreign = await h.app.inject({
        method: 'DELETE',
        url: `/v1/devices/${b.clientDeviceId}`,
        headers: { authorization: `Bearer ${a.agentToken}` },
      });
      expect(foreign.statusCode).toBe(404);
      expect(foreign.statusCode).not.toBe(403);

      const own = await h.app.inject({
        method: 'DELETE',
        url: `/v1/devices/${a.clientDeviceId}`,
        headers: { authorization: `Bearer ${a.agentToken}` },
      });
      expect(own.statusCode).toBe(204);

      const bList = await h.app.inject({
        method: 'GET',
        url: '/v1/devices',
        headers: { authorization: `Bearer ${b.agentToken}` },
      });
      expect((bList.json() as { devices: { id: string }[] }).devices.map((d) => d.id)).toContain(
        b.clientDeviceId,
      );
    },
  },
  {
    name: 'WS /v1/agent cannot relay to, or impersonate, another tenant',
    covers: ['GET /v1/agent'],
    async run({ a, b, wsUrl }) {
      const sockets: WsClient[] = [];
      try {
        const agentA = await openWs(`${wsUrl}/v1/agent`, a.agentToken);
        sockets.push(agentA);

        // Targeting a device id that exists, but in another tenant.
        agentA.send({ t: 'relay', to: b.clientDeviceId, payload: 'Y2lwaGVy' });
        expect(await agentA.next()).toMatchObject({ t: 'error', code: 'not_found' });

        // A's token on the agent endpoint authenticates as A's agent, never B's.
        agentA.send({ t: 'relay', to: a.clientDeviceId, payload: 'Y2lwaGVy' });
        expect(await agentA.next()).toMatchObject({ t: 'error', message: 'Peer is not connected' });

        await expect(openWs(`${wsUrl}/v1/agent`, `${b.accountId}.forged-secret`)).rejects.toThrow(/401/);
      } finally {
        for (const s of sockets) s.close();
      }
    },
  },
  {
    name: 'WS /v1/client cannot relay to another tenant, and relays within its own',
    covers: ['GET /v1/client'],
    async run({ a, b, wsUrl }) {
      const sockets: WsClient[] = [];
      try {
        const clientA = await openWs(`${wsUrl}/v1/client`, a.clientToken);
        const agentA = await openWs(`${wsUrl}/v1/agent`, a.agentToken);
        sockets.push(clientA, agentA);

        clientA.send({ t: 'relay', to: b.agentDeviceId, payload: 'Y2lwaGVy' });
        expect(await clientA.next()).toMatchObject({ t: 'error', code: 'not_found' });

        clientA.send({ t: 'relay', to: a.agentDeviceId, payload: 'Y2lwaGVy' });
        expect(await agentA.next()).toEqual({
          t: 'relay',
          from: a.clientDeviceId,
          payload: 'Y2lwaGVy',
        });

        // A client token presented on the agent endpoint is rejected outright.
        const wrongKind = await openWs(`${wsUrl}/v1/agent`, a.clientToken);
        sockets.push(wrongKind);
        expect(await wrongKind.closed()).toBe(4003);
      } finally {
        for (const s of sockets) s.close();
      }
    },
  },
];

describe('cross-tenant isolation', () => {
  let h: Harness;
  let wsUrl: string;

  beforeAll(async () => {
    h = await startHarness();
    const address = await h.app.listen({ host: '127.0.0.1', port: 0 });
    wsUrl = address.replace('http://', 'ws://');
  });

  afterAll(async () => {
    await h.close();
  });

  for (const testCase of cases) {
    it(testCase.name, async () => {
      await truncateAll();
      const a = await createAccount(h, 'alpha');
      const b = await createAccount(h, 'bravo');
      expect(a.accountId).not.toBe(b.accountId);
      await testCase.run({ h, a, b, wsUrl });
    });
  }

  it('every registered route is either covered by a tenant case or explicitly exempt', () => {
    const registered = new Set(
      h.routes
        // Fastify auto-registers HEAD alongside GET; it shares the GET handler
        // and therefore the GET case's tenant assertions.
        .filter((r: RouteInfo) => r.method !== 'HEAD')
        .map((r: RouteInfo) => `${r.method} ${r.url}`),
    );
    const covered = new Set(cases.flatMap((c) => c.covers));

    for (const key of Object.keys(EXEMPT)) covered.add(key);

    const untested = [...registered].filter((r) => !covered.has(r));
    const stale = [...covered].filter((r) => !registered.has(r));

    expect(untested, 'routes with no cross-tenant assertion').toEqual([]);
    expect(stale, 'tenant assertions naming routes that no longer exist').toEqual([]);

    const enforced = [...registered].filter((r) => !(r in EXEMPT));
    // Recorded for the gate report: the endpoint count criterion 5 asks for.
    expect(enforced).toHaveLength(8);
  });
});

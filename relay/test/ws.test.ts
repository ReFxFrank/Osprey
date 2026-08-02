import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createAccount, startHarness, type Account, type Harness } from './support/harness.ts';
import { truncateAll } from './support/pg.ts';
import { openWs, type WsClient } from './support/ws.ts';

describe('websocket attach and relay', () => {
  let h: Harness;
  let wsUrl: string;
  let account: Account;
  const open: WsClient[] = [];

  beforeAll(async () => {
    h = await startHarness();
    const address = await h.app.listen({ host: '127.0.0.1', port: 0 });
    wsUrl = address.replace('http://', 'ws://');
  });

  afterAll(async () => {
    await h.close();
  });

  beforeEach(async () => {
    for (const s of open.splice(0)) s.close();
    await truncateAll();
    account = await createAccount(h, 'ws');
  });

  async function connect(path: '/v1/agent' | '/v1/client', token: string): Promise<WsClient> {
    const client = await openWs(`${wsUrl}${path}`, token);
    open.push(client);
    return client;
  }

  it('rejects an unauthenticated upgrade with 401', async () => {
    await expect(openWs(`${wsUrl}/v1/agent`, 'garbage')).rejects.toThrow(/401/);
  });

  it('answers ping with pong', async () => {
    const agent = await connect('/v1/agent', account.agentToken);
    agent.send({ t: 'ping' });
    expect(await agent.next()).toEqual({ t: 'pong' });
  });

  it('relays an opaque payload between paired devices in both directions', async () => {
    const agent = await connect('/v1/agent', account.agentToken);
    const client = await connect('/v1/client', account.clientToken);

    client.send({ t: 'relay', to: account.agentDeviceId, payload: 'dG8tYWdlbnQ=' });
    expect(await agent.next()).toEqual({
      t: 'relay',
      from: account.clientDeviceId,
      payload: 'dG8tYWdlbnQ=',
    });

    agent.send({ t: 'relay', to: account.clientDeviceId, payload: 'dG8tY2xpZW50' });
    expect(await client.next()).toEqual({
      t: 'relay',
      from: account.agentDeviceId,
      payload: 'dG8tY2xpZW50',
    });
  });

  it('answers a malformed frame with an error and keeps the socket open', async () => {
    const agent = await connect('/v1/agent', account.agentToken);
    agent.send('this is not a frame');
    expect(await agent.next()).toMatchObject({ t: 'error', code: 'bad_request' });

    agent.send({ t: 'ping' });
    expect(await agent.next()).toEqual({ t: 'pong' });
  });

  it('stops relaying the moment the pairing is revoked', async () => {
    const agent = await connect('/v1/agent', account.agentToken);
    const client = await connect('/v1/client', account.clientToken);

    client.send({ t: 'relay', to: account.agentDeviceId, payload: 'YmVmb3Jl' });
    expect(await agent.next()).toMatchObject({ t: 'relay', payload: 'YmVmb3Jl' });

    const revoked = await h.app.inject({
      method: 'DELETE',
      url: `/v1/pairings/${account.pairingId}`,
      headers: { authorization: `Bearer ${account.clientToken}` },
    });
    expect(revoked.statusCode).toBe(204);

    client.send({ t: 'relay', to: account.agentDeviceId, payload: 'YWZ0ZXI=' });
    expect(await client.next()).toMatchObject({ t: 'error', code: 'not_found' });
  });

  it('drops a live socket when its device is revoked', async () => {
    const client = await connect('/v1/client', account.clientToken);
    const res = await h.app.inject({
      method: 'DELETE',
      url: `/v1/devices/${account.clientDeviceId}`,
      headers: { authorization: `Bearer ${account.agentToken}` },
    });
    expect(res.statusCode).toBe(204);
    expect(await client.closed()).toBe(4001);
  });

  it('supersedes an earlier socket for the same device', async () => {
    const first = await connect('/v1/agent', account.agentToken);
    await connect('/v1/agent', account.agentToken);
    expect(await first.closed()).toBe(4000);
  });
});

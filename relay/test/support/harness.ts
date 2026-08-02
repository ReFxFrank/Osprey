import { createHash, randomBytes } from 'node:crypto';
import { buildApp, quotaDefaultsFrom, type RelayApp } from '../../src/app.ts';
import { loadConfig, type RelayConfig } from '../../src/config.ts';
import { createRepoFromUrl, type RepoHandle } from '../../src/repo/index.ts';
import { appUrl } from './pg.ts';

export const TEST_ENROLLMENT_SECRET = 'test-enrollment-secret-0123456789abcdef';

export interface Harness extends RelayApp {
  readonly config: RelayConfig;
  close(): Promise<void>;
}

export async function startHarness(overrides: Record<string, string> = {}): Promise<Harness> {
  const config = loadConfig({
    DATABASE_URL: appUrl,
    OSPREY_ENROLLMENT_SECRET: TEST_ENROLLMENT_SECRET,
    OSPREY_LOG_LEVEL: 'silent',
    OSPREY_ENROLL_RATE_LIMIT_PER_HOUR: '1000',
    ...overrides,
  } as NodeJS.ProcessEnv);

  const handle: RepoHandle = createRepoFromUrl(config.databaseUrl, quotaDefaultsFrom(config), 5);
  const relay = await buildApp(config, handle.repo);

  return {
    ...relay,
    config,
    close: async () => {
      await relay.app.close();
      await handle.close();
    },
  };
}

/** Key material shaped like the real thing; the relay only ever stores and echoes it. */
export function fakePeerMaterial(kind: 'agent' | 'client', label: string) {
  return {
    displayName: label,
    identityPublicKey: randomBytes(32).toString('base64url'),
    identityAlgorithm: kind === 'agent' ? ('ed25519' as const) : ('p256' as const),
    noiseStaticPublicKey: randomBytes(32).toString('base64url'),
    noiseStaticSignature: randomBytes(64).toString('base64url'),
  };
}

export interface Account {
  readonly accountId: string;
  readonly agentDeviceId: string;
  readonly agentToken: string;
  clientDeviceId: string;
  clientToken: string;
  pairingId: string;
}

export function pairingSecret(): { secret: string; routingId: string } {
  const secret = randomBytes(32).toString('base64url');
  return { secret, routingId: createHash('sha256').update(secret, 'utf8').digest('hex') };
}

/** Enrolls an agent, issues a pairing token, and redeems it — one complete tenant. */
export async function createAccount(h: Harness, label: string): Promise<Account> {
  const enroll = await h.app.inject({
    method: 'POST',
    url: '/v1/agents/enroll',
    payload: { enrollmentSecret: TEST_ENROLLMENT_SECRET, ...fakePeerMaterial('agent', `${label}-agent`) },
  });
  if (enroll.statusCode !== 201) throw new Error(`enroll failed: ${enroll.statusCode} ${enroll.body}`);
  const enrolled = enroll.json() as { accountId: string; deviceId: string; deviceToken: string };

  const { routingId } = pairingSecret();
  const issued = await h.app.inject({
    method: 'POST',
    url: '/v1/pairing/tokens',
    headers: { authorization: `Bearer ${enrolled.deviceToken}` },
    payload: { routingId },
  });
  if (issued.statusCode !== 201) throw new Error(`token issue failed: ${issued.statusCode} ${issued.body}`);

  const redeemed = await h.app.inject({
    method: 'POST',
    url: '/v1/pairing/redeem',
    payload: { accountId: enrolled.accountId, routingId, ...fakePeerMaterial('client', `${label}-phone`) },
  });
  if (redeemed.statusCode !== 201) throw new Error(`redeem failed: ${redeemed.statusCode} ${redeemed.body}`);
  const pairing = redeemed.json() as { pairingId: string; deviceId: string; deviceToken: string };

  return {
    accountId: enrolled.accountId,
    agentDeviceId: enrolled.deviceId,
    agentToken: enrolled.deviceToken,
    clientDeviceId: pairing.deviceId,
    clientToken: pairing.deviceToken,
    pairingId: pairing.pairingId,
  };
}

/**
 * Configuration is read once, at startup, and fails loudly. A relay that boots
 * with a missing enrollment secret would expose the unbounded account-minting
 * surface described in execution plan item 11, so there is no default for it.
 */

export interface RelayConfig {
  readonly host: string;
  readonly port: number;
  readonly databaseUrl: string;
  /** Deploy-time shared secret required by POST /v1/agents/enroll. */
  readonly enrollmentSecret: string;
  /** Global (not per-account) enrollment attempts allowed per source IP per hour. */
  readonly enrollRateLimitPerHour: number;
  /**
   * Redeem attempts allowed per source IP, and failed redeem attempts allowed
   * per target account, inside a one-minute window. `POST /v1/pairing/redeem`
   * is unauthenticated and names its tenant in the body, so without this an
   * anonymous caller can drive unbounded per-tenant database work.
   *
   * The window is a minute rather than an hour because the per-account half is
   * reachable by a third party: a flood against one tenant costs that tenant a
   * minute of pairing availability, not an hour.
   */
  readonly redeemRateLimitPerMinute: number;
  readonly pairingTokenTtlSeconds: number;
  readonly defaultMaxDevices: number;
  readonly defaultMaxPairingAttemptsPerHour: number;
  readonly defaultTurnBytesPerMonth: bigint;
  readonly logLevel: string;
}

class ConfigError extends Error {}

function required(env: NodeJS.ProcessEnv, key: string): string {
  const value = env[key];
  if (value === undefined || value.trim() === '') {
    throw new ConfigError(`Missing required environment variable ${key}`);
  }
  return value;
}

function intWithDefault(env: NodeJS.ProcessEnv, key: string, fallback: number): number {
  const raw = env[key];
  if (raw === undefined || raw.trim() === '') return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new ConfigError(`Environment variable ${key} must be a positive integer, got ${raw}`);
  }
  return parsed;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): RelayConfig {
  const enrollmentSecret = required(env, 'OSPREY_ENROLLMENT_SECRET');
  if (enrollmentSecret.length < 32) {
    throw new ConfigError(
      'OSPREY_ENROLLMENT_SECRET must be at least 32 characters; it is the only thing between a public relay and unbounded account creation',
    );
  }
  return {
    host: env.OSPREY_HOST ?? '0.0.0.0',
    port: intWithDefault(env, 'OSPREY_PORT', 8080),
    databaseUrl: required(env, 'DATABASE_URL'),
    enrollmentSecret,
    enrollRateLimitPerHour: intWithDefault(env, 'OSPREY_ENROLL_RATE_LIMIT_PER_HOUR', 10),
    redeemRateLimitPerMinute: intWithDefault(env, 'OSPREY_REDEEM_RATE_LIMIT_PER_MINUTE', 20),
    // Brief §6.1 fixes the QR validity window at 120 seconds.
    pairingTokenTtlSeconds: intWithDefault(env, 'OSPREY_PAIRING_TOKEN_TTL_SECONDS', 120),
    defaultMaxDevices: intWithDefault(env, 'OSPREY_DEFAULT_MAX_DEVICES', 25),
    defaultMaxPairingAttemptsPerHour: intWithDefault(
      env,
      'OSPREY_DEFAULT_MAX_PAIRING_ATTEMPTS_PER_HOUR',
      20,
    ),
    defaultTurnBytesPerMonth: BigInt(env.OSPREY_DEFAULT_TURN_BYTES_PER_MONTH ?? '53687091200'),
    logLevel: env.OSPREY_LOG_LEVEL ?? 'info',
  };
}

export { ConfigError };

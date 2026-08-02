import { sql } from 'drizzle-orm';
import {
  bigint,
  boolean,
  index,
  integer,
  jsonb,
  pgPolicy,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';

/**
 * Brief §0.1 / §6.7: every table carries `account_id` and no query is global.
 * The repository layer (`src/repo/`) is the primary enforcement — it filters on
 * `accountId` in every statement. The RLS policies below are the backstop, and
 * they only bite because the runtime connects as a non-owner role without
 * BYPASSRLS (see `sql/roles.sql` and `sql/grants.sql`); an owner connection
 * would silently ignore every policy here, which is the trap the execution plan
 * calls out in item 12.
 *
 * The `nullif(…, '')` is load-bearing, not defensive noise. `SET LOCAL` reverts
 * the GUC on commit to the *session* value, which for a custom variable that was
 * never set at session scope is the empty string rather than unset. Without the
 * nullif, the first query on a pooled connection after any tenant transaction
 * would evaluate `''::uuid` and raise `invalid input syntax for type uuid`
 * instead of returning zero rows.
 */
export const APP_ROLE = 'osprey_app';

const tenantPolicy = (table: string) =>
  pgPolicy(`${table}_tenant_isolation`, {
    for: 'all',
    to: APP_ROLE,
    using: sql`account_id = nullif(current_setting('app.account_id', true), '')::uuid`,
    withCheck: sql`account_id = nullif(current_setting('app.account_id', true), '')::uuid`,
  });

export const accounts = pgTable(
  'accounts',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    // Free-text operator label. Attacker-supplied at enrollment; never an identifier.
    displayName: text('display_name'),
  },
  () => [
    // `accounts` is keyed by `id`, not `account_id`, so the shared helper does not apply.
    pgPolicy('accounts_tenant_isolation', {
      for: 'all',
      to: APP_ROLE,
      using: sql`id = nullif(current_setting('app.account_id', true), '')::uuid`,
      withCheck: sql`id = nullif(current_setting('app.account_id', true), '')::uuid`,
    }),
  ],
).enableRLS();

/**
 * Execution plan item 9: the phone is a first-class device row, distinguished
 * by `kind`, so `push_tokens` (P8) can carry a real foreign key to it and so a
 * pairing is a join between two rows in one table rather than two registries.
 */
export const devices = pgTable(
  'devices',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    accountId: uuid('account_id')
      .notNull()
      .references(() => accounts.id, { onDelete: 'cascade' }),
    kind: text('kind', { enum: ['agent', 'client'] }).notNull(),
    displayName: text('display_name').notNull(),
    /**
     * Hardware-backed identity public key as pinned end-to-end (Ed25519 for an
     * agent, P-256 SEC1 for iOS). Stored for the device list only: the relay is
     * untrusted, so a peer MUST pin from the Noise channel, never from here.
     */
    identityPublicKey: text('identity_public_key').notNull(),
    identityAlgorithm: text('identity_algorithm', { enum: ['ed25519', 'p256'] }).notNull(),
    /**
     * Current X25519 Noise static and the cross-signature binding it to
     * `identity_public_key` (execution plan item 1). Rotatable by re-signing,
     * which is why `pairings` snapshots what was actually pinned rather than
     * pointing here.
     */
    noiseStaticPublicKey: text('noise_static_public_key').notNull(),
    noiseStaticSignature: text('noise_static_signature').notNull(),
    /**
     * SHA-256 of the bearer token this device presents to the relay. Relay-plane
     * authentication only — it gates routing and device listing, never anything
     * end-to-end. The plaintext token is returned once, at issue, and never stored.
     */
    authTokenHash: text('auth_token_hash').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp('last_seen_at', { withTimezone: true }),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
  },
  (t) => [
    index('devices_account_idx').on(t.accountId),
    uniqueIndex('devices_auth_token_hash_key').on(t.authTokenHash),
    tenantPolicy('devices'),
  ],
).enableRLS();

/**
 * The pairing join. Unpair is a soft revoke (`revoked_at`) so the audit history
 * of who was ever allowed to control this host survives the revocation.
 */
export const pairings = pgTable(
  'pairings',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    accountId: uuid('account_id')
      .notNull()
      .references(() => accounts.id, { onDelete: 'cascade' }),
    agentDeviceId: uuid('agent_device_id')
      .notNull()
      .references(() => devices.id, { onDelete: 'cascade' }),
    clientDeviceId: uuid('client_device_id')
      .notNull()
      .references(() => devices.id, { onDelete: 'cascade' }),
    // Both sides' pinned X25519 Noise statics and the cross-signatures binding
    // each static to that side's identity key (execution plan item 1).
    agentNoiseStaticPublicKey: text('agent_noise_static_public_key').notNull(),
    agentNoiseStaticSignature: text('agent_noise_static_signature').notNull(),
    clientNoiseStaticPublicKey: text('client_noise_static_public_key').notNull(),
    clientNoiseStaticSignature: text('client_noise_static_signature').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    revokedBy: text('revoked_by', { enum: ['agent', 'client'] }),
  },
  (t) => [
    index('pairings_account_idx').on(t.accountId),
    index('pairings_agent_idx').on(t.accountId, t.agentDeviceId),
    index('pairings_client_idx').on(t.accountId, t.clientDeviceId),
    tenantPolicy('pairings'),
  ],
).enableRLS();

/**
 * Execution plan item 9 / §2 #2. Three invariants the brief omitted:
 *  - only `routing_id = SHA-256(pairing_secret)` is stored, never the secret,
 *    so a hostile relay operator cannot complete the Noise_IKpsk2 handshake;
 *  - `account_id` + `agent_device_id` are on the row, so a relay cannot route a
 *    phone's pairing into a different tenant's pending pairing;
 *  - redemption is a single atomic UPDATE (see `repo/pairingTokens.ts`).
 */
export const pairingTokens = pgTable(
  'pairing_tokens',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    accountId: uuid('account_id')
      .notNull()
      .references(() => accounts.id, { onDelete: 'cascade' }),
    agentDeviceId: uuid('agent_device_id')
      .notNull()
      .references(() => devices.id, { onDelete: 'cascade' }),
    routingId: text('routing_id').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    used: boolean('used').notNull().default(false),
    usedAt: timestamp('used_at', { withTimezone: true }),
  },
  (t) => [
    // Global uniqueness on the rendezvous id: two tenants must never be able to
    // hold the same routing_id, or redemption becomes ambiguous.
    uniqueIndex('pairing_tokens_routing_id_key').on(t.routingId),
    index('pairing_tokens_account_created_idx').on(t.accountId, t.createdAt),
    tenantPolicy('pairing_tokens'),
  ],
).enableRLS();

/** P8 registers rows here; P0 only creates the table and its FK to the client device. */
export const pushTokens = pgTable(
  'push_tokens',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    accountId: uuid('account_id')
      .notNull()
      .references(() => accounts.id, { onDelete: 'cascade' }),
    deviceId: uuid('device_id')
      .notNull()
      .references(() => devices.id, { onDelete: 'cascade' }),
    apnsToken: text('apns_token').notNull(),
    environment: text('environment', { enum: ['sandbox', 'production'] }).notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('push_tokens_device_key').on(t.accountId, t.deviceId),
    tenantPolicy('push_tokens'),
  ],
).enableRLS();

/** Brief §0.1: per-account quotas exist and are enforced from P0. */
export const quotas = pgTable(
  'quotas',
  {
    accountId: uuid('account_id')
      .primaryKey()
      .references(() => accounts.id, { onDelete: 'cascade' }),
    maxDevices: integer('max_devices').notNull(),
    maxPairingAttemptsPerHour: integer('max_pairing_attempts_per_hour').notNull(),
    // P5 enforces this; P0 stores the budget so the column does not have to be
    // added under a live pairing table later.
    turnBytesPerMonth: bigint('turn_bytes_per_month', { mode: 'bigint' }).notNull(),
  },
  () => [
    pgPolicy('quotas_tenant_isolation', {
      for: 'all',
      to: APP_ROLE,
      using: sql`account_id = nullif(current_setting('app.account_id', true), '')::uuid`,
      withCheck: sql`account_id = nullif(current_setting('app.account_id', true), '')::uuid`,
    }),
  ],
).enableRLS();

/**
 * Relay-side audit (brief §6.4 is the agent-side log; this is its relay
 * counterpart). Execution plan item 14: pairing success, pairing failure and
 * unpair are the highest-privilege events in the system and are recorded here.
 */
export const auditRelay = pgTable(
  'audit_relay',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    accountId: uuid('account_id')
      .notNull()
      .references(() => accounts.id, { onDelete: 'cascade' }),
    deviceId: uuid('device_id').references(() => devices.id, { onDelete: 'set null' }),
    event: text('event').notNull(),
    detail: jsonb('detail').notNull(),
    remoteIp: text('remote_ip'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index('audit_relay_account_created_idx').on(t.accountId, t.createdAt),
    tenantPolicy('audit_relay'),
  ],
).enableRLS();

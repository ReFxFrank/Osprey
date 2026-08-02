/**
 * Request schemas are Fastify/ajv JSON Schema rather than a validation library:
 * Fastify already compiles them, so the relay gains no dependency, and an
 * invalid body is rejected before any handler code — and therefore before any
 * database statement — runs.
 */

const BASE64: object = { type: 'string', minLength: 16, maxLength: 512, pattern: '^[A-Za-z0-9+/=_-]+$' };
const UUID: object = { type: 'string', format: 'uuid' };
const HEX_SHA256: object = { type: 'string', pattern: '^[0-9a-f]{64}$' };
const DISPLAY_NAME: object = { type: 'string', minLength: 1, maxLength: 128 };

/** The key material every device presents, agent or client. */
const peerMaterial = {
  displayName: DISPLAY_NAME,
  identityPublicKey: BASE64,
  identityAlgorithm: { type: 'string', enum: ['ed25519', 'p256'] },
  noiseStaticPublicKey: BASE64,
  noiseStaticSignature: BASE64,
};

const peerMaterialRequired = [
  'displayName',
  'identityPublicKey',
  'identityAlgorithm',
  'noiseStaticPublicKey',
  'noiseStaticSignature',
];

export const enrollBodySchema = {
  type: 'object',
  additionalProperties: false,
  required: ['enrollmentSecret', ...peerMaterialRequired],
  properties: {
    enrollmentSecret: { type: 'string', minLength: 32, maxLength: 512 },
    ...peerMaterial,
  },
} as const;

export const issueTokenBodySchema = {
  type: 'object',
  additionalProperties: false,
  required: ['routingId'],
  properties: {
    // SHA-256 of the pairing secret. The secret itself must never appear here.
    routingId: HEX_SHA256,
  },
} as const;

export const redeemBodySchema = {
  type: 'object',
  additionalProperties: false,
  required: ['accountId', 'routingId', ...peerMaterialRequired],
  properties: {
    // Carried in the scanned QR. Binds redemption to one tenant (plan item 9b).
    accountId: UUID,
    routingId: HEX_SHA256,
    ...peerMaterial,
  },
} as const;

export const idParamSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['id'],
  properties: { id: UUID },
} as const;

export interface PeerMaterialBody {
  displayName: string;
  identityPublicKey: string;
  identityAlgorithm: 'ed25519' | 'p256';
  noiseStaticPublicKey: string;
  noiseStaticSignature: string;
}

export interface EnrollBody extends PeerMaterialBody {
  enrollmentSecret: string;
}

export interface RedeemBody extends PeerMaterialBody {
  accountId: string;
  routingId: string;
}

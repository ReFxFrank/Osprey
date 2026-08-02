import { isUuid } from '../repo/index.ts';

/**
 * The relay's view of a frame is deliberately thin: a destination device id and
 * an opaque payload. `payload` is Noise ciphertext (brief §6.2) — the relay
 * cannot read it, and nothing here should ever grow a field that requires it to.
 */
export type ClientFrame =
  | { readonly t: 'relay'; readonly to: string; readonly payload: string }
  | { readonly t: 'ping' };

export type ParseResult =
  | { readonly ok: true; readonly frame: ClientFrame }
  | { readonly ok: false; readonly message: string };

/** Bounds the per-frame allocation a peer can force before it is authorised to relay anything. */
export const MAX_FRAME_BYTES = 256 * 1024;

/**
 * Total-function parser. Every malformed input returns a value; nothing here
 * throws, because a remote peer chooses this input and an exception would take
 * the connection handler with it (CLAUDE.md rule 2).
 */
export function parseClientFrame(raw: unknown): ParseResult {
  let text: string;
  if (typeof raw === 'string') {
    text = raw;
  } else if (raw instanceof Buffer || raw instanceof Uint8Array) {
    if (raw.byteLength > MAX_FRAME_BYTES) return { ok: false, message: 'frame too large' };
    text = Buffer.from(raw).toString('utf8');
  } else {
    return { ok: false, message: 'unsupported frame encoding' };
  }
  if (text.length > MAX_FRAME_BYTES) return { ok: false, message: 'frame too large' };

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, message: 'frame is not valid JSON' };
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { ok: false, message: 'frame must be a JSON object' };
  }
  const obj = parsed as Record<string, unknown>;

  if (obj.t === 'ping') return { ok: true, frame: { t: 'ping' } };

  if (obj.t !== 'relay') return { ok: false, message: 'unknown frame type' };
  if (!isUuid(obj.to)) return { ok: false, message: 'relay.to must be a device uuid' };
  if (typeof obj.payload !== 'string' || obj.payload.length === 0) {
    return { ok: false, message: 'relay.payload must be a non-empty string' };
  }
  return { ok: true, frame: { t: 'relay', to: obj.to, payload: obj.payload } };
}

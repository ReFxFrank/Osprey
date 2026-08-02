import { describe, expect, it } from 'vitest';
import { MAX_FRAME_BYTES, parseClientFrame } from '../src/ws/frames.ts';

/**
 * CLAUDE.md rule 2: a malformed network message must never panic. The parser is
 * a total function, so this suite is mostly a fuzz over the shapes a hostile
 * peer can send — the assertion in every case is "returned a value, did not
 * throw".
 */
describe('websocket frame parsing', () => {
  const hostileInputs: unknown[] = [
    '',
    'null',
    'undefined',
    '{',
    '[]',
    '[1,2,3]',
    '"a string"',
    '123',
    'true',
    '{"t":"relay"}',
    '{"t":"relay","to":"not-a-uuid","payload":"x"}',
    '{"t":"relay","to":"00000000-0000-0000-0000-000000000000"}',
    '{"t":"relay","to":"00000000-0000-0000-0000-000000000000","payload":""}',
    '{"t":"relay","to":"00000000-0000-0000-0000-000000000000","payload":123}',
    '{"t":"relay","to":null,"payload":null}',
    '{"t":"unknown"}',
    '{"t":null}',
    '{"__proto__":{"admin":true},"t":"ping"}',
    '{"t":"ping","extra":{"deeply":{"nested":[1,2,3]}}}',
    Buffer.from('not json at all'),
    Buffer.from([0xff, 0xfe, 0x00, 0x01]),
    new Uint8Array([0x7b, 0x22]),
    42,
    null,
    undefined,
    { t: 'relay' },
    Symbol('nope'),
  ];

  it('never throws on any hostile input', () => {
    for (const input of hostileInputs) {
      expect(() => parseClientFrame(input)).not.toThrow();
    }
  });

  it('rejects every hostile input except the two that are actually valid', () => {
    const accepted = hostileInputs.filter((i) => parseClientFrame(i).ok);
    expect(accepted).toEqual(['{"__proto__":{"admin":true},"t":"ping"}', '{"t":"ping","extra":{"deeply":{"nested":[1,2,3]}}}']);
  });

  it('does not let a __proto__ key in a frame pollute Object.prototype', () => {
    parseClientFrame('{"__proto__":{"polluted":true},"t":"ping"}');
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('accepts a well-formed relay frame', () => {
    const result = parseClientFrame(
      JSON.stringify({ t: 'relay', to: '2f1c0e26-0d5f-4d3a-9d0f-3a5b1a2c9e77', payload: 'Y2lwaGVy' }),
    );
    expect(result).toEqual({
      ok: true,
      frame: { t: 'relay', to: '2f1c0e26-0d5f-4d3a-9d0f-3a5b1a2c9e77', payload: 'Y2lwaGVy' },
    });
  });

  it('rejects an oversized frame before parsing it', () => {
    const oversized = Buffer.alloc(MAX_FRAME_BYTES + 1, 0x61);
    const result = parseClientFrame(oversized);
    expect(result).toEqual({ ok: false, message: 'frame too large' });
  });
});

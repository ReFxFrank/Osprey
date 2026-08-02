// Emits the Swift half of the protocol into ios/Osprey/Osprey/Generated/.

import { camel, docComment, swiftIdent } from './names.ts';
import type { EnumDef, EnumValueDef, FieldDef, ResolvedType, Schema } from './schema.ts';
import type { EmittedFile } from './emit-rust.ts';

const HEADER = [
  '// DO NOT EDIT — generated from proto/messages.toml by proto/generate.ts.',
  '// Run `pnpm generate` in proto/ after changing the registry.',
  '',
  'import Foundation',
  '',
];

const SCALAR_MAP: Record<string, string> = {
  string: 'String',
  bool: 'Bool',
  u16: 'UInt16',
  u32: 'UInt32',
  u64: 'UInt64',
  i32: 'Int32',
  i64: 'Int64',
  f64: 'Double',
};

function swiftType(t: ResolvedType): string {
  let base: string;
  switch (t.kind) {
    case 'scalar': {
      const mapped = SCALAR_MAP[t.name];
      if (mapped === undefined) throw new Error(`no Swift mapping for scalar \`${t.name}\``);
      base = mapped;
      break;
    }
    case 'uuid':
      base = 'UUID';
      break;
    case 'bytes':
      base = 'Data';
      break;
    case 'messageType':
    case 'enum':
      base = t.name;
      break;
    case 'json':
      throw new Error('the `json` type has no Swift mapping; the envelope body is generic');
  }
  return t.array ? `[${base}]` : base;
}

interface SwiftProperty {
  wire: string;
  ident: string;
  type: string;
  doc: string;
}

/** Swift case spelling for a wire name, backticked when it is a keyword. */
function swiftCase(wire: string): string {
  return swiftIdent(camel(wire));
}

function toProperty(field: FieldDef): SwiftProperty {
  const type = field.optional ? `${swiftType(field.type)}?` : swiftType(field.type);
  return { wire: field.name, ident: swiftCase(field.name), type, doc: field.doc };
}

/**
 * Emits a struct with an explicit public memberwise initialiser, plus explicit
 * CodingKeys when it is `Codable`. Both are spelled out rather than left to
 * synthesis: the initialiser because synthesis is internal-only, the keys
 * because the wire names are snake_case and the properties are not.
 */
function emitStruct(
  name: string,
  conformance: string,
  doc: string[],
  properties: SwiftProperty[],
  extraMembers: string[],
  codable: boolean,
  out: string[],
): void {
  out.push(...doc);
  out.push(`public struct ${name}: ${conformance} {`);
  out.push(...extraMembers);
  for (const p of properties) {
    out.push(...docComment(p.doc, '    '));
    out.push(`    public var ${p.ident}: ${p.type}`);
  }
  out.push('');
  const args = properties.map((p) => `${p.ident}: ${p.type}`).join(', ');
  out.push(`    public init(${args}) {`);
  for (const p of properties) {
    out.push(`        self.${p.ident} = ${p.ident}`);
  }
  out.push('    }');
  if (codable) {
    out.push('');
    out.push('    private enum CodingKeys: String, CodingKey {');
    for (const p of properties) {
      out.push(`        case ${p.ident} = "${p.wire}"`);
    }
    out.push('    }');
  }
  out.push('}');
  out.push('');
}

function emitOpenEnum(name: string, doc: string, values: EnumValueDef[], out: string[]): void {
  out.push(...docComment(doc));
  out.push('///');
  out.push('/// Unrecognised wire values decode to `.unknown`, preserving the original string.');
  out.push(`public enum ${name}: Codable, Hashable, Sendable {`);
  for (const v of values) {
    out.push(...docComment(v.doc, '    '));
    out.push(`    case ${swiftCase(v.wire)}`);
  }
  out.push('    /// A value this build does not know, kept verbatim so it can be logged or relayed.');
  out.push('    case unknown(String)');
  out.push('');
  out.push('    /// Wire spelling of this value.');
  out.push('    public var wireValue: String {');
  out.push('        switch self {');
  for (const v of values) {
    out.push(`        case .${swiftCase(v.wire)}: return "${v.wire}"`);
  }
  out.push('        case .unknown(let raw): return raw');
  out.push('        }');
  out.push('    }');
  out.push('');
  out.push('    public init(wireValue: String) {');
  out.push('        switch wireValue {');
  for (const v of values) {
    out.push(`        case "${v.wire}": self = .${swiftCase(v.wire)}`);
  }
  out.push('        default: self = .unknown(wireValue)');
  out.push('        }');
  out.push('    }');
  out.push('');
  out.push('    public init(from decoder: any Decoder) throws {');
  out.push('        let raw = try decoder.singleValueContainer().decode(String.self)');
  out.push('        self.init(wireValue: raw)');
  out.push('    }');
  out.push('');
  out.push('    public func encode(to encoder: any Encoder) throws {');
  out.push('        var container = encoder.singleValueContainer()');
  out.push('        try container.encode(wireValue)');
  out.push('    }');
  out.push('}');
  out.push('');
}

function emitEnums(schema: Schema): EmittedFile {
  const out = [...HEADER];
  for (const e of schema.enums as EnumDef[]) {
    emitOpenEnum(e.name, e.doc, e.values, out);
  }
  emitOpenEnum(
    'Capability',
    "A message group a peer implements. Negotiated in `hello`/`hello.ok`; the\neffective set for a session is the intersection of both peers' sets.",
    schema.capabilities.map((g) => ({ wire: g.name, doc: g.doc })),
    out,
  );
  out.push('/// Which data channel a message must travel on (brief §5.3).');
  out.push('public enum Channel: Hashable, Sendable {');
  out.push('    /// Reliable and ordered. A dropped keystroke is unacceptable.');
  out.push('    case reliable');
  out.push('    /// Unordered with `maxRetransmits: 0`. A dropped mouse-move is invisible.');
  out.push('    case unreliable');
  out.push('}');
  return { name: 'Enums.swift', contents: `${out.join('\n')}\n` };
}

function caseList(cases: string[], indent: string): string {
  return cases.map((c) => `.${swiftIdent(c)}`).join(`,\n${indent}     `);
}

function emitMessageType(schema: Schema): EmittedFile {
  const out = [...HEADER];
  out.push('/// Every message type the protocol reserves.');
  out.push('///');
  out.push('/// Closed on purpose: an unrecognised `t` cannot be routed, so decoding one is');
  out.push('/// an error rather than something to ignore. Contrast the value enums, which');
  out.push('/// are open. Types whose body schema is not yet designed are still listed here');
  out.push('/// so the registry stays the single source of truth for the wire.');
  out.push('public enum MessageType: String, Codable, Hashable, Sendable, CaseIterable {');
  for (const entry of schema.registry) {
    out.push(`    case ${swiftIdent(entry.swiftCase)} = "${entry.wire}"`);
  }
  out.push('');
  out.push('    /// Capability that must be negotiated before this type may be sent.');
  out.push('    ///');
  out.push('    /// `nil` means the type is mandatory for every peer.');
  out.push('    public var capability: Capability? {');
  out.push('        switch self {');
  for (const group of schema.groups) {
    const members = schema.registry.filter((e) => e.group.name === group.name);
    if (members.length === 0) continue;
    out.push(`        case ${caseList(members.map((e) => e.swiftCase), '        ')}:`);
    out.push(`            return ${group.capability ? `.${swiftCase(group.name)}` : 'nil'}`);
  }
  out.push('        }');
  out.push('    }');
  out.push('');
  out.push('    /// Data channel this type must travel on (brief §5.3).');
  out.push('    public var channel: Channel {');
  const unreliable = schema.registry.filter((e) => e.unreliable);
  if (unreliable.length === 0) {
    out.push('        .reliable');
  } else {
    out.push('        switch self {');
    out.push(`        case ${caseList(unreliable.map((e) => e.swiftCase), '        ')}:`);
    out.push('            return .unreliable');
    out.push('        default:');
    out.push('            return .reliable');
    out.push('        }');
  }
  out.push('    }');
  out.push('}');
  return { name: 'MessageType.swift', contents: `${out.join('\n')}\n` };
}

function emitBodies(schema: Schema): EmittedFile {
  const out = [...HEADER];
  out.push('/// A body schema that knows which registry type it belongs to.');
  out.push('public protocol OspreyMessageBody: Codable, Hashable, Sendable {');
  out.push('    static var messageType: MessageType { get }');
  out.push('}');
  out.push('');
  for (const m of schema.messages) {
    const doc = [...docComment(m.doc), `/// Wire type: \`${m.wire}\`.`];
    const extra = [`    public static let messageType: MessageType = .${camel(m.wire)}`, ''];
    emitStruct(m.swiftName, 'OspreyMessageBody', doc, m.fields.map(toProperty), extra, true, out);
  }
  return { name: 'Bodies.swift', contents: `${out.join('\n')}\n` };
}

function emitEnvelope(schema: Schema): EmittedFile {
  const out = [...HEADER];
  const bodyField = schema.envelopeFields.find((f) => f.type.kind === 'json');
  if (bodyField === undefined) throw new Error('envelope has no `json` body field');
  const headerFields = schema.envelopeFields.filter((f) => f.type.kind !== 'json');
  const headerProps = headerFields.map(toProperty);

  out.push('/// Failure modes of envelope decoding that `DecodingError` does not cover.');
  out.push('public enum OspreyProtocolError: Error, Hashable, Sendable {');
  out.push('    /// Peer offered an envelope version outside the supported range.');
  out.push('    case unsupportedVersion(found: UInt32, min: UInt32, max: UInt32)');
  out.push('    /// The message type is reserved but its body schema is not yet defined.');
  out.push('    case bodyDeferred(MessageType)');
  out.push('}');
  out.push('');
  emitStruct(
    'EnvelopeHeader',
    'Codable, Hashable, Sendable',
    [
      '/// The envelope fields that can be read before the body schema is known.',
      '///',
      '/// Decoding this from a full envelope ignores `body`, which is what makes the',
      '/// two-step decode possible.',
    ],
    headerProps,
    [],
    true,
    out,
  );

  out.push(...docComment(schema.envelopeDoc));
  out.push('public struct Envelope<Body: OspreyMessageBody>: Codable, Hashable, Sendable {');
  for (const p of headerProps) {
    out.push(...docComment(p.doc, '    '));
    out.push(`    public var ${p.ident}: ${p.type}`);
  }
  out.push(...docComment(bodyField.doc, '    '));
  out.push('    public var body: Body');
  out.push('');
  out.push('    public init(id: UUID = UUID(), ts: Int64, body: Body) {');
  out.push('        self.v = OspreyProtocol.protocolVersion');
  out.push('        self.id = id');
  out.push('        self.t = Body.messageType');
  out.push('        self.ts = ts');
  out.push('        self.body = body');
  out.push('    }');
  out.push('');
  out.push('    private enum CodingKeys: String, CodingKey {');
  for (const p of headerProps) {
    out.push(`        case ${p.ident} = "${p.wire}"`);
  }
  out.push('        case body = "body"');
  out.push('    }');
  out.push('}');
  out.push('');
  out.push('/// A decoded envelope body, one case per fully defined message type.');
  out.push('public enum MessageBody: Hashable, Sendable {');
  for (const m of schema.messages) {
    out.push(`    /// \`${m.wire}\``);
    out.push(`    case ${swiftCase(m.wire)}(${m.swiftName})`);
  }
  out.push('');
  out.push('    /// The registry type this body belongs to.');
  out.push('    public var messageType: MessageType {');
  out.push('        switch self {');
  for (const m of schema.messages) {
    out.push(`        case .${swiftCase(m.wire)}: return .${swiftCase(m.wire)}`);
  }
  out.push('        }');
  out.push('    }');
  out.push('}');
  out.push('');
  emitStruct(
    'DecodedEnvelope',
    'Hashable, Sendable',
    ['/// An envelope whose body has been resolved against its message type.'],
    [...headerProps, { wire: 'body', ident: 'body', type: 'MessageBody', doc: 'Decoded payload.' }],
    [],
    false,
    out,
  );

  out.push('/// Protocol constants and the encode/decode entry points.');
  out.push('public enum OspreyProtocol {');
  out.push('    /// Highest envelope version this build speaks.');
  out.push(`    public static let protocolVersion: UInt32 = ${schema.protocolVersion}`);
  out.push('    /// Lowest envelope version this build accepts from a peer.');
  out.push(`    public static let minProtocolVersion: UInt32 = ${schema.minProtocolVersion}`);
  out.push('');
  out.push('    /// The base64 strategy is set explicitly rather than left to Foundation\'s');
  out.push('    /// default, because the Rust peer encodes `bytes` with the padded RFC 4648');
  out.push('    /// standard alphabet and interop must not rest on an unstated default.');
  out.push('    public static func decoder() -> JSONDecoder {');
  out.push('        let decoder = JSONDecoder()');
  out.push('        decoder.dataDecodingStrategy = .base64');
  out.push('        return decoder');
  out.push('    }');
  out.push('');
  out.push('    public static func encoder() -> JSONEncoder {');
  out.push('        let encoder = JSONEncoder()');
  out.push('        encoder.dataEncodingStrategy = .base64');
  out.push('        return encoder');
  out.push('    }');
  out.push('');
  out.push('    public static func encode<Body: OspreyMessageBody>(');
  out.push('        id: UUID = UUID(),');
  out.push('        ts: Int64,');
  out.push('        body: Body,');
  out.push('        using encoder: JSONEncoder = OspreyProtocol.encoder()');
  out.push('    ) throws -> Data {');
  out.push('        try encoder.encode(Envelope(id: id, ts: ts, body: body))');
  out.push('    }');
  out.push('');
  out.push('    /// Reads the envelope fields that do not depend on the body schema.');
  out.push('    public static func decodeHeader(');
  out.push('        _ data: Data,');
  out.push('        using decoder: JSONDecoder = OspreyProtocol.decoder()');
  out.push('    ) throws -> EnvelopeHeader {');
  out.push('        try decoder.decode(EnvelopeHeader.self, from: data)');
  out.push('    }');
  out.push('');
  out.push('    /// Decodes a full envelope, resolving the body against `t`.');
  out.push('    ///');
  out.push('    /// The payload is parsed twice: `Codable` cannot select a body type from a');
  out.push('    /// sibling key in one pass, and a wrong guess would have to be recovered');
  out.push('    /// from mid-stream. Control-plane rates make the second parse irrelevant,');
  out.push('    /// and `input.*` never travels this path.');
  out.push('    public static func decode(');
  out.push('        _ data: Data,');
  out.push('        using decoder: JSONDecoder = OspreyProtocol.decoder()');
  out.push('    ) throws -> DecodedEnvelope {');
  out.push('        let header = try decodeHeader(data, using: decoder)');
  out.push('        guard header.v >= minProtocolVersion, header.v <= protocolVersion else {');
  out.push('            throw OspreyProtocolError.unsupportedVersion(');
  out.push('                found: header.v, min: minProtocolVersion, max: protocolVersion)');
  out.push('        }');
  out.push('        let body: MessageBody');
  out.push('        switch header.t {');
  for (const m of schema.messages) {
    out.push(`        case .${swiftCase(m.wire)}:`);
    out.push(`            let decoded = try decoder.decode(Envelope<${m.swiftName}>.self, from: data)`);
    out.push(`            body = .${swiftCase(m.wire)}(decoded.body)`);
  }
  if (schema.registry.some((e) => e.defined === null)) {
    out.push('        default:');
    out.push('            throw OspreyProtocolError.bodyDeferred(header.t)');
  }
  out.push('        }');
  const ctorArgs = headerProps.map((p) => `${p.ident}: header.${p.ident}`).join(', ');
  out.push(`        return DecodedEnvelope(${ctorArgs}, body: body)`);
  out.push('    }');
  out.push('}');
  return { name: 'Envelope.swift', contents: `${out.join('\n')}\n` };
}

export function emitSwift(schema: Schema): EmittedFile[] {
  return [emitEnums(schema), emitMessageType(schema), emitBodies(schema), emitEnvelope(schema)];
}

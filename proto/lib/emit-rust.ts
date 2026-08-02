// Emits the Rust half of the protocol into agent/osprey-proto/src/generated/.

import { docComment, pascal } from './names.ts';
import type { EnumDef, EnumValueDef, FieldDef, ResolvedType, Schema } from './schema.ts';

export interface EmittedFile {
  name: string;
  contents: string;
}

const HEADER = [
  '// DO NOT EDIT — generated from proto/messages.toml by proto/generate.ts.',
  '// Run `pnpm generate` in proto/ after changing the registry.',
  '',
];

function rustType(t: ResolvedType): string {
  let base: string;
  switch (t.kind) {
    case 'scalar':
      base = t.name === 'string' ? 'String' : t.name;
      break;
    case 'uuid':
      base = 'uuid::Uuid';
      break;
    case 'bytes':
      base = 'Vec<u8>';
      break;
    case 'json':
      base = 'serde_json::Value';
      break;
    case 'messageType':
    case 'enum':
      base = t.name;
      break;
  }
  return t.array ? `Vec<${base}>` : base;
}

function emitField(field: FieldDef, out: string[]): void {
  out.push(...docComment(field.doc, '    '));
  if (field.type.kind === 'bytes') {
    out.push('    #[serde(with = "crate::b64")]');
  }
  if (field.optional) {
    out.push('    #[serde(default, skip_serializing_if = "Option::is_none")]');
  }
  const ty = field.optional ? `Option<${rustType(field.type)}>` : rustType(field.type);
  out.push(`    pub ${field.name}: ${ty},`);
}

/**
 * Open string enum: every declared value plus an `Unknown` arm that preserves
 * the wire string. Serde routes through String so an unrecognised value never
 * fails the enclosing message — a peer on an older build has to be able to read
 * a newer peer's message and ignore what it does not understand.
 */
function emitOpenEnum(name: string, doc: string, values: EnumValueDef[], out: string[]): void {
  out.push(...docComment(doc));
  out.push('///');
  out.push('/// Unrecognised wire values decode to `Unknown`, preserving the original string.');
  out.push('#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]');
  out.push('#[serde(from = "String", into = "String")]');
  out.push(`pub enum ${name} {`);
  for (const v of values) {
    out.push(...docComment(v.doc, '    '));
    out.push(`    ${pascal(v.wire)},`);
  }
  out.push('    /// A value this build does not know, kept verbatim so it can be logged or relayed.');
  out.push('    Unknown(String),');
  out.push('}');
  out.push('');
  out.push(`impl ${name} {`);
  out.push('    /// Wire spelling of this value.');
  out.push('    pub fn as_str(&self) -> &str {');
  out.push('        match self {');
  for (const v of values) {
    out.push(`            Self::${pascal(v.wire)} => "${v.wire}",`);
  }
  out.push('            Self::Unknown(raw) => raw.as_str(),');
  out.push('        }');
  out.push('    }');
  out.push('}');
  out.push('');
  out.push(`impl From<String> for ${name} {`);
  out.push('    fn from(raw: String) -> Self {');
  out.push('        match raw.as_str() {');
  for (const v of values) {
    out.push(`            "${v.wire}" => Self::${pascal(v.wire)},`);
  }
  out.push('            _ => Self::Unknown(raw),');
  out.push('        }');
  out.push('    }');
  out.push('}');
  out.push('');
  out.push(`impl From<${name}> for String {`);
  out.push(`    fn from(value: ${name}) -> Self {`);
  out.push('        match value {');
  out.push(`            ${name}::Unknown(raw) => raw,`);
  out.push('            other => other.as_str().to_owned(),');
  out.push('        }');
  out.push('    }');
  out.push('}');
  out.push('');
  out.push(`impl core::fmt::Display for ${name} {`);
  out.push('    fn fmt(&self, f: &mut core::fmt::Formatter<\'_>) -> core::fmt::Result {');
  out.push('        f.write_str(self.as_str())');
  out.push('    }');
  out.push('}');
  out.push('');
}

function emitEnums(schema: Schema): EmittedFile {
  const out = [...HEADER];
  out.push('//! Value enumerations shared across message bodies.');
  out.push('');
  out.push('use serde::{Deserialize, Serialize};');
  out.push('');
  for (const e of schema.enums) {
    emitOpenEnum(e.name, e.doc, e.values, out);
  }
  const capabilityValues: EnumValueDef[] = schema.capabilities.map((g) => ({ wire: g.name, doc: g.doc }));
  emitOpenEnum(
    'Capability',
    'A message group a peer implements. Negotiated in `hello`/`hello.ok`; the\neffective set for a session is the intersection of both peers\' sets.',
    capabilityValues,
    out,
  );
  out.push('/// Which data channel a message must travel on (brief §5.3).');
  out.push('#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]');
  out.push('pub enum Channel {');
  out.push('    /// Reliable and ordered. A dropped keystroke is unacceptable.');
  out.push('    Reliable,');
  out.push('    /// Unordered with `maxRetransmits: 0`. A dropped mouse-move is invisible.');
  out.push('    Unreliable,');
  out.push('}');
  return { name: 'enums.rs', contents: `${out.join('\n')}\n` };
}

function emitRegistry(schema: Schema): EmittedFile {
  const out = [...HEADER];
  out.push('//! The complete message type registry.');
  out.push('');
  out.push('use serde::{Deserialize, Serialize};');
  out.push('');
  out.push('use super::enums::{Capability, Channel};');
  out.push('use crate::error::UnknownMessageType;');
  out.push('');
  out.push('/// Every message type the protocol reserves.');
  out.push('///');
  out.push('/// Closed on purpose: an unrecognised `t` cannot be routed, so it is a hard');
  out.push('/// error rather than something to ignore. Contrast the value enums, which are');
  out.push('/// open. Types whose body schema is not yet designed are still listed here so');
  out.push('/// the registry stays the single source of truth for the wire.');
  out.push('#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]');
  out.push('pub enum MessageType {');
  for (const entry of schema.registry) {
    out.push(`    #[serde(rename = "${entry.wire}")]`);
    out.push(`    ${entry.rustVariant},`);
  }
  out.push('}');
  out.push('');
  out.push('impl MessageType {');
  out.push('    /// Every registered type, in registry order.');
  out.push('    pub const ALL: &\'static [MessageType] = &[');
  for (const entry of schema.registry) {
    out.push(`        MessageType::${entry.rustVariant},`);
  }
  out.push('    ];');
  out.push('');
  out.push('    /// Wire spelling of this type.');
  out.push('    pub fn as_str(&self) -> &\'static str {');
  out.push('        match self {');
  for (const entry of schema.registry) {
    out.push(`            Self::${entry.rustVariant} => "${entry.wire}",`);
  }
  out.push('        }');
  out.push('    }');
  out.push('');
  out.push('    /// Capability that must be negotiated before this type may be sent.');
  out.push('    ///');
  out.push('    /// `None` means the type is mandatory for every peer.');
  out.push('    pub fn capability(&self) -> Option<Capability> {');
  out.push('        match self {');
  for (const group of schema.groups) {
    const members = schema.registry.filter((e) => e.group.name === group.name);
    if (members.length === 0) continue;
    const arms = members.map((e) => `Self::${e.rustVariant}`).join('\n            | ');
    const value = group.capability ? `Some(Capability::${pascal(group.name)})` : 'None';
    out.push(`            ${arms} => ${value},`);
  }
  out.push('        }');
  out.push('    }');
  out.push('');
  out.push('    /// Data channel this type must travel on (brief §5.3).');
  out.push('    pub fn channel(&self) -> Channel {');
  const unreliable = schema.registry.filter((e) => e.unreliable);
  if (unreliable.length === 0) {
    out.push('        Channel::Reliable');
  } else {
    out.push('        match self {');
    out.push(`            ${unreliable.map((e) => `Self::${e.rustVariant}`).join('\n            | ')} => Channel::Unreliable,`);
    out.push('            _ => Channel::Reliable,');
    out.push('        }');
  }
  out.push('    }');
  out.push('}');
  out.push('');
  out.push('impl core::fmt::Display for MessageType {');
  out.push('    fn fmt(&self, f: &mut core::fmt::Formatter<\'_>) -> core::fmt::Result {');
  out.push('        f.write_str(self.as_str())');
  out.push('    }');
  out.push('}');
  out.push('');
  out.push('impl core::str::FromStr for MessageType {');
  out.push('    type Err = UnknownMessageType;');
  out.push('');
  out.push('    fn from_str(value: &str) -> Result<Self, Self::Err> {');
  out.push('        Self::ALL');
  out.push('            .iter()');
  out.push('            .copied()');
  out.push('            .find(|candidate| candidate.as_str() == value)');
  out.push('            .ok_or_else(|| UnknownMessageType(value.to_owned()))');
  out.push('    }');
  out.push('}');
  return { name: 'registry.rs', contents: `${out.join('\n')}\n` };
}

function emitBodies(schema: Schema): EmittedFile {
  const out = [...HEADER];
  out.push('//! Body schemas for the message types that are fully defined.');
  out.push('//!');
  out.push('//! Unknown JSON fields are ignored rather than rejected, so a peer on an older');
  out.push('//! build can read a message a newer peer extended.');
  out.push('');
  out.push('use serde::{Deserialize, Serialize};');
  out.push('');
  const used = new Set<string>();
  for (const m of schema.messages) {
    for (const f of m.fields) {
      if (f.type.kind === 'enum') used.add(f.type.name);
    }
  }
  if (used.size > 0) {
    out.push(`use super::enums::{${[...used].sort().join(', ')}};`);
    out.push('');
  }
  for (const m of schema.messages) {
    out.push(...docComment(m.doc));
    out.push(`/// Wire type: \`${m.wire}\`.`);
    out.push('#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]');
    out.push(`pub struct ${m.rustName} {`);
    for (const field of m.fields) {
      emitField(field, out);
    }
    out.push('}');
    out.push('');
  }
  return { name: 'bodies.rs', contents: `${out.join('\n')}\n` };
}

function emitEnvelope(schema: Schema): EmittedFile {
  const out = [...HEADER];
  out.push('//! The wire envelope and the decoded body union.');
  out.push('');
  out.push('use serde::{Deserialize, Serialize};');
  out.push('use uuid::Uuid;');
  out.push('');
  out.push(`use super::bodies::{${schema.messages.map((m) => m.rustName).sort().join(', ')}};`);
  out.push('use super::registry::MessageType;');
  out.push('use crate::error::ProtoError;');
  out.push('');
  out.push('/// Highest envelope version this build speaks.');
  out.push(`pub const PROTOCOL_VERSION: u32 = ${schema.protocolVersion};`);
  out.push('/// Lowest envelope version this build accepts from a peer.');
  out.push(`pub const MIN_PROTOCOL_VERSION: u32 = ${schema.minProtocolVersion};`);
  out.push('');
  out.push(...docComment(schema.envelopeDoc));
  out.push('#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]');
  out.push('pub struct Envelope {');
  for (const field of schema.envelopeFields) {
    emitField(field, out);
  }
  out.push('}');
  out.push('');
  out.push('/// A decoded envelope body, one variant per fully defined message type.');
  out.push('#[derive(Debug, Clone, PartialEq, Serialize)]');
  out.push('#[serde(untagged)]');
  out.push('pub enum Body {');
  for (const m of schema.messages) {
    out.push(`    /// \`${m.wire}\``);
    out.push(`    ${pascal(m.wire)}(${m.rustName}),`);
  }
  out.push('}');
  out.push('');
  out.push('impl Body {');
  out.push('    /// The registry type this body belongs to.');
  out.push('    pub fn message_type(&self) -> MessageType {');
  out.push('        match self {');
  for (const m of schema.messages) {
    out.push(`            Self::${pascal(m.wire)}(_) => MessageType::${pascal(m.wire)},`);
  }
  out.push('        }');
  out.push('    }');
  out.push('}');
  out.push('');
  out.push('impl Envelope {');
  out.push('    /// Wraps a decoded body in an envelope at the current protocol version.');
  out.push('    pub fn new(id: Uuid, ts: i64, body: &Body) -> Result<Self, ProtoError> {');
  out.push('        let t = body.message_type();');
  out.push('        let value = serde_json::to_value(body).map_err(|source| ProtoError::Encode { t, source })?;');
  out.push('        Ok(Self { v: PROTOCOL_VERSION, id, t, ts, body: value })');
  out.push('    }');
  out.push('');
  out.push('    /// Rejects an envelope this build cannot interpret.');
  out.push('    pub fn check_version(&self) -> Result<(), ProtoError> {');
  out.push('        if self.v < MIN_PROTOCOL_VERSION || self.v > PROTOCOL_VERSION {');
  out.push('            return Err(ProtoError::UnsupportedVersion {');
  out.push('                found: self.v,');
  out.push('                min: MIN_PROTOCOL_VERSION,');
  out.push('                max: PROTOCOL_VERSION,');
  out.push('            });');
  out.push('        }');
  out.push('        Ok(())');
  out.push('    }');
  out.push('');
  out.push('    /// Decodes `body` against the schema selected by `t`.');
  out.push('    ///');
  out.push('    /// Separate from envelope parsing so a body that fails validation reports');
  out.push('    /// which message type it claimed to be.');
  out.push('    pub fn decode_body(&self) -> Result<Body, ProtoError> {');
  out.push('        match self.t {');
  for (const m of schema.messages) {
    out.push(`            MessageType::${pascal(m.wire)} => decode(self.t, &self.body).map(Body::${pascal(m.wire)}),`);
  }
  if (schema.registry.some((e) => e.defined === null)) {
    out.push('            other => Err(ProtoError::BodyDeferred(other)),');
  }
  out.push('        }');
  out.push('    }');
  out.push('}');
  out.push('');
  out.push('fn decode<T: serde::de::DeserializeOwned>(');
  out.push('    t: MessageType,');
  out.push('    body: &serde_json::Value,');
  out.push(') -> Result<T, ProtoError> {');
  out.push('    T::deserialize(body).map_err(|source| ProtoError::MalformedBody { t, source })');
  out.push('}');
  return { name: 'envelope.rs', contents: `${out.join('\n')}\n` };
}

function emitMod(): EmittedFile {
  const out = [...HEADER];
  out.push('//! Generated protocol types. See `proto/messages.toml`.');
  out.push('');
  out.push('pub mod bodies;');
  out.push('pub mod enums;');
  out.push('pub mod envelope;');
  out.push('pub mod registry;');
  out.push('');
  out.push('pub use bodies::*;');
  out.push('pub use enums::*;');
  out.push('pub use envelope::*;');
  out.push('pub use registry::*;');
  return { name: 'mod.rs', contents: `${out.join('\n')}\n` };
}

export function emitRust(schema: Schema): EmittedFile[] {
  return [emitMod(), emitEnums(schema), emitRegistry(schema), emitBodies(schema), emitEnvelope(schema)];
}

// Parses and validates proto/messages.toml into the model the emitters read.
// Every failure throws with the offending name in the message: a codegen input
// error must be obvious at the terminal, never a silently skipped message type.

import { parse as parseToml } from 'smol-toml';
import { isRustKeyword, pascal, camel } from './names.ts';

export type TypeKind = 'scalar' | 'uuid' | 'bytes' | 'json' | 'messageType' | 'enum';

export interface ResolvedType {
  kind: TypeKind;
  /** For `scalar` the TOML spelling; for `enum` the enum name. */
  name: string;
  array: boolean;
}

export interface FieldDef {
  name: string;
  type: ResolvedType;
  optional: boolean;
  doc: string;
}

export interface EnumValueDef {
  wire: string;
  doc: string;
}

export interface EnumDef {
  name: string;
  doc: string;
  values: EnumValueDef[];
}

export interface MessageDef {
  wire: string;
  group: string;
  rustName: string;
  swiftName: string;
  doc: string;
  fields: FieldDef[];
}

export interface GroupDef {
  name: string;
  doc: string;
  capability: boolean;
  deferred: string[];
  unreliable: string[];
}

export interface RegistryEntry {
  wire: string;
  group: GroupDef;
  rustVariant: string;
  swiftCase: string;
  unreliable: boolean;
  /** null for a name-only reservation whose body schema is not yet designed. */
  defined: MessageDef | null;
}

export interface Schema {
  protocolVersion: number;
  minProtocolVersion: number;
  rustOut: string;
  swiftOut: string;
  envelopeDoc: string;
  envelopeFields: FieldDef[];
  groups: GroupDef[];
  enums: EnumDef[];
  messages: MessageDef[];
  registry: RegistryEntry[];
  /** Capability-bearing groups, in declaration order. */
  capabilities: GroupDef[];
}

const SCALARS = new Set(['string', 'bool', 'u16', 'u32', 'u64', 'i32', 'i64', 'f64']);

type Table = Record<string, unknown>;

function asTable(value: unknown, what: string): Table {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${what}: expected a table`);
  }
  return value as Table;
}

function asArray(value: unknown, what: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${what}: expected an array`);
  return value;
}

function str(table: Table, key: string, what: string): string {
  const v = table[key];
  if (typeof v !== 'string') throw new Error(`${what}: missing required string \`${key}\``);
  return v;
}

function optStr(table: Table, key: string): string {
  const v = table[key];
  if (v === undefined) return '';
  if (typeof v !== 'string') throw new Error(`\`${key}\` must be a string`);
  return v;
}

function int(table: Table, key: string, what: string): number {
  const v = table[key];
  if (typeof v !== 'number' && typeof v !== 'bigint') {
    throw new Error(`${what}: missing required integer \`${key}\``);
  }
  return Number(v);
}

function strArray(table: Table, key: string, what: string): string[] {
  const v = table[key];
  if (v === undefined) return [];
  return asArray(v, `${what}.${key}`).map((item, i) => {
    if (typeof item !== 'string') throw new Error(`${what}.${key}[${i}]: expected a string`);
    return item;
  });
}

function resolveType(spec: string, enumNames: Set<string>, what: string): ResolvedType {
  const array = spec.startsWith('[') && spec.endsWith(']');
  const inner = array ? spec.slice(1, -1).trim() : spec;

  let resolved: ResolvedType;
  if (SCALARS.has(inner)) resolved = { kind: 'scalar', name: inner, array };
  else if (inner === 'uuid') resolved = { kind: 'uuid', name: inner, array };
  else if (inner === 'bytes') resolved = { kind: 'bytes', name: inner, array };
  else if (inner === 'json') resolved = { kind: 'json', name: inner, array };
  else if (inner === 'MessageType') resolved = { kind: 'messageType', name: inner, array };
  else if (enumNames.has(inner)) resolved = { kind: 'enum', name: inner, array };
  else throw new Error(`${what}: unknown type \`${spec}\``);

  if (array && (resolved.kind === 'bytes' || resolved.kind === 'json' || resolved.kind === 'messageType')) {
    throw new Error(`${what}: \`${spec}\` is not a supported array element type`);
  }
  return resolved;
}

function parseFields(raw: unknown, enumNames: Set<string>, what: string): FieldDef[] {
  return asArray(raw, `${what}.fields`).map((entry, i) => {
    const t = asTable(entry, `${what}.fields[${i}]`);
    const name = str(t, 'name', `${what}.fields[${i}]`);
    if (isRustKeyword(name)) {
      throw new Error(`${what}.fields[${i}]: \`${name}\` is a Rust keyword; rename the wire field`);
    }
    const optional = t.optional === true;
    const type = resolveType(str(t, 'type', `${what}.${name}`), enumNames, `${what}.${name}`);
    if (optional && type.kind === 'bytes') {
      throw new Error(`${what}.${name}: optional \`bytes\` is not supported by the base64 serde helper`);
    }
    return { name, type, optional, doc: optStr(t, 'doc') };
  });
}

function parseGroups(raw: unknown): GroupDef[] {
  return asArray(raw, 'groups').map((entry, i) => {
    const t = asTable(entry, `groups[${i}]`);
    const name = str(t, 'name', `groups[${i}]`);
    return {
      name,
      doc: optStr(t, 'doc'),
      capability: t.capability !== false,
      deferred: strArray(t, 'deferred', `group \`${name}\``),
      unreliable: strArray(t, 'unreliable', `group \`${name}\``),
    };
  });
}

function parseEnums(raw: unknown): EnumDef[] {
  if (raw === undefined) return [];
  return asArray(raw, 'enums').map((entry, i) => {
    const t = asTable(entry, `enums[${i}]`);
    const name = str(t, 'name', `enums[${i}]`);
    const values = asArray(t.values, `enum \`${name}\`.values`).map((v, j) => {
      const vt = asTable(v, `enum \`${name}\`.values[${j}]`);
      return { wire: str(vt, 'name', `enum \`${name}\`.values[${j}]`), doc: optStr(vt, 'doc') };
    });
    if (values.length === 0) throw new Error(`enum \`${name}\`: needs at least one value`);
    for (const v of values) {
      if (isRustKeyword(pascal(v.wire))) {
        throw new Error(`enum \`${name}\`: value \`${v.wire}\` becomes the Rust keyword \`${pascal(v.wire)}\``);
      }
    }
    return { name, doc: optStr(t, 'doc'), values };
  });
}

function parseMessages(raw: unknown, enumNames: Set<string>): MessageDef[] {
  if (raw === undefined) return [];
  return asArray(raw, 'messages').map((entry, i) => {
    const t = asTable(entry, `messages[${i}]`);
    const wire = str(t, 'type', `messages[${i}]`);
    const fields = parseFields(t.fields, enumNames, `message \`${wire}\``);
    return {
      wire,
      group: str(t, 'group', `message \`${wire}\``),
      rustName: optStr(t, 'rust_name') || `${pascal(wire)}Body`,
      swiftName: optStr(t, 'swift_name') || `${pascal(wire)}Body`,
      doc: optStr(t, 'doc'),
      fields,
    };
  });
}

/**
 * Builds the ordered registry of every message type. Group declaration order
 * decides enum variant order, so a reordering of the TOML is a reviewable diff
 * in the generated files rather than an invisible ABI-shaped change.
 */
function buildRegistry(groups: GroupDef[], messages: MessageDef[]): RegistryEntry[] {
  const byGroup = new Map<string, MessageDef[]>();
  for (const m of messages) {
    const bucket = byGroup.get(m.group);
    if (bucket) bucket.push(m);
    else byGroup.set(m.group, [m]);
  }
  for (const groupName of byGroup.keys()) {
    if (!groups.some((g) => g.name === groupName)) {
      throw new Error(`message group \`${groupName}\` is not declared in [[groups]]`);
    }
  }

  const seen = new Set<string>();
  const registry: RegistryEntry[] = [];
  for (const group of groups) {
    const defined = byGroup.get(group.name) ?? [];
    const names = [...defined.map((m) => m.wire), ...group.deferred];
    for (const un of group.unreliable) {
      if (!names.includes(un)) {
        throw new Error(`group \`${group.name}\`: \`${un}\` in \`unreliable\` is not one of its messages`);
      }
    }
    for (const wire of names) {
      if (seen.has(wire)) throw new Error(`duplicate message type \`${wire}\``);
      if (isRustKeyword(pascal(wire))) {
        throw new Error(`message type \`${wire}\` becomes the Rust keyword \`${pascal(wire)}\``);
      }
      seen.add(wire);
      registry.push({
        wire,
        group,
        rustVariant: pascal(wire),
        swiftCase: camel(wire),
        unreliable: group.unreliable.includes(wire),
        defined: defined.find((m) => m.wire === wire) ?? null,
      });
    }
  }
  return registry;
}

export function loadSchema(source: string): Schema {
  const root = asTable(parseToml(source), 'messages.toml');
  const meta = asTable(root.meta, '[meta]');
  const envelope = asTable(root.envelope, '[envelope]');

  const groups = parseGroups(root.groups);
  const enums = parseEnums(root.enums);
  const enumNames = new Set(enums.map((e) => e.name));
  // Synthesised from the group table rather than declared, so the capability
  // set cannot drift from the message registry it gates.
  enumNames.add('Capability');

  const messages = parseMessages(root.messages, enumNames);
  const registry = buildRegistry(groups, messages);

  const protocolVersion = int(meta, 'protocol_version', '[meta]');
  const minProtocolVersion = int(meta, 'min_protocol_version', '[meta]');
  if (minProtocolVersion > protocolVersion) {
    throw new Error('[meta]: min_protocol_version exceeds protocol_version');
  }

  return {
    protocolVersion,
    minProtocolVersion,
    rustOut: str(meta, 'rust_out', '[meta]'),
    swiftOut: str(meta, 'swift_out', '[meta]'),
    envelopeDoc: optStr(envelope, 'doc'),
    envelopeFields: parseFields(envelope.fields, enumNames, 'envelope'),
    groups,
    enums,
    messages,
    registry,
    capabilities: groups.filter((g) => g.capability),
  };
}

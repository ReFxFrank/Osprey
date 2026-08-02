// Identifier translation between the wire names in messages.toml and the
// idiomatic spelling each target language expects.

const WORD_SEPARATORS = /[._-]+/;

/** Rust keywords that would produce uncompilable field or variant names. */
const RUST_KEYWORDS = new Set([
  'as', 'break', 'const', 'continue', 'crate', 'dyn', 'else', 'enum', 'extern',
  'false', 'fn', 'for', 'if', 'impl', 'in', 'let', 'loop', 'match', 'mod',
  'move', 'mut', 'pub', 'ref', 'return', 'self', 'Self', 'static', 'struct',
  'super', 'trait', 'true', 'type', 'unsafe', 'use', 'where', 'while', 'async',
  'await', 'abstract', 'become', 'box', 'do', 'final', 'macro', 'override',
  'priv', 'try', 'typeof', 'unsized', 'virtual', 'yield',
]);

/**
 * Swift keywords that need backticks when used as a property name. Swift
 * accepts far more of these than Rust does, so the generator escapes rather
 * than rejects.
 */
const SWIFT_KEYWORDS = new Set([
  'associatedtype', 'class', 'deinit', 'enum', 'extension', 'fileprivate',
  'func', 'import', 'init', 'inout', 'internal', 'let', 'open', 'operator',
  'private', 'protocol', 'public', 'rethrows', 'static', 'struct', 'subscript',
  'typealias', 'var', 'break', 'case', 'continue', 'default', 'defer', 'do',
  'else', 'fallthrough', 'for', 'guard', 'if', 'in', 'repeat', 'return',
  'switch', 'where', 'while', 'as', 'catch', 'false', 'is', 'nil', 'super',
  'self', 'Self', 'throw', 'throws', 'true', 'try', 'Type', 'Protocol',
]);

function words(wire: string): string[] {
  return wire.split(WORD_SEPARATORS).filter((w) => w.length > 0);
}

/** `hello.ok` -> `HelloOk`, `fs.read.begin` -> `FsReadBegin`. */
export function pascal(wire: string): string {
  return words(wire)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join('');
}

/** `hello.ok` -> `helloOk`, `bad_request` -> `badRequest`. */
export function camel(wire: string): string {
  const p = pascal(wire);
  return p.charAt(0).toLowerCase() + p.slice(1);
}

export function isRustKeyword(name: string): boolean {
  return RUST_KEYWORDS.has(name);
}

/** Swift property spelling, backticked when it collides with a keyword. */
export function swiftIdent(name: string): string {
  return SWIFT_KEYWORDS.has(name) ? `\`${name}\`` : name;
}

/**
 * Renders TOML doc text as a doc comment. Both Rust and Swift use `///`, and
 * neither has an escape hazard inside a line comment, so one implementation
 * serves both.
 */
export function docComment(doc: string, indent = ''): string[] {
  if (doc.trim().length === 0) return [];
  return doc
    .trimEnd()
    .split('\n')
    .map((line) => `${indent}/// ${line}`.trimEnd());
}

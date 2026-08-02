// Protocol code generator.
//
// Reads proto/messages.toml — the single source of truth — and writes the Rust
// and Swift type sets. Run `pnpm generate` after any change to the registry;
// never hand-edit anything under the output directories.

import { mkdir, readFile, readdir, unlink, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadSchema } from './lib/schema.ts';
import { emitRust, type EmittedFile } from './lib/emit-rust.ts';
import { emitSwift } from './lib/emit-swift.ts';

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * Writes `files` into `dir` and deletes any leftover file with the same
 * extension. A renamed message group must not leave a stale generated file
 * behind that still compiles and still gets used.
 */
async function syncDirectory(dir: string, extension: string, files: EmittedFile[]): Promise<string[]> {
  await mkdir(dir, { recursive: true });
  const expected = new Set(files.map((f) => f.name));
  const existing = await readdir(dir);
  const removed: string[] = [];
  for (const name of existing) {
    if (name.endsWith(extension) && !expected.has(name)) {
      await unlink(join(dir, name));
      removed.push(name);
    }
  }
  for (const file of files) {
    await writeFile(join(dir, file.name), file.contents, 'utf8');
  }
  return removed;
}

async function main(): Promise<void> {
  const sourcePath = join(HERE, 'messages.toml');
  const schema = loadSchema(await readFile(sourcePath, 'utf8'));

  const rustDir = resolve(HERE, schema.rustOut);
  const swiftDir = resolve(HERE, schema.swiftOut);

  const rustFiles = emitRust(schema);
  const swiftFiles = emitSwift(schema);

  const removedRust = await syncDirectory(rustDir, '.rs', rustFiles);
  const removedSwift = await syncDirectory(swiftDir, '.swift', swiftFiles);

  const defined = schema.registry.filter((e) => e.defined !== null).length;
  const deferred = schema.registry.length - defined;
  process.stdout.write(
    [
      `protocol v${schema.protocolVersion} (min v${schema.minProtocolVersion})`,
      `${schema.registry.length} message types: ${defined} defined, ${deferred} name-only`,
      `${schema.capabilities.length} capabilities, ${schema.enums.length + 1} value enums`,
      `rust  -> ${rustDir} (${rustFiles.map((f) => f.name).join(', ')})`,
      `swift -> ${swiftDir} (${swiftFiles.map((f) => f.name).join(', ')})`,
      ...[...removedRust, ...removedSwift].map((name) => `removed stale ${name}`),
      '',
    ].join('\n'),
  );
}

await main();

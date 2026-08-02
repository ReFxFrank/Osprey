import { rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { ESLint } from 'eslint';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

/**
 * Gate P0: "No raw `db.` access outside `src/repo/` — lint rule active and
 * passing." A rule that is configured but does not fire is worth nothing, so
 * this suite writes deliberately violating files into the real source tree,
 * lints them with the project's own configuration, asserts the specific rules
 * report, and removes them again.
 */
describe('repository boundary lint', () => {
  const probeDir = join(process.cwd(), 'src', 'routes');
  const written: string[] = [];
  let eslint: ESLint;

  beforeAll(() => {
    eslint = new ESLint({ cwd: process.cwd() });
  });

  afterAll(async () => {
    await Promise.all(written.map((f) => rm(f, { force: true })));
  });

  async function lintProbe(name: string, source: string) {
    const file = join(probeDir, name);
    written.push(file);
    await writeFile(file, source, 'utf8');
    const [result] = await eslint.lintFiles([file]);
    await rm(file, { force: true });
    return (result?.messages ?? []).map((m) => `${m.ruleId ?? 'parse'}: ${m.message}`);
  }

  it('rejects a route importing the drizzle client directly', async () => {
    const messages = await lintProbe(
      '__probe_direct.ts',
      "import { withTenant } from '../db/client.ts';\nexport const probe = withTenant;\n",
    );
    expect(messages.some((m) => m.startsWith('no-restricted-imports'))).toBe(true);
    expect(messages.some((m) => m.startsWith('boundaries/element-types'))).toBe(true);
  });

  it('rejects a route importing the schema through a deeper relative path', async () => {
    // The evasion the string-matching rule alone would be vulnerable to: a path
    // that walks out of the package and back in. The resolver-based rule sees
    // the same file regardless of spelling.
    const messages = await lintProbe(
      '__probe_relative.ts',
      "import { devices } from '../../../relay/src/db/schema.ts';\nexport const probe = devices;\n",
    );
    expect(messages.some((m) => m.startsWith('boundaries/element-types'))).toBe(true);
  });

  it('rejects a route importing drizzle-orm or postgres directly', async () => {
    const messages = await lintProbe(
      '__probe_external.ts',
      "import { eq } from 'drizzle-orm';\nimport postgres from 'postgres';\nexport const probe = { eq, postgres };\n",
    );
    expect(messages.some((m) => m.startsWith('no-restricted-imports'))).toBe(true);
    expect(messages.some((m) => m.startsWith('boundaries/external'))).toBe(true);
  });

  it('reports zero errors across the real source tree', async () => {
    const results = await eslint.lintFiles(['src/**/*.ts', 'test/**/*.ts']);
    const problems = results.flatMap((r) =>
      r.messages.map((m) => `${r.filePath}:${m.line} ${m.ruleId ?? 'parse'} ${m.message}`),
    );
    expect(problems).toEqual([]);
  });
});

import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startHarness, type Harness } from './support/harness.ts';

/**
 * Two checks over the shipped tree that review kept missing.
 *
 * The first is dead code. `repo/quotas.ts` shipped with zero callers while the
 * quota queries it duplicated lived inline in `repo/pairingTokens.ts`, and
 * `devices.countActive`, `pairings.listForDevice` and `audit.list` had none
 * either. Unreachable tenant-scoped query builders are not harmless: they are
 * the code most likely to be copied into a new route by someone who assumes an
 * existing helper was reviewed for tenancy.
 *
 * The second is `.env.example`. A placeholder password there defeats
 * docker-compose's `${VAR:?...}` guard, which fires only on a blank value — so
 * a deployment that never edited the file boots happily on a credential that is
 * in the repository.
 */

const REPO_DIR = join(process.cwd(), 'src', 'repo');

/** Members of the repository surface that are called from outside `src/repo/`. */
async function sourceOutsideRepo(): Promise<string> {
  const parts: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (full === REPO_DIR) continue;
        await walk(full);
        continue;
      }
      if (entry.name.endsWith('.ts')) parts.push(await readFile(full, 'utf8'));
    }
  };
  await walk(join(process.cwd(), 'src'));
  return parts.join('\n');
}

describe('repository surface has no unreachable members', () => {
  let h: Harness;

  beforeAll(async () => {
    h = await startHarness();
  });
  afterAll(async () => {
    await h.close();
  });

  it('exposes only repository modules that the composition root wires up', async () => {
    const modules = (await readdir(REPO_DIR)).filter((f) => f.endsWith('.ts') && f !== 'index.ts');
    const index = await readFile(join(REPO_DIR, 'index.ts'), 'utf8');
    const unreferenced = modules.filter((f) => !index.includes(`./${f}`));
    expect(unreferenced, 'repo modules nothing imports').toEqual([]);
  });

  it('has a caller outside src/repo/ for every method the repository exposes', async () => {
    // Whitespace is stripped so a call broken across lines — `deps.repo.devices`
    // then `.touchLastSeen(` — still reads as one qualified reference. Matching
    // the bare member name instead would let `hub.get(` vouch for `quotas.get`.
    const consumers = (await sourceOutsideRepo()).replace(/\s+/g, '');
    const orphans: string[] = [];

    // The live object, not a source scrape: this is exactly the surface a route
    // can reach through `deps.repo`.
    for (const [moduleName, module] of Object.entries(h.repo)) {
      for (const member of Object.keys(module as Record<string, unknown>)) {
        if (!consumers.includes(`.${moduleName}.${member}(`)) orphans.push(`${moduleName}.${member}`);
      }
    }

    expect(orphans, 'repository methods with no caller outside src/repo/').toEqual([]);
  });
});

describe('.env.example ships no usable credential', () => {
  it('leaves every password blank so the compose guard actually fires', async () => {
    const example = await readFile(join(process.cwd(), '.env.example'), 'utf8');
    const assigned = [...example.matchAll(/^([A-Z0-9_]*(?:PASSWORD|SECRET))=(.*)$/gm)];
    expect(assigned.length).toBeGreaterThan(0);
    for (const [, name, value] of assigned) {
      expect(value, `${name ?? 'variable'} must ship blank, not with a placeholder`).toBe('');
    }
  });

  it('tells the operator how to generate each blank credential', async () => {
    const example = await readFile(join(process.cwd(), '.env.example'), 'utf8');
    expect([...example.matchAll(/openssl rand/g)]).toHaveLength(3);
  });
});

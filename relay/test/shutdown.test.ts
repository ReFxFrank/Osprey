import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * Node 24 defaults to `--unhandled-rejections=throw`. A shutdown promise fired
 * with `void` and no `.catch()` therefore turns a recoverable "the server did
 * not close cleanly" into an immediate crash — losing the reason and skipping
 * whatever teardown had not run yet, including the connection pool.
 *
 * This runs the real signal handler in a real process because that is the only
 * place the behaviour exists; the test runner installs its own handlers and
 * would mask it.
 */
const FIXTURE = fileURLToPath(new URL('./support/shutdownFixture.ts', import.meta.url));

interface Run {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

function runFixture(mode: 'resolve' | 'reject'): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [FIXTURE], {
      env: { ...process.env, SHUTDOWN_FIXTURE_MODE: mode },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => (stdout += chunk));
    child.stderr.on('data', (chunk: string) => (stderr += chunk));
    child.once('error', reject);
    child.once('close', (code) => resolve({ code, stdout, stderr }));
  });
}

describe('shutdown handling', () => {
  it('closes the database pool and exits zero on a clean shutdown', async () => {
    const run = await runFixture('resolve');
    expect(run.stdout).toContain('server close attempted');
    expect(run.stdout).toContain('database closed');
    expect(run.code).toBe(0);
  });

  it('logs a failing close, still closes the pool, and exits non-zero', async () => {
    const run = await runFixture('reject');
    // The `finally` is what makes this line appear: without it a rejecting
    // server close strands the connection pool.
    expect(run.stdout).toContain('database closed');
    expect(run.stdout).toContain('log.error shutdown failed: listener refused to close');
    // The crash signature the missing `.catch()` produced.
    expect(run.stderr).not.toContain('ERR_UNHANDLED_REJECTION');
    expect(run.code).toBe(1);
  });
});

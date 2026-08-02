/**
 * Spawned as its own process by `test/shutdown.test.ts`. The behaviour under
 * test is what Node does to a rejected promise that nothing is waiting on, so it
 * cannot be observed from inside a test runner that installs its own handlers —
 * it needs a real process, a real signal, and a real exit code.
 *
 * `SHUTDOWN_FIXTURE_MODE=reject` makes the server's close reject, which is the
 * case that used to take the process down with ERR_UNHANDLED_REJECTION.
 */
import { installShutdownHandlers } from '../../src/shutdown.ts';

const shouldReject = process.env.SHUTDOWN_FIXTURE_MODE === 'reject';

const server = {
  close: async (): Promise<void> => {
    process.stdout.write('server close attempted\n');
    if (shouldReject) throw new Error('listener refused to close');
  },
};

const database = {
  close: async (): Promise<void> => {
    process.stdout.write('database closed\n');
  },
};

const log = {
  error: (details: Record<string, unknown>, message: string): void => {
    const err = details.err;
    const reason = err instanceof Error ? err.message : String(err);
    process.stdout.write(`log.error ${message}: ${reason}\n`);
  },
};

installShutdownHandlers(server, database, log);

// Holds the loop open long enough for the signal to arrive and the handler's
// async work to finish; cleared so the process exits on its own afterwards.
const keepAlive = setTimeout(() => undefined, 2_000);
process.once('SIGTERM', () => {
  setTimeout(() => clearTimeout(keepAlive), 100);
});

process.stdout.write('ready\n');
process.kill(process.pid, 'SIGTERM');

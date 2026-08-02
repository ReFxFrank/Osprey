/**
 * Signal handling lives here rather than inline in `index.ts` so the failure
 * path can be exercised by a test. It is the path that matters: Node 24 defaults
 * to `--unhandled-rejections=throw`, so a shutdown promise with nothing attached
 * turns a recoverable "the server did not close cleanly" into an immediate
 * crash that loses the reason and skips the rest of the teardown.
 */

/** Anything with an async close — the Fastify instance and the database pool. */
export interface Closable {
  close(): Promise<void>;
}

export interface ShutdownLog {
  error(details: Record<string, unknown>, message: string): void;
}

export const SHUTDOWN_SIGNALS = ['SIGINT', 'SIGTERM'] as const;

export function installShutdownHandlers(server: Closable, database: Closable, log: ShutdownLog): void {
  for (const signal of SHUTDOWN_SIGNALS) {
    process.once(signal, () => {
      void (async () => {
        try {
          await server.close();
        } finally {
          // In `finally` so a server that refuses to close cannot strand the
          // connection pool as well.
          await database.close();
        }
      })().catch((err: unknown) => {
        log.error({ err, signal }, 'shutdown failed');
        process.exitCode = 1;
      });
    });
  }
}

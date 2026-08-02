/**
 * Execution plan item 11: per-account quotas structurally cannot bound *account*
 * creation, so enrollment needs a limit that exists outside any tenant. This is
 * that limit — a fixed window keyed on source IP, global to the process.
 *
 * TODO(frank): decide whether 1.0 ships more than one relay process. This
 * counter is per-process, so a horizontally scaled relay would multiply the
 * effective limit by the replica count and need Redis or a Postgres counter
 * instead. Single-operator 1.0 runs one process, so the in-memory window is
 * correct today and wrong the moment that changes.
 */
export interface RateLimiter {
  /** Returns true when the caller is within budget, and consumes one unit. */
  consume(key: string): boolean;
  reset(): void;
}

export function createFixedWindowLimiter(limit: number, windowMs: number): RateLimiter {
  const windows = new Map<string, { count: number; expiresAt: number }>();

  return {
    consume(key: string): boolean {
      const now = Date.now();
      for (const [k, w] of windows) {
        if (w.expiresAt <= now) windows.delete(k);
      }
      const existing = windows.get(key);
      if (existing === undefined || existing.expiresAt <= now) {
        windows.set(key, { count: 1, expiresAt: now + windowMs });
        return limit >= 1;
      }
      existing.count += 1;
      return existing.count <= limit;
    },
    reset(): void {
      windows.clear();
    },
  };
}

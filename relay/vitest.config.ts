import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    globalSetup: ['test/support/globalSetup.ts'],
    // Every test file shares one Postgres database and truncates it between
    // tests; running files in parallel would have them truncate each other's
    // fixtures. Correctness over wall-clock here.
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});

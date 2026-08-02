import { buildApp, quotaDefaultsFrom } from './app.ts';
import { loadConfig } from './config.ts';
import { createRepoFromUrl } from './repo/index.ts';

const config = loadConfig();
const handle = createRepoFromUrl(config.databaseUrl, quotaDefaultsFrom(config));
const { app } = await buildApp(config, handle.repo);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    void (async () => {
      await app.close();
      await handle.close();
    })();
  });
}

await app.listen({ host: config.host, port: config.port });

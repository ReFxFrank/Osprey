import { buildApp, quotaDefaultsFrom } from './app.ts';
import { loadConfig } from './config.ts';
import { createRepoFromUrl } from './repo/index.ts';
import { installShutdownHandlers } from './shutdown.ts';

const config = loadConfig();
const handle = await createRepoFromUrl(config.databaseUrl, quotaDefaultsFrom(config));
const { app } = await buildApp(config, handle.repo);

installShutdownHandlers(app, handle, app.log);

await app.listen({ host: config.host, port: config.port });

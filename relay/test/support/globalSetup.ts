import { runMigrations } from '../../src/db/migrate.ts';
import { ownerUrl, recreateDatabase } from './pg.ts';

/**
 * The suite runs against a real Postgres cluster, not a fake. Row-level
 * security, the atomic single-statement redeem, and the non-owner role are all
 * properties of the database; a stub would assert nothing about any of them.
 */
export default async function setup(): Promise<void> {
  await recreateDatabase();
  await runMigrations(ownerUrl);
}

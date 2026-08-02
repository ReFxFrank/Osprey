import boundaries from 'eslint-plugin-boundaries';
import tseslint from 'typescript-eslint';

/**
 * CLAUDE.md rule 12 and brief §4.2: a raw `db.` access outside `src/repo/` must
 * fail the build, not merely fail review.
 *
 * Two independent mechanisms, because each defeats a different evasion:
 *
 *  1. `no-restricted-imports` with *patterns*, applied to every file except the
 *     repository and the db module itself. It lists the alias form, every
 *     relative depth (`./db/…`, `../db/…`, `../../db/…`), and the underlying
 *     libraries (`drizzle-orm*`, `postgres`, `pg`). It is exact and cheap, but
 *     it matches on the import *string*, so an unusual spelling could slip past.
 *
 *  2. `boundaries/element-types`, which resolves each import to a file on disk
 *     and classifies it by directory. Because it works on the resolved path, no
 *     amount of `../` juggling changes the verdict — `src/routes/x.ts` importing
 *     `../db/client.ts` and importing `../../relay/src/db/client.ts` are the
 *     same violation.
 *
 * The pair is verified by `test/lint-enforcement.test.ts`, which writes a
 * deliberately violating file, runs ESLint over it, asserts both rules fire,
 * and deletes it.
 */

const DB_IMPORT_PATTERNS = [
  'db',
  'db/*',
  './db',
  './db/*',
  '../db',
  '../db/*',
  '../../db',
  '../../db/*',
  '../../../db',
  '../../../db/*',
  '**/db/client',
  '**/db/client.ts',
  '**/db/schema',
  '**/db/schema.ts',
  'drizzle-orm',
  'drizzle-orm/*',
  'drizzle-orm/**',
  'postgres',
  'pg',
];

const DB_IMPORT_MESSAGE =
  'Database access is confined to src/repo/. Route handlers, http/ and ws/ must call a repository function that takes accountId as its first parameter (brief §4.2, §6.7).';

export default tseslint.config(
  {
    ignores: ['node_modules/**', 'drizzle/**', 'dist/**', 'eslint.config.js'],
  },
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
  },
  {
    // Mechanism 1 — import-string denial everywhere the db is off limits.
    files: ['src/**/*.ts', 'test/**/*.ts'],
    ignores: ['src/repo/**', 'src/db/**', 'test/support/**', 'drizzle.config.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        { patterns: [{ group: DB_IMPORT_PATTERNS, message: DB_IMPORT_MESSAGE }] },
      ],
    },
  },
  {
    // Mechanism 2 — resolver-based layering.
    files: ['src/**/*.ts'],
    plugins: { boundaries },
    settings: {
      'boundaries/include': ['src/**/*.ts'],
      'boundaries/elements': [
        { type: 'db', pattern: 'src/db/*.ts', mode: 'file' },
        { type: 'repo', pattern: 'src/repo/*.ts', mode: 'file' },
        { type: 'http', pattern: 'src/http/*.ts', mode: 'file' },
        { type: 'ws', pattern: 'src/ws/*.ts', mode: 'file' },
        { type: 'routes', pattern: 'src/routes/*.ts', mode: 'file' },
        { type: 'app', pattern: 'src/*.ts', mode: 'file' },
      ],
    },
    rules: {
      'boundaries/element-types': [
        'error',
        {
          default: 'disallow',
          rules: [
            { from: ['db'], allow: ['db'] },
            { from: ['repo'], allow: ['repo', 'db'] },
            { from: ['http'], allow: ['http', 'repo'] },
            { from: ['ws'], allow: ['ws', 'repo'] },
            { from: ['routes'], allow: ['routes', 'repo', 'http', 'ws', 'app'] },
            { from: ['app'], allow: ['app', 'routes', 'repo', 'http', 'ws'] },
          ],
        },
      ],
      'boundaries/external': [
        'error',
        {
          default: 'allow',
          rules: [
            {
              from: ['routes', 'http', 'ws', 'app'],
              disallow: ['drizzle-orm', 'drizzle-orm/*', 'postgres', 'pg'],
              message: DB_IMPORT_MESSAGE,
            },
          ],
        },
      ],
    },
  },
  {
    files: ['test/**/*.ts'],
    rules: { '@typescript-eslint/no-non-null-assertion': 'off' },
  },
);

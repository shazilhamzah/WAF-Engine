#!/usr/bin/env node
'use strict';
/**
 * npm run setup [-- --reset-passwords]
 *
 * Idempotent first-run setup:
 *  1. creates the data directory and the secret key file (<dataDir>/secret.key, owner-only)
 *  2. creates / migrates the SQLite database
 *  3. loads src/rules/default.rules into the rules table (version 1) if the table is empty
 *  4. writes the initial configuration version from engine.DEFAULT_CONFIG if none exists
 *  5. creates users admin, operator, viewer and admin2 (second admin for separation-of-duties demos)
 *
 * Passwords: WAF_ADMIN_PASSWORD / WAF_OPERATOR_PASSWORD / WAF_VIEWER_PASSWORD / WAF_ADMIN2_PASSWORD, or
 * randomly generated and printed ONCE to this console. They are never written to disk. Existing users are
 * left untouched unless --reset-passwords is given (which also ends their sessions).
 */
const path = require('node:path');
const { loadConfig, loadSecret, ensureDir } = require('../src/config');
const { openDatabase } = require('../src/db');
const { seedDatabase } = require('../src/services/seed');

const ENV_PASSWORDS = { admin: 'WAF_ADMIN_PASSWORD', operator: 'WAF_OPERATOR_PASSWORD', viewer: 'WAF_VIEWER_PASSWORD', admin2: 'WAF_ADMIN2_PASSWORD' };

function usage() {
  return 'Usage: node scripts/setup.js [--reset-passwords]\n';
}

async function main(argv = process.argv.slice(2), env = process.env) {
  const unknown = argv.filter((a) => !['--reset-passwords', '--help', '-h'].includes(a));
  if (argv.includes('--help') || argv.includes('-h')) { process.stdout.write(usage()); return 0; }
  if (unknown.length) { process.stderr.write(`Unknown option(s): ${unknown.join(' ')}\n${usage()}`); return 2; }
  const resetPasswords = argv.includes('--reset-passwords');

  const cfg = loadConfig(env);
  ensureDir(cfg.dataDir);
  const secret = loadSecret(cfg.dataDir, env);
  let engine;
  try {
    engine = require('../src/engine');
  } catch (err) {
    process.stderr.write(`Cannot load the security engine (src/engine): ${err.message}\n`);
    return 1;
  }

  const passwords = {};
  for (const [user, name] of Object.entries(ENV_PASSWORDS)) if (env[name]) passwords[user] = env[name];

  const db = openDatabase(cfg.dbPath);
  try {
    const result = await seedDatabase(db, engine, { passwords, includeAdmin2: true, resetPasswords });
    const out = process.stdout;
    out.write('\nWAF Studio setup complete\n');
    out.write(`  data directory : ${path.relative(process.cwd(), cfg.dataDir) || '.'}\n`);
    out.write(`  database       : ${cfg.dbPath === ':memory:' ? ':memory:' : path.relative(process.cwd(), cfg.dbPath)} (schema v${db.schemaVersion})\n`);
    out.write(`  secret key     : ${secret.source === 'env' ? 'from WAF_SECRET' : secret.source === 'generated' ? 'generated (secret.key, owner-only)' : 'existing secret.key'}\n`);
    out.write(`  rules          : ${result.rules.skipped ? `unchanged (${db.rules.count()} in database)` : `${result.rules.loaded} loaded from src/rules/default.rules`}\n`);
    if (result.rules.errors && result.rules.errors.length) {
      out.write(`  rule warnings  : ${result.rules.errors.length} (first: ${JSON.stringify(result.rules.errors[0]).slice(0, 160)})\n`);
    }
    out.write(`  configuration  : ${result.config.seeded ? `version ${result.config.version} written from engine defaults` : `unchanged (active version ${db.configs.latest() ? db.configs.latest().version : 'none'})`}\n`);

    const touched = [...result.created.map((u) => ({ ...u, what: 'created' })), ...result.updated.map((u) => ({ ...u, what: 'password reset' }))];
    if (touched.length === 0) {
      out.write('  users          : unchanged (use --reset-passwords to set new passwords)\n');
    } else {
      out.write('\n  Accounts (passwords are shown ONCE and are not stored anywhere in plain text):\n');
      for (const u of touched) {
        const shown = u.generated ? result.passwords[u.username] : '(from environment variable)';
        out.write(`    ${u.username.padEnd(9)} ${u.role.padEnd(9)} ${u.what.padEnd(15)} ${shown}\n`);
      }
      out.write('\n  Store generated passwords in a password manager now; change them via the console (Account page).\n');
    }
    out.write('\nNext: npm start\n');
    return 0;
  } finally {
    db.close();
  }
}

if (require.main === module) {
  main().then((code) => { process.exitCode = code; }, (err) => {
    process.stderr.write(`Setup failed: ${err.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { main };

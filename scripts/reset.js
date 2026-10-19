#!/usr/bin/env node
'use strict';
/**
 * npm run reset -- --yes [--new-secret]
 *
 * Recovery tool: deletes the SQLite database (and its -wal/-shm files) so that `npm run setup` can
 * recreate it. Use after corruption or to start a demo from a clean state. WAF Studio must be stopped.
 *
 * By default the secret key file is kept (so client pseudonyms stay stable); pass --new-secret to delete
 * it as well. Without --yes nothing is deleted.
 */
const fs = require('node:fs');
const path = require('node:path');
const { loadConfig } = require('../src/config');

function main(argv = process.argv.slice(2), env = process.env) {
  const known = ['--yes', '-y', '--new-secret', '--help', '-h'];
  const unknown = argv.filter((a) => !known.includes(a));
  const usage = 'Usage: node scripts/reset.js --yes [--new-secret]\n'
    + '  Deletes the WAF Studio database (all users, rules, events, exceptions and audit records).\n'
    + '  Stop WAF Studio first. Run `npm run setup` afterwards.\n';
  if (argv.includes('--help') || argv.includes('-h')) { process.stdout.write(usage); return 0; }
  if (unknown.length) { process.stderr.write(`Unknown option(s): ${unknown.join(' ')}\n${usage}`); return 2; }

  const cfg = loadConfig(env);
  if (cfg.dbPath === ':memory:') { process.stdout.write('WAF_DB_PATH is :memory: — nothing to delete.\n'); return 0; }
  const targets = [cfg.dbPath, `${cfg.dbPath}-wal`, `${cfg.dbPath}-shm`, `${cfg.dbPath}-journal`];
  if (argv.includes('--new-secret')) targets.push(path.join(cfg.dataDir, 'secret.key'));
  const existing = targets.filter((p) => fs.existsSync(p));

  if (!argv.includes('--yes') && !argv.includes('-y')) {
    process.stdout.write(`${usage}\nWould delete:\n${existing.map((p) => `  ${path.relative(process.cwd(), p)}`).join('\n') || '  (nothing — no database found)'}\n\nRe-run with --yes to confirm.\n`);
    return 1;
  }
  for (const p of existing) {
    try {
      fs.rmSync(p, { force: true });
      process.stdout.write(`deleted ${path.relative(process.cwd(), p)}\n`);
    } catch (err) {
      process.stderr.write(`could not delete ${path.relative(process.cwd(), p)} (${err.code}); is WAF Studio still running?\n`);
      return 1;
    }
  }
  if (!existing.length) process.stdout.write('No database found; nothing to delete.\n');
  process.stdout.write('Reset complete. Run `npm run setup` to recreate users, rules and configuration.\n');
  return 0;
}

if (require.main === module) process.exitCode = main();

module.exports = { main };

'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { migrate, LATEST_VERSION } = require('./schema');
const { createUsersRepository } = require('./repositories/users');
const { createSessionsRepository } = require('./repositories/sessions');
const { createRulesRepository } = require('./repositories/rules');
const { createConfigRepository } = require('./repositories/configs');
const { createEventsRepository } = require('./repositories/events');
const { createExceptionsRepository } = require('./repositories/exceptions');
const { createAuditRepository } = require('./repositories/audit');

function openDatabase(dbPath = ':memory:', options = {}) {
  const memory = dbPath === ':memory:';
  if (!memory) fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true, mode: 0o700 });
  const raw = new DatabaseSync(dbPath);
  raw.exec('PRAGMA foreign_keys = ON');
  raw.exec('PRAGMA busy_timeout = 5000');
  if (!memory) {
    raw.exec('PRAGMA journal_mode = WAL');
    raw.exec('PRAGMA synchronous = NORMAL');
  }
  const integrity = raw.prepare('PRAGMA quick_check').get();
  if (!integrity || Object.values(integrity)[0] !== 'ok') {
    raw.close();
    throw new Error('Database integrity check failed; see docs/security-controls.md (recovery) or run `npm run reset -- --yes`');
  }
  let migration;
  try {
    migration = migrate(raw);
  } catch (err) {
    raw.close(); // windows keeps the file locked until it is closed
    throw err;
  }
  if (!memory) { try { fs.chmodSync(dbPath, 0o600); } catch { /* best effort */ } }

  const clock = typeof options.clock === 'function' ? options.clock : () => Date.now();
  let depth = 0;
  function transaction(fn) {
    if (depth > 0) {
      const sp = `sp_${depth}`;
      raw.exec(`SAVEPOINT ${sp}`);
      depth += 1;
      try {
        const result = fn();
        raw.exec(`RELEASE ${sp}`);
        return result;
      } catch (err) {
        raw.exec(`ROLLBACK TO ${sp}`);
        raw.exec(`RELEASE ${sp}`);
        throw err;
      } finally {
        depth -= 1;
      }
    }
    raw.exec('BEGIN IMMEDIATE');
    depth = 1;
    try {
      const result = fn();
      raw.exec('COMMIT');
      return result;
    } catch (err) {
      try { raw.exec('ROLLBACK'); } catch { /* already rolled back */ }
      throw err;
    } finally {
      depth = 0;
    }
  }

  const ctx = { raw, clock, transaction };
  const store = {
    raw,
    path: dbPath,
    schemaVersion: LATEST_VERSION,
    migration,
    clock,
    transaction,
    users: createUsersRepository(ctx),
    sessions: createSessionsRepository(ctx),
    rules: createRulesRepository(ctx),
    configs: createConfigRepository(ctx),
    events: createEventsRepository(ctx),
    exceptions: createExceptionsRepository(ctx),
    audit: createAuditRepository(ctx),
    isOpen() { return raw.isOpen; },
    close() { if (raw.isOpen) raw.close(); },
  };
  return store;
}

module.exports = { openDatabase };

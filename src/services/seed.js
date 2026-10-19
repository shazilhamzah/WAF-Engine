'use strict';
/**
 * Database seeding, shared by scripts/setup.js, tests and the evaluation harness.
 *
 *   const { passwords, created } = await seedDatabase(db, engine, { passwords: { admin: '…' } });
 *
 * - default rules: `src/rules/default.rules` parsed with engine.parseRuleFile, stored as version 1 when the
 *   rules table is empty
 * - default configuration from engine.DEFAULT_CONFIG when no config version exists
 * - users admin/operator/viewer (usernames = role names; `options.users` adds more, e.g. admin2) when they
 *   do not exist; passwords come from `options.passwords[username]` or are randomly generated and
 *   returned (never written to disk). Existing users keep their password unless `resetPasswords: true`.
 * Idempotent: running it twice changes nothing.
 */
const fs = require('node:fs');
const path = require('node:path');
const { hashPassword, generatePassword, checkPasswordPolicy } = require('../auth/passwords');

const DEFAULT_RULES_PATH = path.resolve(__dirname, '..', 'rules', 'default.rules');
const DEFAULT_USERS = Object.freeze([
  { username: 'admin', role: 'admin' },
  { username: 'operator', role: 'operator' },
  { username: 'viewer', role: 'viewer' },
]);
/** Second administrator used to demonstrate separation of duties (exception approval). */
const ADMIN2 = Object.freeze({ username: 'admin2', role: 'admin' });

function metaFromSource(engine, id, source) {
  const fallback = { id: Number(id), name: `Rule ${id}`, severity: null, category: null };
  if (typeof engine.validateRuleSource !== 'function') return fallback;
  const v = engine.validateRuleSource(source);
  if (!v || !v.ok || !v.rule) return { ...fallback, invalid: true, errors: (v && v.errors) || [] };
  return {
    id: Number(v.rule.id ?? id),
    name: String(v.rule.name || fallback.name),
    severity: v.rule.severity ?? null,
    category: v.rule.category ?? null,
  };
}

function seedRules(db, engine, { rulesText, rulesPath = DEFAULT_RULES_PATH } = {}) {
  if (db.rules.count() > 0) return { loaded: 0, skipped: true, errors: [] };
  let text = rulesText;
  if (text === undefined) {
    if (!fs.existsSync(rulesPath)) return { loaded: 0, skipped: true, errors: [{ message: `rules file not found: ${path.basename(rulesPath)}` }] };
    text = fs.readFileSync(rulesPath, 'utf8');
  }
  if (!engine || typeof engine.parseRuleFile !== 'function') {
    return { loaded: 0, skipped: true, errors: [{ message: 'engine.parseRuleFile unavailable' }] };
  }
  const parsed = engine.parseRuleFile(text) || {};
  const errors = [...(parsed.errors || [])];
  let loaded = 0;
  db.transaction(() => {
    for (const r of parsed.rules || []) {
      const meta = metaFromSource(engine, r.id, r.source);
      if (meta.invalid) { errors.push({ ruleId: r.id, message: 'rule failed validation', errors: meta.errors }); continue; }
      if (db.rules.get(meta.id)) { errors.push({ ruleId: meta.id, message: 'duplicate rule id' }); continue; }
      db.rules.create({ id: meta.id, name: meta.name, source: r.source, enabled: true, severity: meta.severity, category: meta.category }, null);
      loaded += 1;
    }
  });
  return { loaded, skipped: false, errors };
}

function seedConfig(db, engine) {
  if (db.configs.latest()) return { seeded: false, version: db.configs.latest().version };
  const base = engine && engine.DEFAULT_CONFIG ? structuredClone(engine.DEFAULT_CONFIG) : null;
  if (!base) return { seeded: false, version: null };
  const v = typeof engine.validateConfig === 'function' ? engine.validateConfig(base) : { ok: true, config: base };
  const rec = db.configs.append(v && v.ok ? v.config : base, null, 'default configuration');
  return { seeded: true, version: rec.version };
}

/**
 * @param {object} db  repository store from openDatabase()
 * @param {object} [engine] src/engine (rules/config are skipped when absent)
 * @param {{ passwords?: Record<string,string>, users?: Array<{username,role}>, includeAdmin2?: boolean,
 *           resetPasswords?: boolean, rulesText?: string, rulesPath?: string }} [options]
 * @returns {Promise<{ passwords: Record<string,string>, created: Array<{username,role,generated:boolean}>,
 *                     rules: object, config: object }>}
 */
async function seedDatabase(db, engine, options = {}) {
  const given = { ...(options.passwords || {}) };
  const users = [...DEFAULT_USERS, ...(options.includeAdmin2 ? [ADMIN2] : []), ...(options.users || [])];
  const passwords = { ...given };
  const created = [];
  const updated = [];

  for (const { username, role } of users) {
    const existing = db.users.findByUsername(username);
    if (existing && !options.resetPasswords) continue;
    let password = given[username];
    let generated = false;
    if (password !== undefined) {
      const problems = checkPasswordPolicy(password, username);
      if (problems.length) throw new Error(`Password for ${username} ${problems.join('; ')}`);
    } else {
      password = generatePassword();
      generated = true;
    }
    const hash = await hashPassword(password);
    if (existing) {
      db.users.setPasswordHash(existing.id, hash);
      db.sessions.deleteForUser(existing.id);
      updated.push({ username, role: existing.role, generated });
    } else {
      db.users.create({ username, passwordHash: hash, role });
      created.push({ username, role, generated });
    }
    passwords[username] = password;
  }

  const rules = engine ? seedRules(db, engine, options) : { loaded: 0, skipped: true, errors: [{ message: 'no engine' }] };
  const config = engine ? seedConfig(db, engine) : { seeded: false, version: null };
  return { passwords, created, updated, rules, config };
}

module.exports = { seedDatabase, seedRules, seedConfig, DEFAULT_USERS, ADMIN2, DEFAULT_RULES_PATH };

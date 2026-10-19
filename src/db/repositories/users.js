'use strict';
const { newId, nowIso, toBool } = require('../util');

const ROLES = Object.freeze(['admin', 'operator', 'viewer']);

function mapUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    role: row.role,
    disabled: toBool(row.disabled),
    failedAttempts: row.failed_attempts,
    lockedUntil: row.locked_until || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/** Public projection (what the API returns). Never includes the password hash. */
function publicUser(u) {
  if (!u) return null;
  return { id: u.id, username: u.username, role: u.role, disabled: u.disabled, lockedUntil: u.lockedUntil, createdAt: u.createdAt };
}

function createUsersRepository({ raw, clock }) {
  const stmts = {
    insert: raw.prepare(`INSERT INTO users (id, username, password_hash, role, disabled, failed_attempts, locked_until, created_at, updated_at)
                         VALUES (?, ?, ?, ?, ?, 0, NULL, ?, ?)`),
    byId: raw.prepare('SELECT * FROM users WHERE id = ?'),
    byName: raw.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE'),
    list: raw.prepare('SELECT * FROM users ORDER BY created_at, username'),
    count: raw.prepare('SELECT COUNT(*) AS n FROM users'),
    countActiveAdmins: raw.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND disabled = 0"),
    setHash: raw.prepare('UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?'),
    setRole: raw.prepare('UPDATE users SET role = ?, updated_at = ? WHERE id = ?'),
    setDisabled: raw.prepare('UPDATE users SET disabled = ?, updated_at = ? WHERE id = ?'),
    setFailures: raw.prepare('UPDATE users SET failed_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?'),
  };

  return {
    ROLES,
    /** @returns user (public fields) */
    create({ username, passwordHash, role, disabled = false }) {
      if (!ROLES.includes(role)) throw new Error('invalid role');
      const id = newId('usr_');
      const ts = nowIso(clock);
      stmts.insert.run(id, username, passwordHash, role, disabled ? 1 : 0, ts, ts);
      return mapUser(stmts.byId.get(id));
    },
    findById(id) { return mapUser(stmts.byId.get(String(id))); },
    findByUsername(username) { return mapUser(stmts.byName.get(String(username))); },
    /** Internal: returns { user, passwordHash } for credential checks only. */
    findCredentials(username) {
      const row = stmts.byName.get(String(username));
      return row ? { user: mapUser(row), passwordHash: row.password_hash } : null;
    },
    getPasswordHash(id) {
      const row = stmts.byId.get(String(id));
      return row ? row.password_hash : null;
    },
    list() { return stmts.list.all().map(mapUser); },
    count() { return stmts.count.get().n; },
    countActiveAdmins() { return stmts.countActiveAdmins.get().n; },
    setPasswordHash(id, passwordHash) { return stmts.setHash.run(passwordHash, nowIso(clock), id).changes > 0; },
    setRole(id, role) {
      if (!ROLES.includes(role)) throw new Error('invalid role');
      return stmts.setRole.run(role, nowIso(clock), id).changes > 0;
    },
    setDisabled(id, disabled) { return stmts.setDisabled.run(disabled ? 1 : 0, nowIso(clock), id).changes > 0; },
    /** Records login-failure state (persisted so a lockout survives restarts). */
    setFailureState(id, failedAttempts, lockedUntil) {
      return stmts.setFailures.run(failedAttempts, lockedUntil || null, nowIso(clock), id).changes > 0;
    },
    resetFailures(id) { return stmts.setFailures.run(0, null, nowIso(clock), id).changes > 0; },
  };
}

module.exports = { createUsersRepository, publicUser, ROLES };

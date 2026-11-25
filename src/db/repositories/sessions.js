'use strict';
/**
 * Sessions are keyed by the SHA-256 hash of the cookie token; the raw token is never stored.
 * Expiry policy (idle/absolute) is applied by src/auth/sessions.js; this repository only persists.
 */

function mapSession(row) {
  if (!row) return null;
  return {
    tokenHash: row.token_hash,
    userId: row.user_id,
    csrfToken: row.csrf_token,
    clientId: row.client_id,
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at,
    expiresAt: row.expires_at,
  };
}

function createSessionsRepository({ raw }) {
  const stmts = {
    insert: raw.prepare(`INSERT INTO sessions (token_hash, user_id, csrf_token, client_id, created_at, last_seen_at, expires_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?)`),
    get: raw.prepare('SELECT * FROM sessions WHERE token_hash = ?'),
    touch: raw.prepare('UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?'),
    del: raw.prepare('DELETE FROM sessions WHERE token_hash = ?'),
    delUser: raw.prepare('DELETE FROM sessions WHERE user_id = ?'),
    delExpired: raw.prepare('DELETE FROM sessions WHERE expires_at <= ? OR last_seen_at <= ?'),
    countUser: raw.prepare('SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?'),
  };
  return {
    create({ tokenHash, userId, csrfToken, clientId = null, createdAt, expiresAt }) {
      stmts.insert.run(tokenHash, userId, csrfToken, clientId, createdAt, createdAt, expiresAt);
      return mapSession(stmts.get.get(tokenHash));
    },
    get(tokenHash) { return mapSession(stmts.get.get(String(tokenHash))); },
    touch(tokenHash, lastSeenAt) { return stmts.touch.run(lastSeenAt, tokenHash).changes > 0; },
    delete(tokenHash) { return stmts.del.run(String(tokenHash)).changes > 0; },
    deleteForUser(userId) { return stmts.delUser.run(String(userId)).changes; },
    /** Deletes sessions past the absolute expiry or idle since before `idleCutoffIso`. */
    deleteExpired(nowIsoValue, idleCutoffIso) { return stmts.delExpired.run(nowIsoValue, idleCutoffIso).changes; },
    countForUser(userId) { return stmts.countUser.get(String(userId)).n; },
  };
}

module.exports = { createSessionsRepository };

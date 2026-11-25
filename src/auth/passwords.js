'use strict';
const crypto = require('node:crypto');
const { promisify } = require('node:util');

const scrypt = promisify(crypto.scrypt);

const PARAMS = Object.freeze({ N: 16384, r: 8, p: 1, keyLen: 64, saltLen: 16 });
const MIN_LENGTH = 12;
const MAX_LENGTH = 256;
const MAXMEM = 64 * 1024 * 1024;

async function derive(password, salt, { N, r, p, keyLen }) {
  return scrypt(String(password).normalize('NFKC'), salt, keyLen, { N, r, p, maxmem: MAXMEM });
}

async function hashPassword(password) {
  if (typeof password !== 'string' || password.length === 0) throw new TypeError('password must be a non-empty string');
  const salt = crypto.randomBytes(PARAMS.saltLen);
  const key = await derive(password, salt, PARAMS);
  return ['scrypt', PARAMS.N, PARAMS.r, PARAMS.p, salt.toString('base64'), key.toString('base64')].join('$');
}

function parseHash(encoded) {
  if (typeof encoded !== 'string') return null;
  const parts = encoded.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return null;
  const [N, r, p] = parts.slice(1, 4).map(Number);
  // refuse absurd parameters from a tampered row
  if (!Number.isInteger(N) || N < 1024 || N > 1 << 20 || (N & (N - 1)) !== 0) return null;
  if (!Number.isInteger(r) || r < 1 || r > 32 || !Number.isInteger(p) || p < 1 || p > 16) return null;
  const salt = Buffer.from(parts[4], 'base64');
  const key = Buffer.from(parts[5], 'base64');
  if (salt.length < 8 || key.length < 32 || key.length > 128) return null;
  return { N, r, p, salt, key };
}

async function verifyPassword(password, encoded) {
  if (typeof password !== 'string' || password.length === 0 || password.length > MAX_LENGTH) return false;
  const parsed = parseHash(encoded);
  if (!parsed) return false;
  const candidate = await derive(password, parsed.salt, { ...parsed, keyLen: parsed.key.length });
  return candidate.length === parsed.key.length && crypto.timingSafeEqual(candidate, parsed.key);
}

let dummyHashPromise = null;
async function dummyVerify(password) {
  // same cost as a real check so unknown users cannot be told apart by timing
  if (!dummyHashPromise) dummyHashPromise = hashPassword(crypto.randomBytes(16).toString('hex'));
  await verifyPassword(typeof password === 'string' && password ? password.slice(0, MAX_LENGTH) : 'x', await dummyHashPromise);
  return false;
}

function checkPasswordPolicy(password, username) {
  const problems = [];
  if (typeof password !== 'string') return ['must be a string'];
  if (password.length < MIN_LENGTH) problems.push(`must be at least ${MIN_LENGTH} characters`);
  if (password.length > MAX_LENGTH) problems.push(`must be at most ${MAX_LENGTH} characters`);
  if (username && password.trim().toLowerCase() === String(username).trim().toLowerCase()) {
    problems.push('must not be the same as the username');
  }
  if (password.length >= MIN_LENGTH && /^(.)\1*$/.test(password)) problems.push('must not be a single repeated character');
  return problems;
}

function generatePassword() {
  return crypto.randomBytes(18).toString('base64url');
}

module.exports = { PARAMS, MIN_LENGTH, MAX_LENGTH, hashPassword, verifyPassword, dummyVerify, checkPasswordPolicy, generatePassword, parseHash };

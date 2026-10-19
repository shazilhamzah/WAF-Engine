'use strict';
/**
 * Default rule set loader. scripts/setup.js (seeding) and tests use this instead of re-reading the
 * file themselves:
 *
 *   const { loadDefaultRules } = require('./src/rules');
 *   const { rules, errors } = loadDefaultRules();   // rules: [{ id, source, name, severity, category }]
 *
 * Each source is one complete rule, ready for rules.create() / engine.compileRules().
 */

const fs = require('node:fs');
const path = require('node:path');
const { parseRuleFile, validateRuleSource } = require('../engine/dsl');

const DEFAULT_RULES_PATH = path.join(__dirname, 'default.rules');

/**
 * @param {string} [file] path of a .rules file (defaults to default.rules)
 * @returns {{ rules: {id: number, source: string, name: string, severity: string, category: string, score: number}[], errors: object[] }}
 */
function loadDefaultRules(file = DEFAULT_RULES_PATH) {
  const text = fs.readFileSync(file, 'utf8');
  const parsed = parseRuleFile(text);
  const rules = parsed.rules.map((r) => {
    const meta = validateRuleSource(r.source).rule;
    return { id: r.id, source: r.source, name: meta.name, severity: meta.severity, category: meta.category, score: meta.score };
  });
  return { rules, errors: parsed.errors };
}

module.exports = { DEFAULT_RULES_PATH, loadDefaultRules };

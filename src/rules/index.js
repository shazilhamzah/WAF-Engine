'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { parseRuleFile, validateRuleSource } = require('../engine/dsl');

const DEFAULT_RULES_PATH = path.join(__dirname, 'default.rules');

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

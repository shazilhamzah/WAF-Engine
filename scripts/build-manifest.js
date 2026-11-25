#!/usr/bin/env node
'use strict';
// Rebuilds docs/evaluation/manifest.json: SHA-256 of every tracked source file and of the stable
// evidence documents, plus the headline numbers copied from the generated evidence files.
// Text hashes normalize CRLF to LF so a Windows and a Linux checkout agree; PDF/PNG use raw bytes.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const OUT = path.join(ROOT, 'docs', 'evaluation', 'manifest.json');
const SOURCE_PATHS = ['fixtures', 'public', 'scripts', 'src', 'target', 'test', 'package.json', 'package-lock.json'];
const EVIDENCE = [
  'docs/00-project-plan.md', 'docs/01-requirements.md', 'docs/02-architecture.md', 'docs/PROGRESS.md',
  'docs/engine.md', 'docs/evaluation/check-summary.json', 'docs/evaluation/latency.json',
  'docs/evaluation/results.json', 'docs/evaluation/results.md', 'docs/final-report.md', 'docs/fixtures.md',
  'docs/limitations-and-ethics.md', 'docs/test-plan.md', 'docs/test-results.md', 'docs/threat-model.md',
  'docs/traceability.md', 'docs/final-report.pdf', 'docs/user-guide.md', 'docs/wireframes.md',
  'docs/evaluation/ui-review.json', 'docs/images/dashboard-desktop.png', 'docs/images/dashboard-mobile.png',
];
const BINARY = /\.(pdf|png|jpe?g|gif|ico|pptx)$/i;

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

function hashFile(rel) {
  const raw = fs.readFileSync(path.join(ROOT, rel));
  if (BINARY.test(rel)) return sha256(raw);
  return sha256(Buffer.from(raw.toString('utf8').replace(/\r\n/g, '\n'), 'utf8'));
}

function trackedSourceFiles() {
  const out = execFileSync('git', ['ls-files', '--', ...SOURCE_PATHS], { cwd: ROOT, encoding: 'utf8' });
  return out.split('\n').filter(Boolean).sort();
}

function pdfPageCount(rel) {
  const text = fs.readFileSync(path.join(ROOT, rel)).toString('latin1');
  return (text.match(/\/Type\s*\/Page(?![s\w])/g) || []).length;
}

function readJson(rel) { return JSON.parse(fs.readFileSync(path.join(ROOT, rel), 'utf8')); }

function main() {
  const sourceFiles = trackedSourceFiles().map((p) => ({ path: p, sha256: hashFile(p) }));
  const evidenceFiles = EVIDENCE.filter((p) => fs.existsSync(path.join(ROOT, p))).map((p) => ({ path: p, sha256: hashFile(p) }));
  const check = readJson('docs/evaluation/check-summary.json');
  const results = readJson('docs/evaluation/results.json');
  const cls = results.metrics.classification;
  const vuln = check.npmAudit.vulnerabilities;
  const manifest = {
    generatedAt: new Date().toISOString(),
    description: 'Source/evidence snapshot built by scripts/build-manifest.js. Text hashes normalize CRLF to LF; PDF/PNG hashes use raw bytes. '
      + 'sourceTreeSha256 is the SHA-256 of the sha256sum-style listing ("<sha256>  <path>\\n" per source file, sorted by path). '
      + 'Runtime data, credentials, dependencies, Git metadata and temporary files are excluded.',
    sourceTreeSha256: sha256(sourceFiles.map((f) => `${f.sha256}  ${f.path}\n`).join('')),
    sourceFiles,
    evidenceFiles,
    verification: {
      automatedTests: check.tests.tests,
      passed: check.tests.pass,
      failed: check.tests.fail,
      skipped: check.tests.skipped,
      criticalHighProductionAdvisories: vuln.critical + vuln.high,
      checkGeneratedAt: check.generatedAt,
      mandatoryChecks: results.totals.total,
      mandatoryPassed: results.totals.passed,
      mandatoryFailed: results.totals.failed,
      evaluationGeneratedAt: results.generatedAt,
      corpusTruePositives: cls.tp,
      corpusTrueNegatives: cls.tn,
      corpusFalsePositives: cls.fp,
      corpusFalseNegatives: cls.fn,
      pdfPages: pdfPageCount('docs/final-report.pdf'),
      uiReview: 'docs/evaluation/ui-review.json',
    },
    scopeException: 'The separate 10-15 minute demonstration/walkthrough was explicitly excluded by the user.',
  };
  fs.writeFileSync(OUT, JSON.stringify(manifest, null, 2) + '\n');
  console.log(`[manifest] ${sourceFiles.length} source + ${evidenceFiles.length} evidence files → ${path.relative(ROOT, OUT)}`);
  console.log(`[manifest] sourceTreeSha256 ${manifest.sourceTreeSha256}`);
}

if (require.main === module) main();
module.exports = { hashFile };

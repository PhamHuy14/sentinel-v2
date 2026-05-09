// engine/scanner/rule-engine.js

// ── A01 ──────────────────────────────────────────────────────────────────────
const { runAllA01Rules } = require('../rules/a01');

// ── A02 ──────────────────────────────────────────────────────────────────────
const { runAllA02Rules } = require('../rules/a02');

// ── A03 ──────────────────────────────────────────────────────────────────────
const { runAllA03Rules } = require('../rules/a03');
const { runSensitiveDataInLogs, runStructuredLogging } = require('../rules/source-enhanced/supply-chain-enhanced');

// ── A04 ──────────────────────────────────────────────────────────────────────
const { runA04Rules } = require('../rules/a04');

// ── A05 ──────────────────────────────────────────────────────────────────────
const { runAllA05Rules } = require('../rules/a05');

// ── A06 ──────────────────────────────────────────────────────────────────────
const { runAllA06Rules } = require('../rules/a06');

// ── A07 ──────────────────────────────────────────────────────────────────────
const { runAllA07Rules } = require('../rules/a07');

// ── A08 ──────────────────────────────────────────────────────────────────────
const { runAllA08Rules } = require('../rules/a08');

// ── A09 ──────────────────────────────────────────────────────────────────────
const { runAuthEventLogging } = require('../rules/a09/auth-event-logging');
const { runAlertingCheck } = require('../rules/a09/alerting-check');

// ── A10 ──────────────────────────────────────────────────────────────────────
const { runExceptionLeakage } = require('../rules/a10/exception-leakage');
const { runMalformedInput } = require('../rules/a10/malformed-input');

// ── Generic ──────────────────────────────────────────────────────────────────
const { runGenericProjectChecks } = require('../rules/generic/generic-project-checks');

function deduplicateFindings(findings) {
  const seen = new Set();
  return findings.filter(f => {
    const key = `${f.ruleId}:${f.target}:${f.location}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function runUrlRules(context) {
  const findings = [
    ...runAllA01Rules(context),
    ...runAllA02Rules(context),
    ...runAllA03Rules(context),
    ...runA04Rules(context),
    ...runAllA05Rules(context),
    ...runAllA06Rules(context),
    ...runAllA07Rules(context),
    ...runAllA08Rules(context),
    ...runMalformedInput(context),
    ...runExceptionLeakage(context),
  ];
  return deduplicateFindings(findings);
}

function runProjectRules(context) {
  const findings = [
    ...runAllA03Rules(context),
    ...runA04Rules(context),
    ...runAllA05Rules(context),
    ...runAllA06Rules(context),
    ...runAllA08Rules(context),
    ...runAuthEventLogging(context),
    ...runAlertingCheck(context),
    ...runSensitiveDataInLogs(context),
    ...runStructuredLogging(context),
    ...runGenericProjectChecks(context),
  ];
  return deduplicateFindings(findings);
}

module.exports = { runUrlRules, runProjectRules };

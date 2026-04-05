// engine/scanner/rule-engine.js

// ── A01 ──────────────────────────────────────────────────────────────────────
const { runCsrfHeuristic } = require('../rules/a01/csrf-heuristic');
const { runIdorHeuristic } = require('../rules/a01/idor-heuristic');
const { runForcedBrowsing } = require('../rules/a01/forced-browsing');
const { runJwtWeakness, runPathTraversalHeuristic, runSensitiveEndpointExposure, runMassAssignmentHeuristic } = require('../rules/a01/access-control-enhanced');

// ── A02 ──────────────────────────────────────────────────────────────────────
const { runMissingSecurityHeaders } = require('../rules/a02/missing-security-headers');
const { runCookieFlags } = require('../rules/a02/cookie-flags');
const { runCorsMisconfig } = require('../rules/a02/cors-misconfig');
const { runDangerousMethods } = require('../rules/a02/dangerous-methods');
const { runDebugExposure } = require('../rules/a02/debug-exposure');

// ── A03 ──────────────────────────────────────────────────────────────────────
const { runNpmDependencyRisk } = require('../rules/a03/npm-dependency-risk');
const { runNugetDependencyRisk } = require('../rules/a03/nuget-dependency-risk');
const { runPackageLockConsistency, runTyposquattingRisk, runCiCdSecurityGates, runSensitiveDataInLogs, runStructuredLogging } = require('../rules/source-enhanced/supply-chain-enhanced');

// ── A04 ──────────────────────────────────────────────────────────────────────
const { runHttpInsecure, runSensitiveDataExposure, runMixedContent, runCookieSecureOnHttps } = require('../rules/a04/crypto-failures');

// ── A05 ──────────────────────────────────────────────────────────────────────
const { runReflectedXss } = require('../rules/a05/reflected-xss');
const { runSqliErrorBased } = require('../rules/a05/sqli-error-based');
const { runCommandInjectionHeuristic } = require('../rules/a05/command-injection-heuristic');
const { runSstiHeuristic, runSqliEnhanced, runNoSqliHeuristic, runXxeHeuristic, runPrototypePollutionHeuristic } = require('../rules/a05/injection-enhanced');

// ── A07 ──────────────────────────────────────────────────────────────────────
const { runAccountEnumeration } = require('../rules/a07/account-enumeration');
const { runSessionFixation } = require('../rules/a07/session-fixation');
const { runResetFlow } = require('../rules/a07/reset-flow');
const { runBruteForceProtection, runPasswordPolicyHeuristic, runDefaultCredentialsHint, runSessionManagement, runMfaPresence } = require('../rules/a07/auth-enhanced');

// ── A08 ──────────────────────────────────────────────────────────────────────
const { runMissingIntegrityCheck } = require('../rules/a08/missing-integrity-check');
const { runUntrustedConfigData } = require('../rules/a08/untrusted-config-data');

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
    ...runCsrfHeuristic(context),
    ...runIdorHeuristic(context),
    ...runForcedBrowsing(context),
    ...runSensitiveEndpointExposure(context),
    ...runJwtWeakness(context),
    ...runPathTraversalHeuristic(context),
    ...runMassAssignmentHeuristic(context),
    ...runMissingSecurityHeaders(context),
    ...runCookieFlags(context),
    ...runCorsMisconfig(context),
    ...runDangerousMethods(context),
    ...runDebugExposure(context),
    ...runHttpInsecure(context),
    ...runSensitiveDataExposure(context),
    ...runMixedContent(context),
    ...runCookieSecureOnHttps(context),
    ...runReflectedXss(context),
    ...runSqliErrorBased(context),
    ...runSqliEnhanced(context),
    ...runCommandInjectionHeuristic(context),
    ...runSstiHeuristic(context),
    ...runNoSqliHeuristic(context),
    ...runXxeHeuristic(context),
    ...runPrototypePollutionHeuristic(context),
    ...runAccountEnumeration(context),
    ...runSessionFixation(context),
    ...runResetFlow(context),
    ...runBruteForceProtection(context),
    ...runPasswordPolicyHeuristic(context),
    ...runDefaultCredentialsHint(context),
    ...runSessionManagement(context),
    ...runMfaPresence(context),
    ...runMalformedInput(context),
    ...runExceptionLeakage(context),
  ];
  return deduplicateFindings(findings);
}

function runProjectRules(context) {
  const findings = [
    ...runNpmDependencyRisk(context),
    ...runNugetDependencyRisk(context),
    ...runPackageLockConsistency(context),
    ...runTyposquattingRisk(context),
    ...runMissingIntegrityCheck(context),
    ...runUntrustedConfigData(context),
    ...runCiCdSecurityGates(context),
    ...runAuthEventLogging(context),
    ...runAlertingCheck(context),
    ...runSensitiveDataInLogs(context),
    ...runStructuredLogging(context),
    ...runGenericProjectChecks(context),
  ];
  return deduplicateFindings(findings);
}

module.exports = { runUrlRules, runProjectRules };

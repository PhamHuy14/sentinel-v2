/**
 * Chỉ mục quy tắc A08 — Software and Data Integrity Failures
 * Tham chiếu: OWASP Top 10 2025 A08, CWE-502, CWE-1357
 *
 * Cách dùng:
 *   const { runAllA08Rules } = require('./engine/rules/a08');
 *   const findings = runAllA08Rules(context);
 */

'use strict';

const { runMissingIntegrityCheck } = require('./missing-integrity-check');
const { runUntrustedConfigData }   = require('./untrusted-config-data');
const { runDeserializationHeuristic } = require('./deserialization');
const { runCiPipelineSecurity }    = require('./ci-pipeline-security');

const ALL_A08_RULES = [
  // ── Blackbox (response analysis) ─────────────────────────────────────────
  { fn: runDeserializationHeuristic, name: 'DeserializationResponse', owasp: 'CWE-502'     },

  // ── Source code analysis ─────────────────────────────────────────────────
  { fn: runMissingIntegrityCheck,    name: 'SRI-Integrity',           owasp: 'WSTG-CONF-11' },
  { fn: runUntrustedConfigData,      name: 'UntrustedConfig',         owasp: 'CWE-502'      },
  { fn: runCiPipelineSecurity,       name: 'CiPipelineSecurity',      owasp: 'CWE-1357'     },
];

/**
 * Chạy toàn bộ quy tắc A08, trả về findings đã khử trùng lặp.
 * @param {object} context
 * @returns {Array}
 */
function runAllA08Rules(context) {
  const allFindings = [];
  const seenKeys = new Set();

  for (const { fn, name } of ALL_A08_RULES) {
    try {
      const results = fn(context) || [];
      for (const finding of results) {
        const key = `${finding.ruleId}::${finding.target}`;
        if (!seenKeys.has(key)) {
          seenKeys.add(key);
          allFindings.push(finding);
        }
      }
    } catch (err) {
      if (process.env.DEBUG_RULES) {
        console.error(`[A08 Rules] Error in ${name}:`, err.message);
      }
    }
  }

  return allFindings;
}

module.exports = {
  runAllA08Rules,
  runMissingIntegrityCheck,
  runUntrustedConfigData,
  runDeserializationHeuristic,
  runCiPipelineSecurity,
};

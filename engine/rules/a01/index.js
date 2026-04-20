/**
 * A01 Rules Index
 * ═══════════════════════════════════════════════════════════════════════════
 * Tập hợp tất cả rules cho OWASP A01 - Broken Access Control
 *
 * CÁCH SỬ DỤNG:
 * Require file này và gọi runAllA01Rules(context) để chạy toàn bộ,
 * hoặc require từng module riêng lẻ.
 */

'use strict';

const { runJwtWeakness, runPathTraversalHeuristic, runSensitiveEndpointExposure, runMassAssignmentHeuristic } = require('./access-control-enhanced');
const { runCsrfHeuristic } = require('./csrf-heuristic');
const { runForcedBrowsing } = require('./forced-browsing');
const { runIdorHeuristic } = require('./idor-heuristic');
const { runPrivilegeEscalationHeuristic } = require('./privilege-escalation');
const { runAuthBypassHeuristic } = require('./auth-bypass');
const { runHttpVerbTampering } = require('./http-verb-tampering');
const { runSessionManagementHeuristic } = require('./session-management');
const { runSecurityHeadersHeuristic } = require('./security-headers');

/**
 * Danh sách tất cả rules theo thứ tự ưu tiên.
 * Mỗi entry: { fn, name, owasp }
 */
const ALL_A01_RULES = [
  // ── Critical / High confidence ──────────────────────────────────────────
  { fn: runPathTraversalHeuristic,       name: 'PathTraversal',         owasp: 'OTG-AUTHZ-001' },
  { fn: runAuthBypassHeuristic,          name: 'AuthBypass',            owasp: 'OTG-AUTHN-004' },
  { fn: runPrivilegeEscalationHeuristic, name: 'PrivilegeEscalation',   owasp: 'OTG-AUTHZ-003' },
  { fn: runJwtWeakness,                  name: 'JwtWeakness',           owasp: 'OTG-AUTHN'     },

  // ── Access control surface ───────────────────────────────────────────────
  { fn: runSensitiveEndpointExposure,    name: 'SensitiveEndpoint',     owasp: 'OTG-CONFIG-005' },
  { fn: runForcedBrowsing,               name: 'ForcedBrowsing',        owasp: 'OTG-AUTHZ-002' },
  { fn: runIdorHeuristic,                name: 'IDOR',                  owasp: 'OTG-AUTHZ-004' },
  { fn: runMassAssignmentHeuristic,      name: 'MassAssignment',        owasp: 'OTG-AUTHZ-003' },

  // ── Session & CSRF ──────────────────────────────────────────────────────
  { fn: runSessionManagementHeuristic,   name: 'SessionManagement',     owasp: 'OTG-SESS-001'  },
  { fn: runCsrfHeuristic,                name: 'CSRF',                  owasp: 'OTG-SESS-005'  },

  // ── HTTP configuration ──────────────────────────────────────────────────
  { fn: runHttpVerbTampering,            name: 'HttpVerbTampering',     owasp: 'OTG-CONFIG-006' },
  { fn: runSecurityHeadersHeuristic,     name: 'SecurityHeaders',       owasp: 'OTG-AUTHN-006' },
];

/**
 * Chạy tất cả A01 rules và trả về array findings (flattened, deduplicated).
 * @param {object} context
 * @returns {Array} findings
 */
function runAllA01Rules(context) {
  const allFindings = [];
  const seenEvidence = new Set();

  for (const { fn, name } of ALL_A01_RULES) {
    try {
      const results = fn(context) || [];
      for (const finding of results) {
        // Simple dedup: same ruleId + same target
        const key = `${finding.ruleId}::${finding.target}`;
        if (!seenEvidence.has(key)) {
          seenEvidence.add(key);
          allFindings.push(finding);
        }
      }
    } catch (err) {
      // Don't let one rule crash the whole pipeline
      if (process.env.DEBUG_RULES) {
        console.error(`[A01 Rules] Error in ${name}:`, err.message);
      }
    }
  }

  return allFindings;
}

module.exports = {
  runAllA01Rules,
  // Also export individual runners for selective use
  runJwtWeakness,
  runPathTraversalHeuristic,
  runSensitiveEndpointExposure,
  runMassAssignmentHeuristic,
  runCsrfHeuristic,
  runForcedBrowsing,
  runIdorHeuristic,
  runPrivilegeEscalationHeuristic,
  runAuthBypassHeuristic,
  runHttpVerbTampering,
  runSessionManagementHeuristic,
  runSecurityHeadersHeuristic,
};

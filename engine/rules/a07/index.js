/**
 * Chỉ mục quy tắc A07 — Identification and Authentication Failures
 * Tham chiếu: OWASP Top 10 2025 A07, WSTG-ATHN, WSTG-SESS, WSTG-IDNT
 *
 * Cách dùng:
 *   const { runAllA07Rules } = require('./engine/rules/a07');
 *   const findings = runAllA07Rules(context);
 */

'use strict';

const { runAccountEnumeration } = require('./account-enumeration');
const {
  runBruteForceProtection,
  runPasswordPolicyHeuristic,
  runDefaultCredentialsHint,
  runSessionManagement,
  runMfaPresence,
  runTokenInUrl,
  runOAuthMisconfig,
  runWeakSessionEntropy,
} = require('./auth-enhanced');
const { runResetFlow } = require('./reset-flow');
const { runSessionFixation } = require('./session-fixation');

/**
 * Danh sách toàn bộ quy tắc theo thứ tự ưu tiên.
 */
const ALL_A07_RULES = [
  // ── Critical / Credential Issues ────────────────────────────────────────
  { fn: runTokenInUrl,               name: 'TokenInUrl',          owasp: 'WSTG-ATHN-03'  },
  { fn: runOAuthMisconfig,           name: 'OAuthMisconfig',      owasp: 'WSTG-ATHN-05'  },
  { fn: runDefaultCredentialsHint,   name: 'DefaultCredentials',  owasp: 'WSTG-ATHN-02'  },

  // ── Session Management ───────────────────────────────────────────────────
  { fn: runSessionFixation,          name: 'SessionFixation',     owasp: 'WSTG-SESS-03'  },
  { fn: runWeakSessionEntropy,       name: 'WeakSessionEntropy',  owasp: 'WSTG-SESS-01'  },
  { fn: runSessionManagement,        name: 'SessionManagement',   owasp: 'WSTG-SESS-07'  },

  // ── Authentication Controls ──────────────────────────────────────────────
  { fn: runBruteForceProtection,     name: 'BruteForce',          owasp: 'WSTG-ATHN-03'  },
  { fn: runAccountEnumeration,       name: 'AccountEnumeration',  owasp: 'WSTG-IDNT-04'  },
  { fn: runMfaPresence,              name: 'MfaPresence',         owasp: 'WSTG-ATHN-06'  },

  // ── Password & Reset ─────────────────────────────────────────────────────
  { fn: runResetFlow,                name: 'ResetFlow',           owasp: 'WSTG-ATHN-09'  },
  { fn: runPasswordPolicyHeuristic,  name: 'PasswordPolicy',      owasp: 'WSTG-ATHN-07'  },
];

/**
 * Chạy toàn bộ quy tắc A07, trả về findings đã khử trùng lặp.
 * @param {object} context
 * @returns {Array}
 */
function runAllA07Rules(context) {
  const allFindings = [];
  const seenKeys = new Set();

  for (const { fn, name } of ALL_A07_RULES) {
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
        console.error(`[A07 Rules] Error in ${name}:`, err.message);
      }
    }
  }

  return allFindings;
}

module.exports = {
  runAllA07Rules,
  runAccountEnumeration,
  runBruteForceProtection,
  runPasswordPolicyHeuristic,
  runDefaultCredentialsHint,
  runSessionManagement,
  runMfaPresence,
  runTokenInUrl,
  runOAuthMisconfig,
  runWeakSessionEntropy,
  runResetFlow,
  runSessionFixation,
};

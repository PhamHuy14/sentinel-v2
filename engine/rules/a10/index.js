'use strict';

/**
 * Chỉ mục quy tắc A10 — Server-Side Request Forgery (SSRF)
 * Tham chiếu: OWASP Top 10 2025 A10, WSTG-INPV-19, CWE-918
 *
 * OWASP A10:2025 = SSRF (Server-Side Request Forgery)
 * Rule exception-leakage và malformed-input được giữ lại vì
 * liên quan đến "mishandling exceptional conditions" khi xử lý SSRF response.
 */

const { runSsrfHeuristic }    = require('./ssrf-heuristic');
const { runSsrfSource }       = require('./ssrf-source');
const { runExceptionLeakage } = require('./exception-leakage');
const { runMalformedInput }   = require('./malformed-input');

const ALL_A10_RULES = [
  // ── SSRF — core A10:2025 ─────────────────────────────────────────────────
  { fn: runSsrfHeuristic,    name: 'SSRF-Blackbox', owasp: 'WSTG-INPV-19' },
  { fn: runSsrfSource,       name: 'SSRF-Source',   owasp: 'CWE-918'      },
  // ── Exception / Error Handling (supplementary) ───────────────────────────
  { fn: runExceptionLeakage, name: 'ExceptionLeak', owasp: 'CWE-209'      },
  { fn: runMalformedInput,   name: 'MalformedInput', owasp: 'CWE-755'     },
];

function runAllA10Rules(context) {
  const allFindings = [];
  const seenKeys = new Set();

  for (const { fn, name } of ALL_A10_RULES) {
    try {
      const results = fn(context) || [];
      for (const f of results) {
        const key = `${f.ruleId}::${f.target}`;
        if (!seenKeys.has(key)) { seenKeys.add(key); allFindings.push(f); }
      }
    } catch (err) {
      if (process.env.DEBUG_RULES) console.error(`[A10] Error in ${name}:`, err.message);
    }
  }
  return allFindings;
}

module.exports = {
  runAllA10Rules,
  runSsrfHeuristic,
  runSsrfSource,
  runExceptionLeakage,
  runMalformedInput,
};

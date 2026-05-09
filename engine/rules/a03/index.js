/**
 * Chỉ mục quy tắc A03 — Injection.
 *
 * Lưu ý: các implementation injection hiện vẫn nằm trong thư mục a05 để giữ
 * tương thích với các import cũ. Index này remap output về đúng OWASP 2025 A03.
 */

'use strict';

const { runCommandInjectionHeuristic } = require('../a05/command-injection-heuristic');
const {
  runSstiHeuristic,
  runSqliEnhanced,
  runNoSqliHeuristic,
  runXxeHeuristic,
  runPrototypePollutionHeuristic,
  runLdapInjectionHeuristic,
  runXpathInjectionHeuristic,
  runCrlfHeuristic,
  runLog4ShellHeuristic,
  runSsrfHeuristic,
} = require('../a05/injection-enhanced');
const { runReflectedXss, runXssPassiveHeuristic } = require('../a05/reflected-xss');
const { runSqliErrorBased } = require('../a05/sqli-error-based');
const { remapFindings } = require('../remap-finding');

const A03_REF = 'https://owasp.org/Top10/2025/A03_2025-Injection/';

const ALL_A03_RULES = [
  { fn: runLog4ShellHeuristic,          name: 'Log4Shell' },
  { fn: runCommandInjectionHeuristic,   name: 'CommandInjection' },
  { fn: runSstiHeuristic,               name: 'SSTI' },
  { fn: runSqliEnhanced,                name: 'SQLi-Enhanced' },
  { fn: runSqliErrorBased,              name: 'SQLi-ErrorBased' },
  { fn: runNoSqliHeuristic,             name: 'NoSQLi' },
  { fn: runLdapInjectionHeuristic,      name: 'LDAPInjection' },
  { fn: runXpathInjectionHeuristic,     name: 'XPathInjection' },
  { fn: runReflectedXss,                name: 'ReflectedXSS' },
  { fn: runXssPassiveHeuristic,         name: 'XSS-Passive' },
  { fn: runXxeHeuristic,                name: 'XXE' },
  { fn: runCrlfHeuristic,               name: 'CRLF' },
  { fn: runPrototypePollutionHeuristic, name: 'PrototypePollution' },
];

function runAllA03Rules(context) {
  const allFindings = [];
  const seenKeys = new Set();

  for (const { fn, name } of ALL_A03_RULES) {
    try {
      const results = remapFindings(fn(context) || [], {
        fromCategory: 'A05',
        toCategory: 'A03',
        top10Url: A03_REF,
      });

      for (const finding of results) {
        const key = `${finding.ruleId}::${finding.target}`;
        if (!seenKeys.has(key)) {
          seenKeys.add(key);
          allFindings.push(finding);
        }
      }
    } catch (err) {
      if (process.env.DEBUG_RULES) {
        console.error(`[A03 Rules] Error in ${name}:`, err.message);
      }
    }
  }

  return allFindings;
}

module.exports = {
  runAllA03Rules,
  runCommandInjectionHeuristic,
  runSstiHeuristic,
  runSqliEnhanced,
  runSqliErrorBased,
  runNoSqliHeuristic,
  runXxeHeuristic,
  runPrototypePollutionHeuristic,
  runLdapInjectionHeuristic,
  runXpathInjectionHeuristic,
  runCrlfHeuristic,
  runLog4ShellHeuristic,
  runSsrfHeuristic,
  runReflectedXss,
  runXssPassiveHeuristic,
};

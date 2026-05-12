'use strict';

/**
 * Chỉ mục quy tắc A09 — Security Logging and Monitoring Failures
 * Tham chiếu: OWASP Top 10 2025 A09, WSTG-LOG, CWE-117, CWE-532
 */

const { runAlertingCheck }        = require('./alerting-check');
const { runAuthEventLogging }     = require('./auth-event-logging');
const { runLogInjection }         = require('./log-injection');
const { runSensitiveDataInLogs }  = require('./sensitive-data-in-logs');

const ALL_A09_RULES = [
  { fn: runSensitiveDataInLogs, name: 'SensitiveDataInLogs', owasp: 'CWE-532'   },
  { fn: runLogInjection,        name: 'LogInjection',        owasp: 'CWE-117'   },
  { fn: runAuthEventLogging,    name: 'AuthEventLogging',    owasp: 'WSTG-LOG'  },
  { fn: runAlertingCheck,       name: 'AlertingCheck',       owasp: 'WSTG-LOG'  },
];

function runAllA09Rules(context) {
  const allFindings = [];
  const seenKeys = new Set();

  for (const { fn, name } of ALL_A09_RULES) {
    try {
      const results = fn(context) || [];
      for (const f of results) {
        const key = `${f.ruleId}::${f.target}`;
        if (!seenKeys.has(key)) { seenKeys.add(key); allFindings.push(f); }
      }
    } catch (err) {
      if (process.env.DEBUG_RULES) console.error(`[A09] Error in ${name}:`, err.message);
    }
  }
  return allFindings;
}

module.exports = {
  runAllA09Rules,
  runAlertingCheck,
  runAuthEventLogging,
  runLogInjection,
  runSensitiveDataInLogs,
};

const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện thiếu Alerting / Monitoring
 * Tham chiếu OWASP WSTG: WSTG-INPV-15, A09:2025
 *
 * Nâng cấp so với bản gốc (chỉ 1 check, regex quá rộng):
 *  1. Phân tách: monitoring framework vs alerting vs log level config
 *  2. Phát hiện debug/verbose logging bật trong production config
 *  3. Phát hiện error suppression (catch blocks nuốt lỗi)
 *  4. Phát hiện console.log dùng cho security events (antipattern)
 */

const MONITORING_FRAMEWORKS = [
  // APM / centralized logging
  { re: /serilog|nlog|log4net|microsoft\.extensions\.logging/i,   label: 'Serilog/NLog/Log4Net (.NET)' },
  { re: /winston|pino|bunyan|morgan|log4js/i,                      label: 'Winston/Pino/Bunyan (Node.js)' },
  { re: /logback|log4j2?|slf4j|java\.util\.logging/i,             label: 'Logback/Log4j (Java)' },
  { re: /logging\.getLogger|structlog|loguru|python-json-logger/i, label: 'Python logging framework' },
  // SIEM / alerting
  { re: /splunk|elastic(?:search)?|kibana|datadog|newrelic/i,      label: 'SIEM/APM (Splunk/Elastic/Datadog)' },
  { re: /pagerduty|opsgenie|victorops|alertmanager/i,              label: 'Alerting platform' },
  { re: /sentry|bugsnag|rollbar|raygun|honeybadger/i,              label: 'Error tracking (Sentry/Bugsnag)' },
  { re: /prometheus|grafana|opentelemetry|jaeger/i,                label: 'Metrics/tracing (Prometheus/OpenTelemetry)' },
];

// Pattern log level bị set debug/verbose trong config production
const DEBUG_LOG_PATTERNS = [
  { re: /["']log(?:Level|_level)["']\s*:\s*["'](?:debug|verbose|trace)["']/i,
    label: 'Log level "debug/verbose/trace" trong config — quá chi tiết cho production' },
  { re: /MinimumLevel\s*:\s*(?:Debug|Verbose|Trace)/i,
    label: 'Serilog MinimumLevel Debug/Verbose — không phù hợp production' },
  { re: /logging\.level\s*=\s*(?:DEBUG|ALL|TRACE)/i,
    label: 'Log level DEBUG/ALL/TRACE trong config' },
  { re: /\bVERBOSE\s*=\s*true\b|\bDEBUG\s*=\s*true\b/,
    label: 'DEBUG/VERBOSE=true trong environment config' },
];

// Pattern nuốt lỗi không log (error suppression)
const ERROR_SUPPRESSION_PATTERNS = [
  { re: /catch\s*\([^)]*\)\s*\{\s*\}/,
    label: 'Empty catch block — lỗi bị nuốt hoàn toàn, không log' },
  { re: /catch\s*\([^)]*\)\s*\{\s*\/\/.{0,40}\s*\}/,
    label: 'Catch block chỉ có comment — lỗi không được log hay xử lý' },
  { re: /except\s+(?:Exception|BaseException)\s*:\s*pass/,
    label: 'Python bare except: pass — nuốt mọi exception không log' },
  { re: /except\s*:\s*pass/,
    label: 'Python bare except: pass — nuốt exception không log' },
];

function runAlertingCheck(context) {
  const findings = [];
  const codeFiles  = context.codeFiles  || [];
  const configFiles = context.configFiles || [];
  const allFiles   = [...codeFiles, ...configFiles];

  const corpus = allFiles.map(f => `${f?.path || ''}\n${f?.content || ''}`).join('\n');

  // ── 1. Kiểm tra monitoring framework tổng thể ─────────────────────────────
  const foundMonitoring = MONITORING_FRAMEWORKS.filter(({ re }) => re.test(corpus));
  if (foundMonitoring.length === 0) {
    findings.push(normalizeFinding({
      ruleId: 'A09-ALERT-001',
      owaspCategory: 'A09',
      title: 'Không phát hiện monitoring / logging framework trong codebase',
      severity: 'medium',
      confidence: 'low',
      target: 'project source',
      location: 'codebase',
      evidence: [
        'Không thấy logging framework (Winston, Serilog, Log4j, Python logging...) hoặc alerting platform (Sentry, Datadog, PagerDuty...).',
        'Thiếu centralized logging khiến không thể phát hiện tấn công hoặc điều tra sự cố.',
      ],
      remediation:
        'Tích hợp logging framework phù hợp: Winston/Pino (Node.js), Serilog (C#), Logback (Java), logging (Python). ' +
        'Gửi logs đến centralized platform: ELK Stack, Splunk, Datadog. ' +
        'Tích hợp error tracking: Sentry, Bugsnag.',
      references: [
        'https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Monitoring_Failures/',
        'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html',
      ],
      collector: 'source',
    }));
  }

  // ── 2. Phát hiện debug logging bật trong config ────────────────────────────
  for (const file of configFiles) {
    const content = file?.content || '';
    const path    = file?.path    || '';
    // Bỏ qua file development rõ ràng
    if (/dev(?:elopment)?|local|test/i.test(path)) continue;

    for (const { re, label } of DEBUG_LOG_PATTERNS) {
      if (re.test(content)) {
        findings.push(normalizeFinding({
          ruleId: 'A09-ALERT-002',
          owaspCategory: 'A09',
          title: 'Log level Debug/Verbose có thể bật trong production config',
          severity: 'medium',
          confidence: 'medium',
          target: path,
          location: path,
          evidence: [
            label,
            'Debug logging tiết lộ thông tin nhạy cảm (query, token, PII) ra log — tăng bề mặt tấn công.',
          ],
          remediation:
            'Set log level = Information (hoặc Warning) trong production. ' +
            'Dùng environment-specific config: appsettings.Production.json, .env.production.',
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#which-events-to-log',
          ],
          collector: 'source',
        }));
        break;
      }
    }
  }

  // ── 3. Phát hiện error suppression ────────────────────────────────────────
  for (const file of codeFiles) {
    const content = file?.content || '';
    const path    = file?.path    || '';
    const suppressMatches = ERROR_SUPPRESSION_PATTERNS.filter(({ re }) => re.test(content));
    if (suppressMatches.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A09-ALERT-003',
        owaspCategory: 'A09',
        title: 'Phát hiện error suppression (empty catch / bare except) — lỗi bị nuốt không log',
        severity: 'low',
        confidence: 'low',
        target: path,
        location: path,
        evidence: suppressMatches.map(m => m.label),
        remediation:
          'Log exception trong catch block ít nhất ở level Warning/Error. ' +
          'Không để catch block rỗng hoặc chỉ có comment. ' +
          'Python: dùng `logging.exception("msg")` trong except.',
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html',
          'https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Monitoring_Failures/',
        ],
        collector: 'source',
      }));
      break; // 1 finding per codebase để tránh spam
    }
  }

  // ── 4. console.log dùng cho security events ────────────────────────────────
  const hasConsoleSecurity = codeFiles.some(f => {
    const c = f?.content || '';
    return /console\.log\s*\(.*(?:password|token|auth|login|error|fail|exception)/i.test(c);
  });
  const hasProperLogger = MONITORING_FRAMEWORKS.slice(0, 5).some(({ re }) => re.test(corpus));

  if (hasConsoleSecurity && !hasProperLogger) {
    findings.push(normalizeFinding({
      ruleId: 'A09-ALERT-004',
      owaspCategory: 'A09',
      title: 'Security event được log bằng console.log thay vì logging framework',
      severity: 'low',
      confidence: 'low',
      target: 'project source',
      location: 'codebase',
      evidence: [
        'console.log được dùng cho security-related messages (auth, token, error).',
        'console.log không hỗ trợ: log level, structured format, centralized shipping, log rotation.',
      ],
      remediation:
        'Thay console.log bằng logging framework (Winston, Pino). ' +
        'Dùng structured logging với JSON format để dễ parse bởi SIEM.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html'],
      collector: 'source',
    }));
  }

  return findings;
}

module.exports = { runAlertingCheck };

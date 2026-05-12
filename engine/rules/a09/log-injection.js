const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện Log Injection / Log Forging
 * Tham chiếu OWASP WSTG: WSTG-INPV-18, CWE-117
 *
 * Log Injection: attacker chèn ký tự CRLF vào input → giả mạo log entries.
 * Ví dụ: username = "admin\nINFO 2025-01-01 Login success user=admin"
 * → Làm log reader tin là admin đăng nhập thành công.
 *
 * Phát hiện:
 *  1. Source: user input được đưa vào log mà không sanitize CRLF
 *  2. Source: log statement nối chuỗi trực tiếp với req.params/query/body
 *  3. Blackbox: CRLF trong response hint log forging qua URL
 */

// Pattern: log statement nối trực tiếp với user-controlled input (source)
const LOG_INJECTION_SOURCE = [
  // Node.js / JavaScript
  {
    re: /(?:logger|log|console)\.\w+\s*\(`[^`]*\$\{(?:req\.|request\.|params\.|query\.|body\.|user\.|input)[^}]*\}/i,
    label: 'Template literal log với req/query/body — user input có thể chứa CRLF',
    lang: 'JavaScript',
  },
  {
    re: /(?:logger|log|console)\.\w+\s*\([^)]*\+\s*(?:req\.|request\.|params\.|query\.|body\.)/i,
    label: 'String concatenation log với req/query/body — không sanitize CRLF',
    lang: 'JavaScript',
  },
  // Python
  {
    re: /logging\.\w+\s*\(\s*[f"'].*\{(?:request\.|req\.|params\.|user_input|username|email)[^}]*\}/i,
    label: 'Python f-string log với request data — cần strip newlines',
    lang: 'Python',
  },
  {
    re: /logging\.\w+\s*\(\s*["'][^"']*%s[^"']*["']\s*%\s*(?:request\.|req\.|username|email)/i,
    label: 'Python % format log với user data',
    lang: 'Python',
  },
  // Java
  {
    re: /(?:log(?:ger)?|LOG)\.\w+\s*\(\s*["'][^"']*["']\s*\+\s*(?:request\.|req\.|username|param|query)/i,
    label: 'Java log string concat với request param — CRLF injection risk',
    lang: 'Java',
  },
  // PHP
  {
    re: /(?:error_log|syslog)\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST|\$_SERVER)/i,
    label: 'PHP error_log với $_GET/$_POST — user input trực tiếp vào log',
    lang: 'PHP',
  },
];

// Pattern thiếu CRLF sanitization trước khi log
const MISSING_CRLF_SANITIZE = [
  // Có log user input nhưng không thấy strip/replace CRLF
  {
    logRe: /(?:logger|log)\.\w+\s*\([^)]*(?:username|email|user|name|input)[^)]*\)/i,
    sanitizeRe: /\.replace\s*\(\s*\/\\r|\\n\/|stripNewlines|sanitize.*log|escapeLog/i,
    label: 'Log user input không qua CRLF sanitization',
  },
];

function runLogInjection(context) {
  const findings = [];
  const codeFiles = context.codeFiles || [];

  // ── 1. Source: log injection patterns ────────────────────────────────────
  for (const file of codeFiles) {
    const content = file?.content || '';
    const path    = file?.path    || '';

    for (const { re, label, lang } of LOG_INJECTION_SOURCE) {
      if (re.test(content)) {
        findings.push(normalizeFinding({
          ruleId: 'A09-LOGINJ-001',
          owaspCategory: 'A09',
          title: `Log Injection risk: user input có thể được đưa vào log mà không sanitize`,
          severity: 'medium',
          confidence: 'low',
          target: path,
          location: path,
          evidence: [
            `[${lang}] ${label}`,
            'Attacker có thể chèn \\r\\n vào input để giả mạo log entry (log forging).',
            'Ví dụ: username="admin\\nINFO Login success" → log reader thấy entry giả mạo.',
          ],
          remediation:
            'Sanitize user input trước khi log: xóa hoặc encode ký tự \\r, \\n, \\t. ' +
            'Node.js: `value.replace(/[\\r\\n]/g, "_")`. ' +
            'Python: `value.replace("\\r", "").replace("\\n", "")`. ' +
            'Dùng structured logging (JSON) — tự escape newlines khi serialize.',
          references: [
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-Side_Template_Injection',
            'https://cwe.mitre.org/data/definitions/117.html',
            'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude',
          ],
          collector: 'source',
        }));
        break; // 1 finding per file
      }
    }
  }

  // ── 2. Source: thiếu CRLF sanitize ────────────────────────────────────────
  const corpus = codeFiles.map(f => f?.content || '').join('\n');
  for (const { logRe, sanitizeRe, label } of MISSING_CRLF_SANITIZE) {
    if (logRe.test(corpus) && !sanitizeRe.test(corpus)) {
      findings.push(normalizeFinding({
        ruleId: 'A09-LOGINJ-002',
        owaspCategory: 'A09',
        title: 'Log user input nhưng không thấy CRLF sanitization trong codebase',
        severity: 'low',
        confidence: 'low',
        target: 'project source',
        location: 'codebase',
        evidence: [
          label,
          'Không thấy .replace(/\\r|\\n/) hoặc tương đương trước log statements.',
        ],
        remediation:
          'Implement helper: `const safeLog = s => String(s).replace(/[\\r\\n\\t]/g, " ")`. ' +
          'Hoặc dùng structured logging (JSON tự escape).',
        references: [
          'https://cwe.mitre.org/data/definitions/117.html',
          'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html',
        ],
        collector: 'source',
      }));
      break;
    }
  }

  // ── 3. Blackbox: CRLF trong response ──────────────────────────────────────
  const text = context.text || '';
  const url  = context.finalUrl || '';
  // Nếu CRLF payload trong URL được reflect trong body (log forging via response)
  if (/(%0d%0a|%0a|%0d)/.test(url) && /\n|\r/.test(text)) {
    findings.push(normalizeFinding({
      ruleId: 'A09-LOGINJ-003',
      owaspCategory: 'A09',
      title: 'CRLF sequence trong URL được reflect — có thể dùng để log injection',
      severity: 'medium',
      confidence: 'medium',
      target: url,
      location: 'HTTP response (CRLF reflect)',
      evidence: [
        'URL chứa %0d%0a (CRLF encoded) và response body chứa newline.',
        'Nếu server log URL này, attacker có thể inject fake log entries.',
      ],
      remediation:
        'Encode hoặc strip CRLF trước khi log URL/request. ' +
        'Implement input validation từ chối %0d, %0a trong request params.',
      references: [
        'https://cwe.mitre.org/data/definitions/117.html',
        'https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Monitoring_Failures/',
      ],
      collector: 'blackbox',
    }));
  }

  return findings;
}

module.exports = { runLogInjection };

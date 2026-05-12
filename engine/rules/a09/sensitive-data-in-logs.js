const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện Sensitive Data bị log không đúng cách
 * Tham chiếu OWASP WSTG: A09:2025, CWE-532 (Insertion of Sensitive Information into Log File)
 *
 * Phát hiện:
 *  1. Password / secret / token bị log trong source code
 *  2. PII (email, phone, SSN, credit card) bị log
 *  3. Request body đầy đủ bị log (có thể chứa credential)
 *  4. Authorization header bị log
 *  5. Database connection string trong log
 */

// Pattern log credential/secret trong source
const CREDENTIAL_LOG_PATTERNS = [
  {
    re: /(?:log|logger|console)\.\w+\s*\([^)]*(?:password|passwd|pwd|secret|api[_-]?key|private[_-]?key|client[_-]?secret)\b/i,
    label: 'Password/secret có thể bị log',
    severity: 'critical',
  },
  {
    re: /(?:log|logger|console)\.\w+\s*\([^)]*(?:bearer|authorization|x-api-key|access[_-]?token|refresh[_-]?token)\b/i,
    label: 'Authorization token / Bearer token có thể bị log',
    severity: 'critical',
  },
  {
    re: /(?:log|logger|console)\.\w+\s*\([^)]*(?:req\.body|request\.body|formData)\b/i,
    label: 'Request body đầy đủ bị log — có thể chứa password/sensitive data',
    severity: 'high',
  },
  {
    re: /(?:log|logger|console)\.\w+\s*\([^)]*(?:req\.headers|request\.headers)\b/i,
    label: 'Request headers bị log — Authorization header có thể bị lộ',
    severity: 'high',
  },
  {
    re: /(?:log|logger|console)\.\w+\s*\([^)]*(?:connection[_-]?string|connectionString|DbPassword|db[_-]?pass)\b/i,
    label: 'Database connection string / password có thể bị log',
    severity: 'critical',
  },
];

// Pattern PII bị log
const PII_LOG_PATTERNS = [
  {
    re: /(?:log|logger|console)\.\w+\s*\([^)]*(?:ssn|social[_-]?security|national[_-]?id|passport)\b/i,
    label: 'SSN / National ID có thể bị log — vi phạm privacy',
    severity: 'high',
  },
  {
    re: /(?:log|logger|console)\.\w+\s*\([^)]*(?:credit[_-]?card|card[_-]?number|cvv|pan)\b/i,
    label: 'Credit card data có thể bị log — vi phạm PCI-DSS',
    severity: 'critical',
  },
  {
    re: /(?:log|logger|console)\.\w+\s*\([^)]*(?:date[_-]?of[_-]?birth|dob|medical|health[_-]?record|diagnosis)\b/i,
    label: 'Medical / health data có thể bị log — vi phạm HIPAA',
    severity: 'high',
  },
];

// Blackbox: sensitive data patterns trong log output bị expose qua response
const SENSITIVE_IN_RESPONSE_PATTERNS = [
  {
    re: /"password"\s*:\s*"[^"]{4,}"|password=\S{4,}/i,
    label: 'Password value xuất hiện trong response / log output',
    severity: 'critical',
  },
  {
    re: /(?:Bearer|token)\s+[A-Za-z0-9\-_]{20,}/i,
    label: 'Bearer token / access token xuất hiện trong response log',
    severity: 'critical',
  },
  {
    re: /\b(?:\d{4}[\s-]){3}\d{4}\b/,
    label: 'Chuỗi dạng credit card number trong response',
    severity: 'high',
  },
  {
    re: /\b[A-Z]{2}\d{6,9}\b/,
    label: 'Có thể là passport/document number trong response',
    severity: 'medium',
  },
];

function runSensitiveDataInLogs(context) {
  const findings = [];
  const codeFiles = context.codeFiles || [];

  // ── 1. Source: credential trong log ─────────────────────────────────────
  for (const file of codeFiles) {
    const content = file?.content || '';
    const path    = file?.path    || '';

    for (const { re, label, severity } of CREDENTIAL_LOG_PATTERNS) {
      if (re.test(content)) {
        findings.push(normalizeFinding({
          ruleId: 'A09-SENSITLOG-001',
          owaspCategory: 'A09',
          title: `Sensitive credential có thể bị log: ${label.split(' —')[0]}`,
          severity,
          confidence: 'low',
          target: path,
          location: path,
          evidence: [
            label,
            'Credential trong log có thể bị lộ qua: log file access, SIEM export, log shipping, log backup.',
            'Ngay cả log được mã hóa vẫn là attack surface nếu key bị lộ.',
          ],
          remediation:
            'Không bao giờ log password, token, secret, private key. ' +
            'Implement log sanitizer: mask sensitive fields trước khi log. ' +
            'Nếu cần debug: dùng partial masking (4 ký tự cuối), chỉ trong development. ' +
            'Audit toàn bộ log statements định kỳ.',
          references: [
            'https://cwe.mitre.org/data/definitions/532.html',
            'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude',
            'https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Monitoring_Failures/',
          ],
          collector: 'source',
        }));
        break;
      }
    }
  }

  // ── 2. Source: PII trong log ──────────────────────────────────────────────
  const corpus = codeFiles.map(f => f?.content || '').join('\n');
  for (const { re, label, severity } of PII_LOG_PATTERNS) {
    if (re.test(corpus)) {
      findings.push(normalizeFinding({
        ruleId: 'A09-SENSITLOG-002',
        owaspCategory: 'A09',
        title: `PII có thể bị log: ${label.split(' —')[0]}`,
        severity,
        confidence: 'low',
        target: 'project source',
        location: 'codebase',
        evidence: [
          label,
          'Logging PII có thể vi phạm GDPR, HIPAA, PCI-DSS và luật bảo vệ dữ liệu cá nhân.',
        ],
        remediation:
          'Không log PII. Dùng pseudonymous ID (user_id) thay tên/email/số CMND. ' +
          'Implement data masking tự động trước log output. ' +
          'Tuân thủ data minimization principle.',
        references: [
          'https://cwe.mitre.org/data/definitions/532.html',
          'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude',
        ],
        collector: 'source',
      }));
      break;
    }
  }

  // ── 3. Blackbox: sensitive data trong response ────────────────────────────
  const text = context.text || '';
  if (context.status >= 500 || /log|debug|trace/i.test(context.contentType || '')) {
    for (const { re, label, severity } of SENSITIVE_IN_RESPONSE_PATTERNS) {
      if (re.test(text)) {
        findings.push(normalizeFinding({
          ruleId: 'A09-SENSITLOG-003',
          owaspCategory: 'A09',
          title: `Sensitive data có thể bị lộ qua response / error log: ${label}`,
          severity,
          confidence: 'medium',
          target: context.finalUrl,
          location: 'HTTP response body',
          evidence: [label, 'Server có thể đang expose log output hoặc debug info qua HTTP response.'],
          remediation:
            'Không expose log output qua HTTP response. ' +
            'Implement global error handler trả về generic error message. ' +
            'Audit error pages để đảm bảo không leak sensitive data.',
          references: [
            'https://cwe.mitre.org/data/definitions/532.html',
            'https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Monitoring_Failures/',
          ],
          collector: 'blackbox',
        }));
        break;
      }
    }
  }

  return findings;
}

module.exports = { runSensitiveDataInLogs };

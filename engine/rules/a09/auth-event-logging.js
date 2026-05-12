const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện thiếu Security Event Logging
 * Tham chiếu OWASP WSTG: WSTG-INPV-15, A09:2025
 *
 * Nâng cấp so với bản gốc (chỉ check login + hasLogging):
 *  1. Kiểm tra logging cho nhiều security event: login, logout, password change, role change
 *  2. Phát hiện thiếu audit trail cho admin operations
 *  3. Phát hiện structured logging vs unstructured
 *  4. Phát hiện log không có timestamp / request ID / user ID
 *  5. Phát hiện thiếu logging cho failed authentication attempts
 */

// Các security event cần được log
const SECURITY_EVENTS = [
  {
    id: 'login',
    codePattern: /login|signin|PasswordSignIn|SignInManager|authenticate/i,
    logPattern: /\b(?:logger|log|audit)\b.*(?:login|signin|auth(?:entic)?)|(?:login|signin|auth).*\b(?:logger|log|audit)\b/i,
    label: 'Login/Authentication flow',
    remediation: 'Log cả login thành công và thất bại với: timestamp, username (không log password), IP, user-agent, kết quả.',
  },
  {
    id: 'logout',
    codePattern: /logout|signout|SignOut|invalidate.*session|session.*destroy/i,
    logPattern: /log.*(?:logout|signout)|(?:logout|signout).*log/i,
    label: 'Logout / Session invalidation',
    remediation: 'Log logout event với user ID và session ID (đã invalidate).',
  },
  {
    id: 'password_change',
    codePattern: /change.*password|password.*change|reset.*password|ChangePassword/i,
    logPattern: /log.*password.*change|log.*reset/i,
    label: 'Password change / reset',
    remediation: 'Log password change với: user ID, timestamp, IP. Không log password mới hay cũ.',
  },
  {
    id: 'role_change',
    codePattern: /AddToRole|RemoveFromRole|assign.*role|role.*assign|grant.*permission|revoke.*permission/i,
    logPattern: /log.*role|log.*permission|audit.*role/i,
    label: 'Role / Permission change (privilege management)',
    remediation: 'Log mọi thay đổi quyền với: actor (ai thực hiện), target (ai bị thay đổi), role cũ/mới, timestamp.',
  },
  {
    id: 'admin_action',
    codePattern: /\[Authorize.*Admin\]|RequireRole.*admin|IsInRole.*admin|admin.*controller/i,
    logPattern: /log.*admin|audit.*admin/i,
    label: 'Admin operations',
    remediation: 'Log tất cả admin actions vào audit log riêng biệt, không thể xóa (append-only).',
  },
  {
    id: 'account_lockout',
    codePattern: /lockout|account.*lock|IsLockedOut|LockoutEnabled/i,
    logPattern: /log.*lock(?:out)?|lockout.*log/i,
    label: 'Account lockout',
    remediation: 'Log account lockout event với: username, IP, số lần thất bại, thời điểm lockout.',
  },
];

// Pattern structured logging (JSON format)
const STRUCTURED_LOG_PATTERNS = [
  /\bstruct(?:ured)?[_-]?log/i,
  /winston.*json|pino.*default|bunyan/i,
  /JsonFormatter|JsonLayout|structuredLogging/i,
  /new.*winston\.createLogger.*format.*json/is,
];

// Pattern log có đủ context fields
const LOG_CONTEXT_PATTERNS = [
  { re: /(?:userId|user_id|username)\s*[,:]/, label: 'userId trong log' },
  { re: /(?:requestId|request_id|correlationId|traceId)\s*[,:]/, label: 'requestId/traceId trong log' },
  { re: /(?:ipAddress|ip_address|remoteAddr|clientIp)\s*[,:]/, label: 'IP address trong log' },
];

function runAuthEventLogging(context) {
  const findings = [];
  const codeFiles = context.codeFiles || [];
  const corpus = codeFiles.map(f => f?.content || '').join('\n');

  if (!corpus.trim()) return findings;

  // ── 1. Kiểm tra từng security event ─────────────────────────────────────
  for (const event of SECURITY_EVENTS) {
    const hasEvent  = event.codePattern.test(corpus);
    const hasLog    = event.logPattern.test(corpus);
    if (hasEvent && !hasLog) {
      findings.push(normalizeFinding({
        ruleId: `A09-LOG-${event.id.toUpperCase().replace('_', '-')}-001`,
        owaspCategory: 'A09',
        title: `Có ${event.label} nhưng không thấy log security event tương ứng`,
        severity: 'medium',
        confidence: 'low',
        target: 'project source',
        location: 'codebase',
        evidence: [
          `Phát hiện code ${event.label} nhưng không thấy logging cho event này.`,
          'Thiếu logging security event khiến không thể phát hiện tấn công, điều tra sự cố, hoặc đáp ứng compliance.',
        ],
        remediation: event.remediation,
        references: [
          'https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Monitoring_Failures/',
          'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#which-events-to-log',
        ],
        collector: 'source',
      }));
    }
  }

  // ── 2. Kiểm tra structured logging ────────────────────────────────────────
  const hasLogging    = /logger|ilogger|log\.|logging\.|winston|pino|serilog/i.test(corpus);
  const hasStructured = STRUCTURED_LOG_PATTERNS.some(re => re.test(corpus));

  if (hasLogging && !hasStructured) {
    findings.push(normalizeFinding({
      ruleId: 'A09-LOG-STRUCT-001',
      owaspCategory: 'A09',
      title: 'Logging có thể không dùng structured format (JSON) — khó parse bởi SIEM',
      severity: 'low',
      confidence: 'low',
      target: 'project source',
      location: 'codebase',
      evidence: [
        'Có logging nhưng không thấy dấu hiệu structured/JSON logging.',
        'Log plain text không thể parse tự động bởi SIEM/ELK → không thể alert tự động.',
      ],
      remediation:
        'Dùng structured JSON logging: Winston format.json(), Pino (mặc định JSON), ' +
        'Serilog JsonFormatter, Logback JsonEncoder. ' +
        'Mỗi log entry cần có: timestamp (ISO 8601), level, message, userId, requestId, IP.',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#output-logs-in-json-format',
      ],
      collector: 'source',
    }));
  }

  // ── 3. Kiểm tra log context fields ───────────────────────────────────────
  if (hasLogging) {
    const missingContext = LOG_CONTEXT_PATTERNS.filter(({ re }) => !re.test(corpus));
    if (missingContext.length >= 2) {
      findings.push(normalizeFinding({
        ruleId: 'A09-LOG-CONTEXT-001',
        owaspCategory: 'A09',
        title: 'Log thiếu context fields quan trọng (userId, requestId, IP)',
        severity: 'low',
        confidence: 'low',
        target: 'project source',
        location: 'codebase',
        evidence: [
          `Không thấy: ${missingContext.map(m => m.label).join(', ')} trong log statements.`,
          'Log thiếu context không thể dùng để điều tra sự cố hoặc trace attack chain.',
        ],
        remediation:
          'Mỗi security event log phải có: userId (hoặc "anonymous"), requestId/traceId, ' +
          'IP address của client, user-agent, timestamp (UTC). ' +
          'Dùng logging middleware để tự động inject context.',
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude',
        ],
        collector: 'source',
      }));
    }
  }

  // ── 4. Kiểm tra failed authentication được log ───────────────────────────
  const hasFailedAuthLog = /log.*(?:fail|invalid|wrong|incorrect|unauthorized|forbidden)/i.test(corpus)
    && /(?:login|auth|signin)/i.test(corpus);

  if (!hasFailedAuthLog && /login|signin|authenticate/i.test(corpus)) {
    findings.push(normalizeFinding({
      ruleId: 'A09-LOG-FAIL-001',
      owaspCategory: 'A09',
      title: 'Không thấy logging cho failed authentication attempts',
      severity: 'medium',
      confidence: 'low',
      target: 'project source',
      location: 'codebase',
      evidence: [
        'Có auth flow nhưng không thấy log cho failed login attempts.',
        'Không log failed auth khiến không phát hiện được brute-force attack.',
      ],
      remediation:
        'Log mọi failed login attempt với: username (không password), IP, timestamp, lý do thất bại. ' +
        'Gửi alert khi > 5 failed attempts/phút từ cùng IP.',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#which-events-to-log',
        'https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Monitoring_Failures/',
      ],
      collector: 'source',
    }));
  }

  return findings;
}

module.exports = { runAuthEventLogging };

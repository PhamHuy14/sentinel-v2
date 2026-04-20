/**
 * Privilege Escalation Heuristic
 * OWASP Reference: OTG-AUTHZ-003
 * Detects attempts to escalate privileges via parameter/field manipulation.
 */

const { normalizeFinding } = require('../../models/finding');

// Patterns in request body / query that suggest privilege escalation attempts
const REQUEST_ESCALATION_PATTERNS = [
  { pattern: /["'](role|roles)["']\s*:\s*["'](admin|superadmin|root|moderator|staff|superuser|operator)["']/i, label: 'role field với giá trị privileged' },
  { pattern: /["'](isAdmin|is_admin|admin)["']\s*:\s*(true|1|"true"|'true')/i, label: 'isAdmin=true trong request' },
  { pattern: /["'](privilege|privileges|permission|permissions|access_level|accessLevel)["']\s*:\s*["']?(admin|high|super|full|all|\d{2,})["']?/i, label: 'privilege field với giá trị cao' },
  { pattern: /["'](level|userLevel|user_level|tier)["']\s*:\s*["']?(\d{2,}|admin|super)["']?/i, label: 'level field bất thường' },
  { pattern: /["'](verified|confirmed|activated|approved|trusted)["']\s*:\s*(true|1|"true")/i, label: 'trust/verified flag manipulation' },
  { pattern: /["'](group|groups|user_group|userGroup)["']\s*:\s*["'](admin|superadmin|root|privileged)/i, label: 'group/userGroup privileged' },
];

// Patterns in URL query string
const QUERY_ESCALATION_PATTERNS = [
  /[?&](role|isAdmin|is_admin|admin|privilege|level)=(admin|superadmin|root|true|1|high)/i,
  /[?&](access|permission)=(full|all|write|admin)/i,
  /[?&](userType|user_type|accountType)=(admin|superuser|staff|privileged)/i,
];

// Response patterns that suggest escalation succeeded
const RESPONSE_ESCALATION_INDICATORS = [
  { pattern: /"role"\s*:\s*"(admin|superadmin|root|moderator)"/i, label: 'role admin trong response' },
  { pattern: /"isAdmin"\s*:\s*true/i, label: 'isAdmin:true trong response' },
  { pattern: /"privileges"\s*:\s*\[/i, label: 'privileges array trong response' },
  { pattern: /"access_level"\s*:\s*["']?(high|full|admin|super)/i, label: 'access_level cao trong response' },
];

function runPrivilegeEscalationHeuristic(context) {
  const findings = [];
  const requestBody = context.requestBody || '';
  const queryString = context.queryString || context.finalUrl || '';
  const responseText = context.text || '';
  const method = (context.method || 'GET').toUpperCase();

  // ----------------------------------------------------------------
  // 1. Kiểm tra request body có chứa privilege manipulation không
  // ----------------------------------------------------------------
  const requestMatches = [];
  for (const { pattern, label } of REQUEST_ESCALATION_PATTERNS) {
    if (pattern.test(requestBody)) {
      requestMatches.push(label);
    }
  }

  // ----------------------------------------------------------------
  // 2. Kiểm tra query string có chứa privilege params không
  // ----------------------------------------------------------------
  const queryMatches = [];
  for (const pattern of QUERY_ESCALATION_PATTERNS) {
    const match = queryString.match(pattern);
    if (match) {
      queryMatches.push(match[0]);
    }
  }

  // ----------------------------------------------------------------
  // 3. Correlation: request có escalation attempt VÀ response confirm
  // ----------------------------------------------------------------
  const responseMatches = [];
  for (const { pattern, label } of RESPONSE_ESCALATION_INDICATORS) {
    if (pattern.test(responseText)) {
      responseMatches.push(label);
    }
  }

  // Case A: Request body + Response confirmation → HIGH confidence
  if (requestMatches.length > 0 && responseMatches.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A01-PRIV-001',
      owaspCategory: 'A01',
      title: 'Có dấu hiệu Privilege Escalation thành công qua request body',
      severity: context.isLocalhost ? 'medium' : 'high',
      confidence: 'high',
      target: context.finalUrl,
      location: 'request body + response body',
      evidence: [
        `Request chứa: ${requestMatches.join(', ')}`,
        `Response xác nhận: ${responseMatches.join(', ')}`,
        `HTTP Method: ${method}`,
      ],
      remediation:
        'Server phải KHÔNG bao giờ cho phép client tự set role/permission. ' +
        'Dùng server-side session để lưu role. ' +
        'Validate whitelist các field được phép bind từ request.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation',
        'https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
  }

  // Case B: Chỉ request body có escalation attempt → MEDIUM confidence
  if (requestMatches.length > 0 && responseMatches.length === 0) {
    findings.push(normalizeFinding({
      ruleId: 'A01-PRIV-002',
      owaspCategory: 'A01',
      title: 'Request chứa privilege fields — cần xác minh server có reject không',
      severity: context.isLocalhost ? 'low' : 'medium',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'request body',
      evidence: [
        `Tìm thấy trong request: ${requestMatches.join(', ')}`,
        'Response không confirm escalation nhưng cần kiểm tra server có ignore field này không.',
      ],
      remediation:
        'Kiểm tra server log để xác nhận field bị ignore. ' +
        'Dùng DTO/ViewModel với allowlist field rõ ràng.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation',
      ],
      collector: 'blackbox',
    }));
  }

  // Case C: Query string escalation attempt
  if (queryMatches.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A01-PRIV-003',
      owaspCategory: 'A01',
      title: 'URL query chứa privilege parameter đáng ngờ',
      severity: context.isLocalhost ? 'low' : 'medium',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'URL query string',
      evidence: [
        `Tìm thấy trong URL: ${queryMatches.slice(0, 3).join(', ')}`,
        'Privilege parameters trong URL dễ bị tamper và không nên dùng để kiểm soát quyền.',
      ],
      remediation:
        'Không dùng URL parameter để truyền hoặc kiểm tra role/permission. ' +
        'Lấy role từ server-side session/token.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation',
      ],
      collector: 'blackbox',
    }));
  }

  return findings;
}

module.exports = { runPrivilegeEscalationHeuristic };

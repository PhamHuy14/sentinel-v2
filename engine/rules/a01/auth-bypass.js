/**
 * Authentication Bypass Heuristic
 * OWASP Reference: OTG-AUTHN-004
 * Detects attempts to bypass authentication via parameter/cookie manipulation,
 * direct page requests, and forced browsing past login gates.
 */

const { normalizeFinding } = require('../../models/finding');

// URL/query patterns that try to skip auth
const AUTH_BYPASS_QUERY_PATTERNS = [
  { pattern: /[?&](authenticated|isAuthenticated|auth)=(true|yes|1)/i, label: 'authenticated=true in URL' },
  { pattern: /[?&](skip_auth|skipAuth|bypass|no_auth)=(true|1|yes)/i, label: 'skip_auth flag in URL' },
  { pattern: /[?&](logged_in|loggedIn|login)=(true|1|yes)/i, label: 'logged_in=true in URL' },
  { pattern: /[?&](session|token|sid)=(null|undefined|0|admin|test)/i, label: 'suspicious session param in URL' },
  { pattern: /[?&](access|grant)=(all|full|admin|true)/i, label: 'access grant param in URL' },
];

// Request body patterns for auth bypass
const AUTH_BYPASS_BODY_PATTERNS = [
  { pattern: /["'](authenticated|isAuthenticated)["']\s*:\s*(true|1|"true")/i, label: 'authenticated flag in request body' },
  { pattern: /["'](bypass_auth|skipLogin|skip_login)["']\s*:\s*(true|1|"true")/i, label: 'bypass flag in request body' },
  { pattern: /["']password["']\s*:\s*["']\s*["']/i, label: 'empty password in request body' },
  // Classic SQL injection auth bypass in input
  { pattern: /["']username["']\s*:.+['"].*or.*['"].*=.*['"]/i, label: 'possible SQL injection in username field' },
];

// Cookie patterns that hint at tampering
const AUTH_BYPASS_COOKIE_PATTERNS = [
  { pattern: /authenticated=(true|1|yes)/i, label: 'authenticated=true cookie' },
  { pattern: /is_admin=(true|1|yes)/i, label: 'is_admin cookie' },
  { pattern: /role=(admin|superadmin|root)/i, label: 'privileged role cookie' },
  { pattern: /session=(null|undefined|guest|test|admin)/i, label: 'suspicious session cookie value' },
  { pattern: /logged_in=(true|1)/i, label: 'logged_in cookie' },
];

// Response signals that auth was bypassed successfully
const AUTH_BYPASS_SUCCESS_SIGNALS = [
  /welcome\s+(admin|administrator|root)/i,
  /"authenticated"\s*:\s*true/i,
  /"loggedIn"\s*:\s*true/i,
  /"isAdmin"\s*:\s*true/i,
  /dashboard|control.panel|admin.panel/i,
  // SQL injection success artifacts in response
  /syntax error|sql error|mysql error|ora-\d{5}/i,
];

function runAuthBypassHeuristic(context) {
  const findings = [];
  const queryString = context.finalUrl || '';
  const requestBody = context.requestBody || '';
  const cookieHeader = context.requestHeaders?.['Cookie'] || '';
  const responseText = context.text || '';
  const statusCode = context.statusCode || 0;

  // ----------------------------------------------------------------
  // 1. URL query bypass attempts
  // ----------------------------------------------------------------
  const queryBypassMatches = [];
  for (const { pattern, label } of AUTH_BYPASS_QUERY_PATTERNS) {
    if (pattern.test(queryString)) {
      queryBypassMatches.push(label);
    }
  }

  // ----------------------------------------------------------------
  // 2. Request body bypass attempts
  // ----------------------------------------------------------------
  const bodyBypassMatches = [];
  for (const { pattern, label } of AUTH_BYPASS_BODY_PATTERNS) {
    if (pattern.test(requestBody)) {
      bodyBypassMatches.push(label);
    }
  }

  // ----------------------------------------------------------------
  // 3. Cookie manipulation
  // ----------------------------------------------------------------
  const cookieBypassMatches = [];
  for (const { pattern, label } of AUTH_BYPASS_COOKIE_PATTERNS) {
    if (pattern.test(cookieHeader)) {
      cookieBypassMatches.push(label);
    }
  }

  // ----------------------------------------------------------------
  // 4. Response signals
  // ----------------------------------------------------------------
  const successSignals = AUTH_BYPASS_SUCCESS_SIGNALS.filter(p => p.test(responseText));

  const hasAnyBypassAttempt =
    queryBypassMatches.length > 0 ||
    bodyBypassMatches.length > 0 ||
    cookieBypassMatches.length > 0;

  // Case A: Bypass attempt + success signal (200 response with auth content)
  if (hasAnyBypassAttempt && successSignals.length > 0 && statusCode === 200) {
    const allEvidence = [
      ...queryBypassMatches.map(l => `URL: ${l}`),
      ...bodyBypassMatches.map(l => `Body: ${l}`),
      ...cookieBypassMatches.map(l => `Cookie: ${l}`),
      `Response có ${successSignals.length} dấu hiệu auth thành công`,
    ];

    findings.push(normalizeFinding({
      ruleId: 'A01-AUTHBYP-001',
      owaspCategory: 'A01',
      title: 'Có dấu hiệu Authentication Bypass thành công',
      severity: context.isLocalhost ? 'medium' : 'critical',
      confidence: 'high',
      target: context.finalUrl,
      location: 'request parameters / cookies',
      evidence: allEvidence,
      remediation:
        'KHÔNG dùng client-controlled parameters để quyết định trạng thái authenticated. ' +
        'Luôn validate session phía server. ' +
        'Áp dụng parameterized queries để chống SQL injection.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema',
        'https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF',
      ],
      collector: 'blackbox',
    }));
    return findings; // Đã có critical finding, không cần thêm
  }

  // Case B: Bypass attempt không confirm được (low-medium)
  if (queryBypassMatches.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A01-AUTHBYP-002',
      owaspCategory: 'A01',
      title: 'URL chứa authentication bypass parameter đáng ngờ',
      severity: context.isLocalhost ? 'info' : 'medium',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'URL query string',
      evidence: queryBypassMatches,
      remediation:
        'Server không được đọc hoặc trust các auth-related parameters từ URL. ' +
        'Trạng thái authenticated chỉ được lấy từ session/token phía server.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema',
      ],
      collector: 'blackbox',
    }));
  }

  if (cookieBypassMatches.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A01-AUTHBYP-003',
      owaspCategory: 'A01',
      title: 'Cookie chứa authentication flag có thể bị manipulate',
      severity: context.isLocalhost ? 'low' : 'high',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'Cookie header',
      evidence: [
        ...cookieBypassMatches,
        'Nếu server tin tưởng cookie này mà không verify server-side session, có thể bypass auth.',
      ],
      remediation:
        'Không lưu trạng thái authenticated hay role vào cookie không có chữ ký (unsigned). ' +
        'Nếu dùng cookie-based auth, phải ký cookie và verify server-side.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema',
      ],
      collector: 'blackbox',
    }));
  }

  return findings;
}

module.exports = { runAuthBypassHeuristic };

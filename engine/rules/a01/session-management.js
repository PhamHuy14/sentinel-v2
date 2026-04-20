/**
 * Session Management Bypass Heuristic
 * OWASP Reference: OTG-SESS-001
 * Detects weak/predictable session tokens, insecure session cookie attributes,
 * and session fixation indicators.
 */

const { normalizeFinding } = require('../../models/finding');

/**
 * Try to base64-decode a string and return decoded value.
 * Returns null if not valid base64 or result is not printable.
 */
function tryBase64Decode(str) {
  try {
    const decoded = Buffer.from(str, 'base64').toString('utf8');
    // Only return if it looks like printable text (not binary)
    if (/^[\x20-\x7E]+$/.test(decoded) && decoded.length >= 4) {
      return decoded;
    }
  } catch (_) {}
  return null;
}

/**
 * Check if a token looks sequential/predictable.
 * Returns a description string if predictable, null otherwise.
 */
function analyzeTokenPredictability(tokenValue) {
  if (!tokenValue) return null;

  // All same character
  if (/^(.)\1+$/.test(tokenValue)) {
    return 'Token gồm toàn ký tự giống nhau';
  }

  // Pure numeric — sequential risk
  if (/^\d+$/.test(tokenValue) && tokenValue.length <= 10) {
    return 'Token thuần số ngắn — dễ brute-force/enumerate';
  }

  // Very short token
  if (tokenValue.length < 16) {
    return `Token quá ngắn (${tokenValue.length} ký tự) — cần ít nhất 128-bit entropy`;
  }

  // Looks like base64 of meaningful data
  const decoded = tryBase64Decode(tokenValue);
  if (decoded) {
    // Check if decoded value leaks info
    if (/user|admin|role|email|@|id=\d/i.test(decoded)) {
      return `Token có vẻ là base64 của thông tin nhạy cảm: "${decoded.substring(0, 50)}"`;
    }
  }

  // Hex string that's too short
  if (/^[0-9a-f]+$/i.test(tokenValue) && tokenValue.length < 32) {
    return `Token hex quá ngắn (${tokenValue.length} hex chars = ${Math.floor(tokenValue.length / 2)} bytes)`;
  }

  return null;
}

function runSessionManagementHeuristic(context) {
  const findings = [];
  const cookies = context.setCookies || context.cookieFlags || [];
  const responseHeaders = context.responseHeaders || {};
  const requestUrl = context.finalUrl || '';
  const responseText = context.text || '';
  const statusCode = context.statusCode || 0;

  // ----------------------------------------------------------------
  // 1. Analyse Set-Cookie headers for insecure session cookies
  // ----------------------------------------------------------------
  const sessionCookieNames = /^(session|sessionid|sess|phpsessid|jsessionid|aspsessionid|connect\.sid|auth|token|access_token)/i;

  for (const cookie of cookies) {
    const name = cookie.name || '';
    const value = cookie.value || '';
    const isSessionCookie = sessionCookieNames.test(name);

    if (!isSessionCookie) continue;

    const issues = [];

    // Check Secure flag
    if (!cookie.secure) {
      issues.push('Thiếu Secure flag — token có thể bị gửi qua HTTP');
    }

    // Check HttpOnly flag
    if (!cookie.httpOnly) {
      issues.push('Thiếu HttpOnly flag — token có thể bị đọc qua JavaScript (XSS)');
    }

    // Check SameSite
    const sameSite = (cookie.sameSite || '').toLowerCase();
    if (!sameSite || sameSite === 'none') {
      issues.push('Thiếu hoặc SameSite=None — dễ bị CSRF');
    }

    // Check token predictability
    const predictability = analyzeTokenPredictability(value);
    if (predictability) {
      issues.push(predictability);
    }

    // Check expiry — session cookie should not have far-future expiry
    if (cookie.expires) {
      const expiry = new Date(cookie.expires);
      const now = new Date();
      const daysUntilExpiry = (expiry - now) / (1000 * 60 * 60 * 24);
      if (daysUntilExpiry > 30) {
        issues.push(`Cookie expires quá xa trong tương lai (${Math.round(daysUntilExpiry)} ngày) — nên dùng session cookie`);
      }
    }

    if (issues.length > 0) {
      const maxSeverity = issues.some(i => i.includes('HttpOnly') || i.includes('Secure'))
        ? (context.isLocalhost ? 'low' : 'medium')
        : 'low';

      findings.push(normalizeFinding({
        ruleId: 'A01-SESS-001',
        owaspCategory: 'A01',
        title: `Session cookie "${name}" có vấn đề bảo mật`,
        severity: maxSeverity,
        confidence: 'high',
        target: context.finalUrl,
        location: `Set-Cookie: ${name}`,
        evidence: issues,
        remediation:
          'Session cookie phải có: Secure, HttpOnly, SameSite=Lax hoặc Strict. ' +
          'Token phải có đủ entropy (ít nhất 128-bit random). ' +
          'Không encode thông tin user vào session token.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-Testing_for_Session_Management_Schema',
          'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
        ],
        collector: 'blackbox',
      }));
    }
  }

  // ----------------------------------------------------------------
  // 2. Session ID in URL (OTG-SESS-004)
  // ----------------------------------------------------------------
  const sessionInUrl = /(jsessionid|phpsessid|sessionid|sessid|sid|session)=[a-z0-9_-]{8,}/i.test(requestUrl);
  if (sessionInUrl) {
    findings.push(normalizeFinding({
      ruleId: 'A01-SESS-002',
      owaspCategory: 'A01',
      title: 'Session ID xuất hiện trong URL',
      severity: context.isLocalhost ? 'low' : 'high',
      confidence: 'high',
      target: context.finalUrl,
      location: 'URL',
      evidence: [
        'Session ID trong URL bị lưu vào server logs, browser history, Referer header.',
        'Attacker có thể lấy session ID từ các nguồn này.',
      ],
      remediation: 'Luôn dùng cookie để truyền session ID, không dùng URL parameter.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/04-Testing_for_Exposed_Session_Variables',
      ],
      collector: 'blackbox',
    }));
  }

  // ----------------------------------------------------------------
  // 3. Session fixation indicator: same session token before/after login
  // ----------------------------------------------------------------
  // This is detectable if context carries pre/post-login session info
  const preLoginToken = context.preLoginSessionToken;
  const postLoginToken = context.postLoginSessionToken;
  if (preLoginToken && postLoginToken && preLoginToken === postLoginToken) {
    findings.push(normalizeFinding({
      ruleId: 'A01-SESS-003',
      owaspCategory: 'A01',
      title: 'Session Fixation: session token không đổi sau khi đăng nhập',
      severity: context.isLocalhost ? 'medium' : 'high',
      confidence: 'high',
      target: context.finalUrl,
      location: 'session cookie',
      evidence: [
        'Session token trước và sau login giống nhau.',
        'Attacker có thể fixate session của victim bằng cách set session ID trước khi victim login.',
      ],
      remediation:
        'Tạo session ID mới ngay sau khi xác thực thành công (session regeneration). ' +
        'Invalidate session cũ.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation',
        'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
  }

  // ----------------------------------------------------------------
  // 4. Missing session invalidation on logout (check via response)
  // ----------------------------------------------------------------
  const isLogoutEndpoint = /logout|signout|sign-out|log-out/i.test(requestUrl);
  if (isLogoutEndpoint && statusCode === 200) {
    // After logout, Set-Cookie should clear session with expires in the past
    const clearedSession = cookies.some(c => {
      const sessionCookie = sessionCookieNames.test(c.name || '');
      const isPastExpiry = c.expires && new Date(c.expires) < new Date();
      const isEmptyValue = !c.value || c.value.length === 0;
      return sessionCookie && (isPastExpiry || isEmptyValue);
    });

    if (!clearedSession && cookies.length === 0) {
      findings.push(normalizeFinding({
        ruleId: 'A01-SESS-004',
        owaspCategory: 'A01',
        title: 'Logout endpoint không xóa session cookie',
        severity: 'medium',
        confidence: 'low',
        target: context.finalUrl,
        location: 'logout response',
        evidence: [
          'Response từ logout endpoint không chứa Set-Cookie để clear session.',
          'Cần xác minh server-side session có bị invalidate không.',
        ],
        remediation:
          'Khi logout: xóa session server-side, gửi Set-Cookie với expires trong quá khứ và giá trị rỗng.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality',
        ],
        collector: 'blackbox',
      }));
    }
  }

  return findings;
}

module.exports = { runSessionManagementHeuristic };

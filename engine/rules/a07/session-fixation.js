const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện Session Fixation và Session Management Issues
 * Tham chiếu OWASP WSTG: WSTG-SESS-03 (Session Fixation), WSTG-SESS-01, WSTG-SESS-09
 *
 * Nâng cấp so với bản gốc (chỉ check Secure attribute):
 *  1. Giữ: session cookie thiếu Secure attribute
 *  2. [NEW] Session ID trong URL (JSESSIONID, PHPSESSID, session trong path/query)
 *  3. [NEW] Session không rotate sau login (heuristic)
 *  4. [NEW] Multiple session cookies đồng thời (session confusion)
 *  5. [NEW] SameSite=None mà không có Secure (đã có trong A02 nhưng focus session)
 */

function runSessionFixation(context) {
  const setCookies = context.setCookies || [];
  const authHints = context.authHints || {};
  const url = context.finalUrl || '';
  const text = context.text || '';
  const findings = [];

  // ── 1. Session cookie thiếu Secure trong auth context (giữ + mở rộng) ────
  const sessionCookies = setCookies.filter(c => /session|auth|identity|token|sid|phpses|jsession/i.test(c));

  for (const cookie of sessionCookies) {
    const cookieName = cookie.split('=')[0].trim();
    const hasSecure = /\bsecure\b/i.test(cookie);
    const hasHttpOnly = /\bhttponly\b/i.test(cookie);
    const sameSiteMatch = cookie.match(/samesite=(\w+)/i);
    const sameSite = sameSiteMatch ? sameSiteMatch[1].toLowerCase() : null;

    // Thiếu Secure trên auth context
    if (!hasSecure && authHints.hasLoginHint) {
      findings.push(normalizeFinding({
        ruleId: 'A07-SESSION-001',
        owaspCategory: 'A07',
        title: `Session cookie "${cookieName}" thiếu Secure flag trong auth context`,
        severity: 'high',
        confidence: 'medium',
        target: url,
        location: 'Set-Cookie header',
        evidence: [
          `Set-Cookie: ${cookie.slice(0, 120)}`,
          'Không có Secure flag → cookie được gửi qua HTTP không mã hóa → dễ bị network sniffing.',
        ],
        remediation:
          'Thêm `Secure` attribute cho tất cả session/auth cookie. ' +
          'Đồng thời thêm `HttpOnly` và `SameSite=Lax` (hoặc Strict).',
        references: [
          'https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/',
          'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#secure-attribute',
        ],
        collector: 'blackbox',
      }));
    }

    // SameSite=None mà không Secure
    if (sameSite === 'none' && !hasSecure) {
      findings.push(normalizeFinding({
        ruleId: 'A07-SESSION-004',
        owaspCategory: 'A07',
        title: `Cookie "${cookieName}" có SameSite=None nhưng thiếu Secure flag`,
        severity: 'high',
        confidence: 'high',
        target: url,
        location: 'Set-Cookie header',
        evidence: [
          `SameSite=None yêu cầu Secure flag nhưng cookie "${cookieName}" không có.`,
          'Browser hiện đại sẽ reject cookie này — gây lỗi auth. Và nếu chấp nhận: cookie đi qua HTTP không mã hóa.',
        ],
        remediation: 'Thêm `Secure` flag: `Set-Cookie: ... SameSite=None; Secure`',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite'],
        collector: 'blackbox',
      }));
    }
  }

  // ── 2. Session ID trong URL ───────────────────────────────────────────────
  const sessionInUrl = [
    { re: /[?;&](?:JSESSIONID|jsessionid)=[A-F0-9]{20,}/i,  label: 'Java JSESSIONID trong URL' },
    { re: /[?;&](?:PHPSESSID|phpsessid)=[a-z0-9]{20,}/i,    label: 'PHP PHPSESSID trong URL' },
    { re: /;jsessionid=[A-F0-9]{20,}/i,                       label: 'JSESSIONID trong URL path (path parameter)' },
    { re: /[?;&](?:session_id|sessionid|sess_id)=[A-Za-z0-9_\-]{16,}/i, label: 'session_id trong URL query' },
    { re: /[?;&](?:ASP\.NET_SessionId)=[A-Za-z0-9_\-]{16,}/i, label: 'ASP.NET SessionId trong URL' },
  ];

  const urlSessionMatch = sessionInUrl.find(({ re }) => re.test(url));
  if (urlSessionMatch) {
    findings.push(normalizeFinding({
      ruleId: 'A07-SESSFIXATION-001',
      owaspCategory: 'A07',
      title: 'Session ID được truyền trong URL — Session Fixation và logging risk',
      severity: 'high',
      confidence: 'high',
      target: url,
      location: 'URL (query/path)',
      evidence: [
        urlSessionMatch.label,
        'Session ID trong URL bị logged ở server access log, browser history, Referer header.',
        'Session Fixation: attacker cung cấp URL với session ID định sẵn cho victim → sau login, attacker có session hợp lệ.',
      ],
      remediation:
        'Không bao giờ đặt session ID trong URL. Dùng cookie với Secure + HttpOnly. ' +
        'Disable URL rewriting cho session (Java: <tracking-mode>COOKIE</tracking-mode>). ' +
        'PHP: session.use_only_cookies = 1, session.use_trans_sid = 0.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation',
        'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-location-in-the-http-request',
      ],
      collector: 'blackbox',
    }));
  }

  // ── 3. Session ID xuất hiện trước và sau login không đổi (session fixation) ─
  // Heuristic: nếu trang có login form VÀ session cookie ĐÃ được set (pre-login)
  // thì cần kiểm tra xem có rotate sau login không
  if (authHints.hasLoginHint && sessionCookies.length > 0) {
    const preLoginSessionHint = /\b(remember me|keep me signed in|stay logged in)\b/i.test(text);
    // Nếu set session cookie trên login page (trước khi user đăng nhập) — cần rotate
    findings.push(normalizeFinding({
      ruleId: 'A07-SESSFIXATION-002',
      owaspCategory: 'A07',
      title: 'Session cookie được set trên login page — cần verify session rotation sau login',
      severity: 'low',
      confidence: 'low',
      target: url,
      location: 'Set-Cookie trên login page',
      evidence: [
        `${sessionCookies.length} session cookie được set trước khi user đăng nhập.`,
        'Cần manual verify: session ID có thay đổi sau khi đăng nhập thành công không?',
        'Nếu không rotate: Session Fixation attack khả thi.',
      ],
      remediation:
        'Sau khi authenticate thành công, luôn tạo session ID mới (regenerate session). ' +
        'Express: req.session.regenerate(). Java: session.invalidate() + getSession(true). ' +
        'PHP: session_regenerate_id(true).',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation',
        'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#renew-the-session-id-after-any-privilege-level-change',
      ],
      collector: 'blackbox',
    }));
  }

  // ── 4. Multiple session cookies cùng lúc (session confusion) ──────────────
  if (sessionCookies.length > 2) {
    findings.push(normalizeFinding({
      ruleId: 'A07-SESSFIXATION-003',
      owaspCategory: 'A07',
      title: `Nhiều session cookie cùng lúc (${sessionCookies.length}) — session confusion risk`,
      severity: 'low',
      confidence: 'medium',
      target: url,
      location: 'Set-Cookie headers',
      evidence: [
        `${sessionCookies.length} session-related cookies: ${sessionCookies.map(c => c.split('=')[0]).join(', ')}`,
        'Multiple session token có thể gây nhầm lẫn: middleware xử lý khác với framework → privilege confusion.',
      ],
      remediation:
        'Chuẩn hóa về 1 session token chính thức. ' +
        'Xóa legacy session cookie nếu không còn dùng.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'],
      collector: 'blackbox',
    }));
  }

  return findings;
}

module.exports = { runSessionFixation };

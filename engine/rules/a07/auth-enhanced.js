const { normalizeFinding } = require('../../models/finding');

/**
 * Bộ quy tắc Authentication nâng cao (A07)
 * Tham chiếu OWASP WSTG: WSTG-ATHN-01 đến WSTG-ATHN-10
 *
 * Nâng cấp so với bản gốc:
 *  1. runBruteForceProtection: Thêm kiểm tra account lockout hint trong response
 *  2. runPasswordPolicyHeuristic: Mở rộng pattern, check autocomplete=off
 *  3. runDefaultCredentialsHint: Mở rộng pattern (admin:admin, root:root, test:test)
 *  4. runSessionManagement: Thêm check session không có expiry + session ID quá ngắn
 *  5. runMfaPresence: Giữ nguyên
 *  6. [NEW] runTokenInUrl: Phát hiện token/session/API key trong URL query string
 *  7. [NEW] runOAuthMisconfig: Phát hiện OAuth implicit flow, missing state, open redirect
 *  8. [NEW] runWeakSessionEntropy: Session cookie value quá ngắn / dạng sequential
 */

// ─────────────────────────────────────────────────────────────────────────────
// 1. Brute Force Protection (nâng cấp)
// ─────────────────────────────────────────────────────────────────────────────

function runBruteForceProtection(context) {
  const findings = [];
  const headers = context.headers || {};
  const getHeader = (k) => (headers?.get ? headers.get(k) : (headers[k] || headers[k.toLowerCase()] || '')) || '';
  const authHints = context.authHints || {};
  if (!authHints.hasLoginHint) return findings;

  const text = context.text || '';

  const hasRateLimit = [
    'x-ratelimit-limit', 'x-ratelimit-remaining', 'retry-after',
    'x-retry-after', 'ratelimit-limit', 'ratelimit-remaining',
  ].some(h => getHeader(h));

  const hasRateLimitMention = /rate.?limit|too many request|try again|please wait/i.test(text);
  const hasLockoutMention = /account.*lock|locked.*account|temporarily.*disabled|account.*disabled/i.test(text);
  const hasCaptcha = /captcha|recaptcha|hcaptcha|g-recaptcha/i.test(text);

  if (!hasRateLimit && !hasRateLimitMention && !hasLockoutMention && !hasCaptcha) {
    findings.push(normalizeFinding({
      ruleId: 'A07-RATELIMIT-001',
      owaspCategory: 'A07',
      title: 'Login endpoint không có dấu hiệu bảo vệ chống brute-force',
      severity: 'medium',
      confidence: 'low',
      target: context.finalUrl,
      location: 'response headers + body',
      evidence: [
        'Không tìm thấy X-RateLimit-*, Retry-After headers.',
        'Không có thông báo rate limiting, account lockout, hoặc CAPTCHA trong response.',
        'Attacker có thể thử vô hạn mật khẩu mà không bị chặn.',
      ],
      remediation:
        'Triển khai ít nhất 1 trong: ' +
        '(1) Rate limiting: tối đa 5-10 lần/phút/IP. ' +
        '(2) Account lockout sau 5-10 lần thất bại (với unlock flow). ' +
        '(3) Progressive delay + CAPTCHA sau 3 lần thất bại. ' +
        'Trả về header Retry-After khi bị throttle.',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#account-lockout',
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism',
      ],
      collector: 'blackbox',
    }));
  }
  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Password Policy (nâng cấp)
// ─────────────────────────────────────────────────────────────────────────────

function runPasswordPolicyHeuristic(context) {
  const text = context.text || '';
  const authHints = context.authHints || {};
  const findings = [];

  if (!authHints.hasLoginHint && !authHints.hasForgotPasswordHint) return findings;

  const hasPasswordField = /<input[^>]+type=["']password["']/i.test(text);
  if (!hasPasswordField) return findings;

  // Kiểm tra minlength ≥ 8
  const hasMinLength = /minlength=["']([89]|[1-9]\d)["']|min.{0,20}8\s*char/i.test(text);
  // Kiểm tra password rules được mô tả
  const hasPasswordRules = /at least|minimum|uppercase|lowercase|special char|must contain|\d+ character/i.test(text);

  if (!hasMinLength && !hasPasswordRules) {
    findings.push(normalizeFinding({
      ruleId: 'A07-PASS-001',
      owaspCategory: 'A07',
      title: 'Không thấy yêu cầu độ mạnh mật khẩu rõ ràng trong form',
      severity: 'low',
      confidence: 'low',
      target: context.finalUrl,
      location: 'password form',
      evidence: ['Form có trường mật khẩu nhưng không thấy minlength hoặc password policy hint.'],
      remediation:
        'Áp dụng tối thiểu 12 ký tự (NIST SP 800-63B). Cho phép ký tự Unicode và khoảng trắng. ' +
        'Kiểm tra mật khẩu bị lộ qua HaveIBeenPwned API. Không enforce complexity rules cứng nhắc.',
      references: [
        'https://pages.nist.gov/800-63-3/sp800-63b.html',
        'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#implement-proper-password-strength-controls',
      ],
      collector: 'blackbox',
    }));
  }

  // Kiểm tra autocomplete=off trên password field (UX tốt nhưng không phải best practice nữa)
  // NIST khuyến nghị KHÔNG block password managers — autocomplete=off là antipattern
  const hasAutocompleteOff = /<input[^>]+type=["']password["'][^>]+autocomplete=["'](?:off|new-password)[^"']*["']/i.test(text)
    || /<input[^>]+autocomplete=["'](?:off|new-password)[^"']*["'][^>]+type=["']password["']/i.test(text);

  if (hasAutocompleteOff && /autocomplete=["']off["']/i.test(text)) {
    findings.push(normalizeFinding({
      ruleId: 'A07-PASS-002',
      owaspCategory: 'A07',
      title: 'Password field có autocomplete="off" — block password manager (antipattern)',
      severity: 'info',
      confidence: 'high',
      target: context.finalUrl,
      location: 'password input field',
      evidence: ['autocomplete="off" trên password field ngăn password manager hoạt động — làm người dùng dùng mật khẩu yếu/lặp.'],
      remediation:
        'Xóa autocomplete="off" khỏi password field. NIST SP 800-63B và OWASP đều khuyến nghị cho phép password manager. ' +
        'Dùng autocomplete="current-password" hoặc "new-password" thay thế.',
      references: [
        'https://www.w3.org/TR/WCAG21/#identify-input-purpose',
        'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Default Credentials (nâng cấp)
// ─────────────────────────────────────────────────────────────────────────────

function runDefaultCredentialsHint(context) {
  const text = context.text || '';

  const patterns = [
    { re: /default\s*(password|credentials?|login)/i,     label: '"default password/credentials" được nhắc trong response' },
    { re: new RegExp('admin[/\\\\:]admin|admin[/\\\\:]password', 'i'), label: 'admin:admin hoặc admin:password được nhắc' },
    { re: new RegExp('root[/\\\\:]root|root[/\\\\:]toor', 'i'),        label: 'root:root hoặc root:toor được nhắc' },
    { re: new RegExp('test[/\\\\:]test|guest[/\\\\:]guest', 'i'),      label: 'test:test hoặc guest:guest được nhắc' },
    { re: /username.*admin.*password.*admin/is,            label: 'Mẫu username/password mặc định trong form' },
    { re: /initial password|first.?time.*password|default.*login.*is/i, label: 'Hướng dẫn dùng mật khẩu mặc định' },
  ];

  const matches = patterns.filter(({ re }) => re.test(text));
  if (matches.length === 0) return [];

  return [normalizeFinding({
    ruleId: 'A07-DEFCRED-001',
    owaspCategory: 'A07',
    title: 'Trang chứa gợi ý về tài khoản/mật khẩu mặc định',
    severity: 'high',
    confidence: 'medium',
    target: context.finalUrl,
    location: 'response body',
    evidence: matches.map(m => m.label),
    remediation:
      'Xóa mọi tham chiếu đến tài khoản mặc định. ' +
      'Bắt buộc đổi mật khẩu ngay lần đăng nhập đầu tiên (forced password change). ' +
      'Audit toàn bộ tài khoản mặc định trong hệ thống.',
    references: [
      'https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/',
      'https://cwe.mitre.org/data/definitions/1392.html',
    ],
    collector: 'blackbox',
  })];
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Session Management (nâng cấp)
// ─────────────────────────────────────────────────────────────────────────────

function runSessionManagement(context) {
  const findings = [];
  const setCookies = context.setCookies || [];
  const sessionCookies = setCookies.filter(c => /session|auth|token|sid/i.test(c));

  for (const cookie of sessionCookies) {
    const cookieName = cookie.split('=')[0] || 'session';
    const maxAgeMatch = cookie.match(/max-age=(\d+)/i);
    const hasExpires = /expires=/i.test(cookie);
    const hasPersistence = maxAgeMatch || hasExpires;

    // Max-Age > 30 ngày
    if (maxAgeMatch && parseInt(maxAgeMatch[1]) > 2592000) {
      findings.push(normalizeFinding({
        ruleId: 'A07-SESSION-002',
        owaspCategory: 'A07',
        title: `Session cookie có Max-Age quá dài (> 30 ngày)`,
        severity: 'low',
        confidence: 'high',
        target: context.finalUrl,
        location: 'Set-Cookie header',
        evidence: [`${cookieName}: Max-Age=${maxAgeMatch[1]}s (${Math.round(parseInt(maxAgeMatch[1]) / 86400)} ngày)`],
        remediation:
          'Giới hạn session lifetime xuống 15-60 phút idle timeout. ' +
          'Dùng session token ngắn hạn + refresh token riêng nếu cần "remember me".',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'],
        collector: 'blackbox',
      }));
    }

    // Session không có expiry — session bất tử
    if (!hasPersistence && !/session/i.test(cookie.split(';').slice(1).join(';'))) {
      findings.push(normalizeFinding({
        ruleId: 'A07-SESSION-003',
        owaspCategory: 'A07',
        title: `Session cookie "${cookieName}" không có Max-Age/Expires — session bất tử (browser session only)`,
        severity: 'info',
        confidence: 'medium',
        target: context.finalUrl,
        location: 'Set-Cookie header',
        evidence: [
          `Cookie "${cookieName}" không có Max-Age hoặc Expires attribute.`,
          'Cookie sẽ tồn tại đến khi browser đóng — nếu browser không đóng thì session không expire.',
        ],
        remediation:
          'Set Max-Age hợp lý (ví dụ: 3600 = 1 giờ cho session thường). ' +
          'Implement idle timeout phía server song song với cookie expiry.',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#expire-and-max-age-attributes'],
        collector: 'blackbox',
      }));
    }
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. MFA Presence (giữ nguyên)
// ─────────────────────────────────────────────────────────────────────────────

function runMfaPresence(context) {
  const authHints = context.authHints || {};
  if (!authHints.hasLoginHint) return [];
  if (!authHints.hasMfaHint) {
    return [normalizeFinding({
      ruleId: 'A07-MFA-001',
      owaspCategory: 'A07',
      title: 'Không thấy dấu hiệu MFA/2FA trên trang đăng nhập',
      severity: 'medium',
      confidence: 'low',
      target: context.finalUrl,
      location: 'login flow',
      evidence: ['Không phát hiện OTP, TOTP, WebAuthn, hoặc nhắc đến xác thực hai lớp trong login page.'],
      remediation:
        'Triển khai TOTP (RFC 6238 — Google/Microsoft Authenticator), ' +
        'WebAuthn/Passkeys, hoặc OTP qua email/SMS. ' +
        'Ưu tiên TOTP/WebAuthn hơn SMS (SMS dễ bị SIM-swap).',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html',
        'https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/',
      ],
      collector: 'blackbox',
    })];
  }
  return [];
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. [NEW] Token in URL
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Token/session/API key trong URL query string bị logged ở:
 *  - Web server access log
 *  - Browser history
 *  - Referer header khi navigate sang trang khác
 *  - CDN/proxy logs
 */
function runTokenInUrl(context) {
  const url = context.finalUrl || '';
  const findings = [];

  try {
    const parsed = new URL(url);
    const params = parsed.searchParams;

    const sensitiveParams = [
      { key: 'token',        severity: 'high',   label: 'token' },
      { key: 'access_token', severity: 'critical', label: 'OAuth access_token' },
      { key: 'id_token',     severity: 'critical', label: 'OAuth ID token' },
      { key: 'api_key',      severity: 'high',   label: 'API key' },
      { key: 'apikey',       severity: 'high',   label: 'API key' },
      { key: 'key',          severity: 'medium', label: 'key parameter' },
      { key: 'secret',       severity: 'high',   label: 'secret' },
      { key: 'password',     severity: 'critical', label: 'password trong URL' },
      { key: 'passwd',       severity: 'critical', label: 'password trong URL' },
      { key: 'session',      severity: 'high',   label: 'session ID' },
      { key: 'sid',          severity: 'high',   label: 'session ID (sid)' },
      { key: 'auth',         severity: 'high',   label: 'auth token' },
      { key: 'jwt',          severity: 'high',   label: 'JWT token' },
      { key: 'bearer',       severity: 'high',   label: 'Bearer token' },
    ];

    for (const { key, severity, label } of sensitiveParams) {
      if (params.has(key)) {
        const value = params.get(key) || '';
        findings.push(normalizeFinding({
          ruleId: 'A07-TOKENURL-001',
          owaspCategory: 'A07',
          title: `${label} được truyền trong URL query string`,
          severity,
          confidence: 'high',
          target: url,
          location: `URL query parameter: ?${key}=`,
          evidence: [
            `Tham số "${key}" xuất hiện trong URL: ...?${key}=${value.slice(0, 8)}${'*'.repeat(Math.min(8, value.length - 8))}`,
            'Token/credential trong URL bị logged ở server log, browser history, và Referer header.',
          ],
          remediation:
            'Truyền token qua HTTP header (Authorization: Bearer ...) hoặc POST request body. ' +
            'KHÔNG BAO GIỜ đặt secret, password, session ID, hoặc access token trong URL. ' +
            'OAuth 2.0 Implicit Flow (access_token trong URL) đã deprecated — dùng Authorization Code + PKCE.',
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#transport-layer-security',
            'https://datatracker.ietf.org/doc/html/rfc6749#section-10.3',
            'https://oauth.net/2/pkce/',
          ],
          collector: 'blackbox',
        }));
        break; // 1 finding per URL
      }
    }

    // Phát hiện JWT trong URL (eyJ...)
    const urlStr = url;
    if (/[?&][^=]+=eyJ[A-Za-z0-9_-]{10,}/i.test(urlStr)) {
      findings.push(normalizeFinding({
        ruleId: 'A07-TOKENURL-002',
        owaspCategory: 'A07',
        title: 'JWT token (eyJ...) được phát hiện trong URL query string',
        severity: 'high',
        confidence: 'high',
        target: url,
        location: 'URL query string',
        evidence: [
          'JWT token (bắt đầu bằng eyJ) xuất hiện trong URL.',
          'JWT trong URL bị logged và visible trong browser history/Referer.',
        ],
        remediation:
          'Gửi JWT qua Authorization header: `Authorization: Bearer <token>`. ' +
          'Không đặt JWT trong URL.',
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html',
          'https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/',
        ],
        collector: 'blackbox',
      }));
    }
  } catch {
    // URL parse failed — skip
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. [NEW] OAuth Misconfiguration
// ─────────────────────────────────────────────────────────────────────────────

function runOAuthMisconfig(context) {
  const text = context.text || '';
  const url = context.finalUrl || '';
  const findings = [];

  // OAuth Implicit Flow: response_type=token trong URL (deprecated, insecure)
  if (/[?&]response_type=token(&|$)/.test(url) || /response_type=["']?token["']?/i.test(text)) {
    findings.push(normalizeFinding({
      ruleId: 'A07-OAUTH-001',
      owaspCategory: 'A07',
      title: 'OAuth Implicit Flow (response_type=token) — đã deprecated, không an toàn',
      severity: 'high',
      confidence: 'high',
      target: context.finalUrl,
      location: 'OAuth authorization request',
      evidence: [
        'response_type=token — Implicit Flow trả access_token trực tiếp trong URL fragment.',
        'Token bị lộ trong browser history, Referer header, và không thể rotate.',
        'OAuth 2.1 loại bỏ hoàn toàn Implicit Flow.',
      ],
      remediation:
        'Chuyển sang Authorization Code Flow + PKCE (Proof Key for Code Exchange). ' +
        'response_type=code&code_challenge=...&code_challenge_method=S256',
      references: [
        'https://oauth.net/2/implicit-flow/',
        'https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics',
        'https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
  }

  // Missing state parameter — CSRF trên OAuth flow
  if (/[?&]response_type=(code|token)/.test(url) && !/[?&]state=/.test(url)) {
    findings.push(normalizeFinding({
      ruleId: 'A07-OAUTH-002',
      owaspCategory: 'A07',
      title: 'OAuth authorization request thiếu state parameter — nguy cơ CSRF',
      severity: 'high',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'OAuth authorization URL',
      evidence: [
        'URL OAuth chứa response_type nhưng không có state parameter.',
        'Không có state → attacker có thể thực hiện OAuth CSRF (người dùng bị bind account với attacker).',
      ],
      remediation:
        'Luôn gửi state parameter ngẫu nhiên, cryptographically secure (≥128-bit entropy). ' +
        'Verify state khi nhận callback. ' +
        'Nếu dùng PKCE, kết hợp cả state + code_verifier.',
      references: [
        'https://datatracker.ietf.org/doc/html/rfc6749#section-10.12',
        'https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html#state-parameter',
      ],
      collector: 'blackbox',
    }));
  }

  // Open Redirect trong OAuth callback
  const redirectUri = (url.match(/[?&]redirect_uri=([^&]+)/) || [])[1] || '';
  if (redirectUri) {
    try {
      const decoded = decodeURIComponent(redirectUri);
      // Nếu redirect_uri là URL tuyệt đối trỏ ra ngoài domain hiện tại
      const targetHost = new URL(decoded).hostname;
      const currentHost = new URL(context.finalUrl).hostname;
      if (targetHost && currentHost && targetHost !== currentHost && !targetHost.endsWith('.' + currentHost)) {
        findings.push(normalizeFinding({
          ruleId: 'A07-OAUTH-003',
          owaspCategory: 'A07',
          title: 'OAuth redirect_uri trỏ ra ngoài domain — open redirect / token leakage',
          severity: 'critical',
          confidence: 'medium',
          target: context.finalUrl,
          location: 'OAuth redirect_uri parameter',
          evidence: [
            `redirect_uri="${decoded.slice(0, 100)}" trỏ đến domain khác (${targetHost}).`,
            'Nếu server chấp nhận redirect_uri này, attacker có thể đánh cắp authorization code.',
          ],
          remediation:
            'Whitelist redirect_uri khi đăng ký OAuth client. ' +
            'Không chấp nhận redirect_uri động hoặc trỏ ra ngoài domain được đăng ký.',
          references: [
            'https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2',
            'https://portswigger.net/web-security/oauth#leaking-authorization-codes-and-access-tokens',
          ],
          collector: 'blackbox',
        }));
      }
    } catch { /* ignore parse errors */ }
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. [NEW] Weak Session Entropy
// ─────────────────────────────────────────────────────────────────────────────

function runWeakSessionEntropy(context) {
  const findings = [];
  const setCookies = context.setCookies || [];

  for (const cookie of setCookies) {
    if (!/session|sid|auth|token/i.test(cookie)) continue;

    const eqIdx = cookie.indexOf('=');
    const scIdx = cookie.indexOf(';');
    if (eqIdx < 0) continue;

    const value = cookie.slice(eqIdx + 1, scIdx > 0 ? scIdx : undefined).trim();
    const cookieName = cookie.slice(0, eqIdx).trim();

    // Skip nếu là JWT (eyJ...) hoặc obviously structured token
    if (value.startsWith('eyJ') || value.includes('.')) continue;

    // Kiểm tra length quá ngắn (< 16 hex chars = 64 bits)
    const hexLike = /^[0-9a-f]+$/i.test(value);
    if (hexLike && value.length < 16) {
      findings.push(normalizeFinding({
        ruleId: 'A07-SESSION-ENTROPY-001',
        owaspCategory: 'A07',
        title: `Session cookie "${cookieName}" có giá trị quá ngắn — entropy thấp`,
        severity: 'high',
        confidence: 'medium',
        target: context.finalUrl,
        location: 'Set-Cookie header',
        evidence: [
          `Cookie "${cookieName}" có value dài ${value.length} ký tự hex = ${value.length * 4} bits entropy.`,
          'Session ID cần ít nhất 128 bits (32 hex chars) để chống brute-force.',
        ],
        remediation:
          'Tạo session ID bằng cryptographically secure random generator với ≥128 bits entropy. ' +
          'Node.js: crypto.randomBytes(32).toString("hex"). ' +
          'Python: secrets.token_hex(32).',
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-length',
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-Testing_for_Session_Management_Schema',
        ],
        collector: 'blackbox',
      }));
    }

    // Kiểm tra sequential/predictable pattern: 1, 2, 3... hoặc timestamp
    const numericOnly = /^\d+$/.test(value);
    if (numericOnly && value.length < 12) {
      findings.push(normalizeFinding({
        ruleId: 'A07-SESSION-ENTROPY-002',
        owaspCategory: 'A07',
        title: `Session cookie "${cookieName}" có giá trị là số thuần túy — có thể predictable`,
        severity: 'high',
        confidence: 'medium',
        target: context.finalUrl,
        location: 'Set-Cookie header',
        evidence: [
          `Cookie "${cookieName}" = "${value.slice(0, 6)}..." (chỉ chứa số).`,
          'Session ID là số sequential hoặc timestamp dễ bị brute-force/predict.',
        ],
        remediation:
          'Không dùng autoincrement ID, timestamp, hoặc số đơn thuần làm session ID. ' +
          'Dùng cryptographically secure random generator.',
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-unpredictability-and-randomness',
        ],
        collector: 'blackbox',
      }));
    }
  }

  return findings;
}

module.exports = {
  runBruteForceProtection,
  runPasswordPolicyHeuristic,
  runDefaultCredentialsHint,
  runSessionManagement,
  runMfaPresence,
  runTokenInUrl,
  runOAuthMisconfig,
  runWeakSessionEntropy,
};

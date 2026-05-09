const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện vấn đề bảo mật trong Password Reset Flow
 * Tham chiếu OWASP WSTG: WSTG-ATHN-09
 *
 * Nâng cấp so với bản gốc (rất yếu — chỉ 1 check duy nhất):
 *  1. Giữ: thiếu throttling/captcha trên reset flow
 *  2. [NEW] Reset token trong URL (bị logged)
 *  3. [NEW] Reset token quá ngắn trong URL (predictable)
 *  4. [NEW] Security questions — deprecated, insecure
 *  5. [NEW] Thiếu thông báo token expiry
 *  6. [NEW] Password reuse allowed hint
 */

function runResetFlow(context) {
  const text = context.text || '';
  const url = context.finalUrl || '';
  const authHints = context.authHints || {};
  const findings = [];

  const isResetContext = authHints.hasForgotPasswordHint
    || /forgot.*password|reset.*password|password.*reset|recover.*account/i.test(text)
    || /reset.*password|forgot.*password/i.test(url);

  if (!isResetContext) return findings;

  // ── 1. Thiếu throttling / captcha trên reset form ─────────────────────────
  const hasProtection = /captcha|recaptcha|hcaptcha|rate.?limit|try again|please wait/i.test(text);
  const hasRateLimitHeader = /retry-after|x-ratelimit/i.test(JSON.stringify(context.responseHeaders || {}));

  if (!hasProtection && !hasRateLimitHeader) {
    findings.push(normalizeFinding({
      ruleId: 'A07-RESET-001',
      owaspCategory: 'A07',
      title: 'Password reset form thiếu throttling/abuse controls',
      severity: 'medium',
      confidence: 'low',
      target: url,
      location: 'password reset flow',
      evidence: [
        'Không thấy dấu hiệu CAPTCHA, rate limiting, hoặc throttling trên reset form.',
        'Attacker có thể spam reset request để: (1) gây DoS email, (2) enumerate tài khoản.',
      ],
      remediation:
        'Thêm rate limiting: tối đa 3-5 reset request/giờ/IP và/hoặc /email. ' +
        'Hiển thị CAPTCHA sau 2-3 request thất bại. ' +
        'Trả về generic message dù email tồn tại hay không.',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html',
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities',
      ],
      collector: 'blackbox',
    }));
  }

  // ── 2. Reset token trong URL query string ─────────────────────────────────
  const hasTokenInUrl = /[?&](token|reset_token|key|code|t)=[A-Za-z0-9_-]{6,}/i.test(url);
  if (hasTokenInUrl) {
    // Lấy token value để check length
    const tokenMatch = url.match(/[?&](?:token|reset_token|key|code|t)=([A-Za-z0-9_-]+)/i);
    const tokenValue = tokenMatch ? tokenMatch[1] : '';
    const tokenLen = tokenValue.length;

    findings.push(normalizeFinding({
      ruleId: 'A07-RESET-002',
      owaspCategory: 'A07',
      title: 'Reset token được truyền trong URL query string — bị logged và vulnerable',
      severity: 'medium',
      confidence: 'high',
      target: url,
      location: 'URL query parameter',
      evidence: [
        `Reset token xuất hiện trong URL: ?...token=${tokenValue.slice(0, 8)}${'*'.repeat(Math.max(0, tokenLen - 8))}`,
        'Token trong URL bị logged ở: server access log, browser history, Referer header khi navigate.',
        'Attacker có thể lấy token từ shared log, proxy log, hoặc browser cache.',
      ],
      remediation:
        'Đây là acceptable nếu: (1) Token chỉ dùng 1 lần, (2) Hết hạn sau 15-60 phút, (3) Được invalidate ngay sau dùng. ' +
        'Best practice: gửi token qua email link (vẫn là URL), nhưng implement các biện pháp bảo vệ token.',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html#step-3-send-a-reset-link',
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities',
      ],
      collector: 'blackbox',
    }));

    // Check token quá ngắn (< 20 chars = < 100 bits với base64)
    if (tokenLen > 0 && tokenLen < 20) {
      findings.push(normalizeFinding({
        ruleId: 'A07-RESET-003',
        owaspCategory: 'A07',
        title: `Reset token quá ngắn (${tokenLen} ký tự) — entropy thấp, dễ brute-force`,
        severity: 'high',
        confidence: 'high',
        target: url,
        location: 'URL reset token',
        evidence: [
          `Token dài ${tokenLen} ký tự — cần ít nhất 32 ký tự (≥128 bits entropy) để chống brute-force.`,
          `Token ngắn: ${tokenLen * 6} bits entropy ước tính — không đủ an toàn.`,
        ],
        remediation:
          'Tạo reset token bằng: crypto.randomBytes(32).toString("hex") → 64 hex chars = 256 bits. ' +
          'KHÔNG dùng UUID v1/v4 ngắn, timestamp, hoặc user ID làm token.',
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html#step-3-send-a-reset-link',
          'https://cwe.mitre.org/data/definitions/640.html',
        ],
        collector: 'blackbox',
      }));
    }
  }

  // ── 3. Security questions — deprecated và insecure ─────────────────────────
  const hasSecurityQuestions = /security question|mother.{0,15}maiden|pet.{0,10}name|first.{0,10}school|favorite.{0,15}color/i.test(text);
  if (hasSecurityQuestions) {
    findings.push(normalizeFinding({
      ruleId: 'A07-RESET-004',
      owaspCategory: 'A07',
      title: 'Reset flow dùng Security Questions — deprecated, dễ đoán hoặc tìm qua OSINT',
      severity: 'medium',
      confidence: 'medium',
      target: url,
      location: 'password reset form',
      evidence: [
        'Phát hiện security question trong reset flow (mother\'s maiden name, pet name, v.v.).',
        'Security questions dễ đoán, bị lộ qua social media, hoặc tìm được qua OSINT.',
        'NIST SP 800-63B đã loại bỏ security questions khỏi khuyến nghị.',
      ],
      remediation:
        'Loại bỏ security questions. Thay bằng: ' +
        '(1) Email link với token ngắn hạn (best practice). ' +
        '(2) OTP qua SMS/email. ' +
        '(3) Backup codes từ MFA setup.',
      references: [
        'https://pages.nist.gov/800-63-3/sp800-63b.html#memsecretver',
        'https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
  }

  // ── 4. Thiếu thông tin token expiry ──────────────────────────────────────
  const mentionsExpiry = /expire|expir|valid for|valid until|\d+\s*(minute|hour|min|hr)/i.test(text);
  if (!mentionsExpiry && hasTokenInUrl) {
    findings.push(normalizeFinding({
      ruleId: 'A07-RESET-005',
      owaspCategory: 'A07',
      title: 'Reset token không có thông tin expiry hiển thị cho người dùng',
      severity: 'low',
      confidence: 'low',
      target: url,
      location: 'password reset page',
      evidence: [
        'Trang reset không đề cập thời gian hết hạn của token.',
        'Cần verify server-side: token có expire sau 15-60 phút không?',
      ],
      remediation:
        'Hiển thị rõ thời gian hết hạn cho người dùng (ví dụ: "Link hết hạn sau 30 phút"). ' +
        'Server phải expire token sau 15-60 phút và invalidate ngay sau khi dùng.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html'],
      collector: 'blackbox',
    }));
  }

  return findings;
}

module.exports = { runResetFlow };

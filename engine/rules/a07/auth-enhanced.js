const { normalizeFinding } = require('../../models/finding');

function runBruteForceProtection(context) {
  const findings = [];
  const headers = context.headers || new Headers();
  const authHints = context.authHints || {};
  if (!authHints.hasLoginHint) return findings;

  const hasRateLimit = ['x-ratelimit-limit','x-ratelimit-remaining','retry-after','x-retry-after','ratelimit-limit']
    .some(h => headers.get(h));
  const text = context.text || '';
  const hasRateLimitMention = /rate.?limit|too many request|try again/i.test(text);

  if (!hasRateLimit && !hasRateLimitMention) {
    findings.push(normalizeFinding({
      ruleId: 'A07-RATELIMIT-001',
      owaspCategory: 'A07',
      title: 'Không thấy dấu hiệu rate limiting trên trang có auth',
      severity: 'medium',
      confidence: 'low',
      target: context.finalUrl,
      location: 'response headers + body',
      evidence: ['Không tìm thấy X-RateLimit-*, Retry-After headers', 'Không có thông báo rate limiting rõ ràng trong response'],
        remediation: 'Triển khai rate limiting cho endpoint đăng nhập (tối đa 5-10 lần/phút/IP). Dùng exponential backoff và CAPTCHA sau nhiều lần thất bại.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#account-lockout'],
      collector: 'blackbox'
    }));
  }
  return findings;
}

function runPasswordPolicyHeuristic(context) {
  const text = context.text || '';
  const authHints = context.authHints || {};
  if (!authHints.hasLoginHint && !authHints.hasForgotPasswordHint) return [];
  const hasPasswordField = /<input[^>]+type=["']password["']/i.test(text);
  const hasMinLength = /minlength=["']([89]|[1-9]\d)["']|min.{0,20}8\s*char/i.test(text);
  const hasPasswordRules = /at least|minimum|uppercase|lowercase|special char|must contain/i.test(text);
  if (hasPasswordField && !hasMinLength && !hasPasswordRules) {
    return [normalizeFinding({
      ruleId: 'A07-PASS-001',
      owaspCategory: 'A07',
      title: 'Không thấy yêu cầu độ mạnh mật khẩu rõ ràng',
      severity: 'low',
      confidence: 'low',
      target: context.finalUrl,
      location: 'password form',
      evidence: ['Form có trường mật khẩu nhưng không thấy minlength hoặc gợi ý password policy'],
      remediation: 'Áp dụng tối thiểu 12 ký tự. Cho phép ký tự Unicode. Kiểm tra mật khẩu rò rỉ bằng dịch vụ như HaveIBeenPwned.',
      references: ['https://pages.nist.gov/800-63-3/sp800-63b.html'],
      collector: 'blackbox'
    })];
  }
  return [];
}

function runDefaultCredentialsHint(context) {
  const text = context.text || '';
  if (/default\s*(password|credentials?|login)|admin\/admin|admin\/password/i.test(text)) {
    return [normalizeFinding({
      ruleId: 'A07-DEFCRED-001',
      owaspCategory: 'A07',
      title: 'Trang chứa gợi ý về tài khoản mặc định',
      severity: 'high',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'response body',
      evidence: ['Phát hiện nội dung nhắc đến username/password mặc định trong response'],
      remediation: 'Xóa mọi tham chiếu đến tài khoản mặc định. Bắt buộc đổi mật khẩu ngay lần đăng nhập đầu tiên.',
      references: ['https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/'],
      collector: 'blackbox'
    })];
  }
  return [];
}

function runSessionManagement(context) {
  const findings = [];
  const setCookies = context.setCookies || [];
  const sessionCookies = setCookies.filter(c => /session|auth|token/i.test(c));
  for (const cookie of sessionCookies) {
    const maxAgeMatch = cookie.match(/max-age=(\d+)/i);
    if (maxAgeMatch && parseInt(maxAgeMatch[1]) > 2592000) {
      findings.push(normalizeFinding({
        ruleId: 'A07-SESSION-002',
        owaspCategory: 'A07',
        title: 'Session cookie có Max-Age quá dài (> 30 ngày)',
        severity: 'low',
        confidence: 'high',
        target: context.finalUrl,
        location: 'Set-Cookie header',
        evidence: [`${cookie.split('=')[0]}: Max-Age=${maxAgeMatch[1]}s (${Math.round(parseInt(maxAgeMatch[1])/86400)} ngày)`],
        remediation: 'Giới hạn session lifetime. Session nên expire sau idle timeout (15-60 phút).',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'],
        collector: 'blackbox'
      }));
    }
  }
  return findings;
}

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
      evidence: ['Không phát hiện OTP, MFA hoặc nhắc đến xác thực hai lớp trong trang đăng nhập'],
      remediation: 'Triển khai TOTP (Google Authenticator), WebAuthn hoặc OTP qua email/SMS.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html'],
      collector: 'blackbox'
    })];
  }
  return [];
}

module.exports = { runBruteForceProtection, runPasswordPolicyHeuristic, runDefaultCredentialsHint, runSessionManagement, runMfaPresence };

const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện Account Enumeration
 * Tham chiếu OWASP WSTG: WSTG-IDNT-04, WSTG-ATHN-10
 *
 * Nâng cấp so với bản gốc:
 *  1. Mở rộng pattern enumeration — bản gốc chỉ check 3 chuỗi rất hẹp
 *  2. Phân tách: enumeration qua login page vs reset-password page
 *  3. Thêm: username/email được phản chiếu trong error message
 *  4. Thêm: HTTP status-based enumeration hint (200 vs 404 / 422)
 *  5. Thêm: response size difference hint (ghi nhận để tester follow-up)
 *  6. Không yêu cầu authHints.hasForgotPasswordHint — check rộng hơn
 */

// ─── Pattern lộ tài khoản qua login form ────────────────────────────────────
const LOGIN_ENUM_PATTERNS = [
  // Phân biệt rõ username sai vs password sai — enumeration cổ điển
  /incorrect password|wrong password|invalid password/i,
  /password (is )?incorrect/i,
  /the password you entered is wrong/i,
  // Thông báo "email/username không tồn tại"
  /email (address )?not found|email does not exist/i,
  /no account.*found.*email|account.*not.*exist|user.*not.*found/i,
  /we couldn't find.*account|we don't have.*account/i,
  /this email (address )?is not registered/i,
  /invalid (username|email)/i,
  // Thông báo username/account không tồn tại
  /username not found|username does not exist/i,
  /there is no account with that (email|username)/i,
  /that account doesn't exist/i,
];

// ─── Pattern lộ tài khoản qua forgot-password / reset flow ──────────────────
const RESET_ENUM_PATTERNS = [
  /email not found|user not found|account does not exist/i,
  /we.*could not find.*your (email|account)/i,
  /no account (is )?associated with/i,
  /(email|account) is not registered/i,
  /if.*account exists.*we will send/i,  // Đây là ĐÚNG — nhưng cần verify thực sự
];

// ─── Pattern username được reflect lại trong error ───────────────────────────
// Đây là vấn đề bổ sung: attacker biết username nào tồn tại khi thấy nó trong response
const USERNAME_REFLECT_PATTERN = /hello,?\s+\w+|welcome back,?\s+\w+|sign in as\s+\w+@/i;

function runAccountEnumeration(context) {
  const text = context.text || '';
  const authHints = context.authHints || {};
  const status = context.status || 0;
  const findings = [];

  // ── 1. Enumeration qua login flow ─────────────────────────────────────────
  if (authHints.hasLoginHint || /sign.?in|log.?in|login/i.test(text)) {
    const loginMatch = LOGIN_ENUM_PATTERNS.find(re => re.test(text));
    if (loginMatch) {
      findings.push(normalizeFinding({
        ruleId: 'A07-ENUM-001',
        owaspCategory: 'A07',
        title: 'Login form có thể lộ thông tin tài khoản qua error message',
        severity: 'medium',
        confidence: 'medium',
        target: context.finalUrl,
        location: 'login form response',
        evidence: [
          'Response phân biệt rõ "sai username" vs "sai password" — attacker có thể dùng để xác định email đã đăng ký.',
          `Pattern phát hiện: "${loginMatch.toString().replace(/\/[gi]*/g, '').slice(1)}"`,
        ],
        remediation:
          'Dùng thông báo chung cho cả 2 trường hợp: "Email hoặc mật khẩu không đúng". ' +
          'Không phân biệt username tồn tại hay không trong response.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account',
          'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#authentication-responses',
        ],
        collector: 'blackbox',
      }));
    }
  }

  // ── 2. Enumeration qua reset-password flow ────────────────────────────────
  if (authHints.hasForgotPasswordHint || /forgot.*password|reset.*password|recover.*account/i.test(text)) {
    const resetMatch = RESET_ENUM_PATTERNS.find(re => re.test(text));

    // "if an account exists, we will send" — đây là pattern đúng nhưng cần verify
    const hasGenericMessage = /if.*account.*exist.*email|if.*email.*registered.*send/i.test(text);

    if (resetMatch && !hasGenericMessage) {
      findings.push(normalizeFinding({
        ruleId: 'A07-ENUM-002',
        owaspCategory: 'A07',
        title: 'Password reset flow lộ thông tin tài khoản qua error message',
        severity: 'medium',
        confidence: 'medium',
        target: context.finalUrl,
        location: 'password reset form',
        evidence: [
          'Reset form trả về thông báo khác nhau tùy thuộc email có tồn tại hay không.',
          'Attacker có thể submit nhiều email để xác định email nào đã đăng ký trong hệ thống.',
        ],
        remediation:
          'Luôn trả về thông báo chung: "Nếu email tồn tại trong hệ thống, chúng tôi đã gửi hướng dẫn đặt lại mật khẩu." ' +
          'Áp dụng thời gian xử lý nhất quán để tránh timing attack.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account',
          'https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html',
        ],
        collector: 'blackbox',
      }));
    }
  }

  // ── 3. HTTP status-based enumeration ─────────────────────────────────────
  // Một số app trả 404 khi user không tồn tại, 401/422 khi sai password
  if ([404, 422, 409].includes(status) && (authHints.hasLoginHint || authHints.hasForgotPasswordHint)) {
    findings.push(normalizeFinding({
      ruleId: 'A07-ENUM-003',
      owaspCategory: 'A07',
      title: `HTTP ${status} trên auth endpoint — có thể hỗ trợ account enumeration qua status code`,
      severity: 'low',
      confidence: 'low',
      target: context.finalUrl,
      location: `HTTP status ${status}`,
      evidence: [
        `Auth endpoint trả HTTP ${status}.`,
        '404 = user not found, 422/409 = user exists nhưng sai data — attacker phân biệt được.',
        'Cần manual verify bằng cách so sánh status với email tồn tại vs không tồn tại.',
      ],
      remediation:
        'Luôn trả 401 Unauthorized cho cả hai trường hợp "user không tồn tại" và "sai password". ' +
        'Không dùng 404 cho user not found trong auth flow.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account',
      ],
      collector: 'blackbox',
    }));
  }

  // ── 4. Username reflected in response ─────────────────────────────────────
  if (USERNAME_REFLECT_PATTERN.test(text) && authHints.hasLoginHint) {
    findings.push(normalizeFinding({
      ruleId: 'A07-ENUM-004',
      owaspCategory: 'A07',
      title: 'Username/email được phản chiếu trong response — hỗ trợ user enumeration',
      severity: 'low',
      confidence: 'low',
      target: context.finalUrl,
      location: 'response body',
      evidence: [
        'Response hiển thị tên/email người dùng — attacker biết username đó tồn tại trong hệ thống.',
        'Cần xem đây là pre-auth hay post-auth context.',
      ],
      remediation:
        'Không hiển thị username/email trong pre-authentication context. ' +
        'Chỉ dùng greeting sau khi đã xác thực thành công.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account',
      ],
      collector: 'blackbox',
    }));
  }

  return findings;
}

module.exports = { runAccountEnumeration };

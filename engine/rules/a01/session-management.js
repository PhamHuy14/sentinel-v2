/**
 * Quy tắc kinh nghiệm về bypass liên quan quản lý phiên
 * Tham chiếu OWASP: OTG-SESS-001
 * Phát hiện session token yếu/dễ đoán, thuộc tính cookie phiên không an toàn,
 * và dấu hiệu session fixation.
 */

const { normalizeFinding } = require('../../models/finding');

/**
 * Thử giải mã chuỗi base64 và trả về giá trị đã giải mã.
 * Trả về null nếu không phải base64 hợp lệ hoặc kết quả không thể in.
 */
function tryBase64Decode(str) {
  try {
    const decoded = Buffer.from(str, 'base64').toString('utf8');
    // Chỉ trả về khi trông giống văn bản có thể in (không phải dữ liệu nhị phân)
    if (/^[\x20-\x7E]+$/.test(decoded) && decoded.length >= 4) {
      return decoded;
    }
  } catch (_) {}
  return null;
}

/**
 * Kiểm tra token có mang tính tuần tự/dễ đoán hay không.
 * Trả về chuỗi mô tả nếu dễ đoán, ngược lại trả về null.
 */
function analyzeTokenPredictability(tokenValue) {
  if (!tokenValue) return null;

  // Toàn bộ là cùng một ký tự
  if (/^(.)\1+$/.test(tokenValue)) {
    return 'Token gồm toàn ký tự giống nhau';
  }

  // Thuần số, có rủi ro tuần tự
  if (/^\d+$/.test(tokenValue) && tokenValue.length <= 10) {
    return 'Token thuần số ngắn — dễ brute-force/enumerate';
  }

  // Token quá ngắn
  if (tokenValue.length < 16) {
    return `Token quá ngắn (${tokenValue.length} ký tự) — cần ít nhất 128-bit entropy`;
  }

  // Có vẻ là base64 của dữ liệu có nghĩa
  const decoded = tryBase64Decode(tokenValue);
  if (decoded) {
    // Kiểm tra giá trị giải mã có làm lộ thông tin không
    if (/user|admin|role|email|@|id=\d/i.test(decoded)) {
      return `Token có vẻ là base64 của thông tin nhạy cảm: "${decoded.substring(0, 50)}"`;
    }
  }

  // Chuỗi hex quá ngắn
  if (/^[0-9a-f]+$/i.test(tokenValue) && tokenValue.length < 32) {
    return `Token hex quá ngắn (${tokenValue.length} hex chars = ${Math.floor(tokenValue.length / 2)} bytes)`;
  }

  return null;
}

function runSessionManagementHeuristic(context) {
  const findings = [];
  const cookies = context.setCookies || context.cookieFlags || [];
  const requestUrl = context.finalUrl || '';
  const statusCode = context.statusCode || 0;

  // ----------------------------------------------------------------
  // 1. Phân tích Set-Cookie để phát hiện cookie phiên không an toàn
  // ----------------------------------------------------------------
  const sessionCookieNames = /^(session|sessionid|sess|phpsessid|jsessionid|aspsessionid|connect\.sid|auth|token|access_token)/i;

  for (const cookie of cookies) {
    const name = cookie.name || '';
    const value = cookie.value || '';
    const isSessionCookie = sessionCookieNames.test(name);

    if (!isSessionCookie) continue;

    const issues = [];

    // Kiểm tra cờ Secure
    if (!cookie.secure) {
      issues.push('Thiếu Secure flag — token có thể bị gửi qua HTTP');
    }

    // Kiểm tra cờ HttpOnly
    if (!cookie.httpOnly) {
      issues.push('Thiếu HttpOnly flag — token có thể bị đọc qua JavaScript (XSS)');
    }

    // Kiểm tra SameSite
    const sameSite = (cookie.sameSite || '').toLowerCase();
    if (!sameSite || sameSite === 'none') {
      issues.push('Thiếu hoặc SameSite=None — dễ bị CSRF');
    }

    // Kiểm tra tính dễ đoán của token
    const predictability = analyzeTokenPredictability(value);
    if (predictability) {
      issues.push(predictability);
    }

    // Kiểm tra thời hạn hết hạn: cookie phiên không nên hết hạn quá xa
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
  // 2. Session ID xuất hiện trong URL (OTG-SESS-004)
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
  // 3. Dấu hiệu session fixation: token không đổi trước/sau đăng nhập
  // ----------------------------------------------------------------
  // Chỉ phát hiện được khi context có thông tin phiên trước/sau đăng nhập
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
  // 4. Thiếu hủy phiên khi logout (kiểm tra qua phản hồi)
  // ----------------------------------------------------------------
  const isLogoutEndpoint = /logout|signout|sign-out|log-out/i.test(requestUrl);
  if (isLogoutEndpoint && statusCode === 200) {
    // Sau logout, Set-Cookie cần xóa session bằng expires trong quá khứ
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

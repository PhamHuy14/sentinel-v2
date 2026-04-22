/**
 * Quy tắc kinh nghiệm CSRF
 * Tham chiếu OWASP: OTG-SESS-005
 *
 * Điểm thay đổi so với bản gốc:
 *   1. Thêm cấu hình CORS sai -> vector CSRF (Access-Control-Allow-Origin + Credentials)
 *   2. Thêm kiểm tra JSON POST không có tiêu đề tùy chỉnh
 *   3. Thêm gợi ý kiểm tra xác thực Origin/Referer
 */

const { normalizeFinding } = require('../../models/finding');
const { hasCsrfToken, detectPostForms } = require('../../collectors/blackbox/form-analyzer');

function runCsrfHeuristic(context) {
  const findings = [];
  const forms = context.forms || [];
  const responseHeaders = context.responseHeaders || {};
  const requestHeaders = context.requestHeaders || {};
  const contentType = (context.contentType || '').toLowerCase();
  const method = (context.method || 'GET').toUpperCase();

  // ── Chuẩn hóa tên tiêu đề phản hồi ──────────────────────────────────────────
  const h = {};
  for (const [k, v] of Object.entries(responseHeaders)) {
    h[k.toLowerCase()] = v;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // 1. CSRF qua form (giữ logic gốc)
  // ─────────────────────────────────────────────────────────────────────────────
  const postForms = detectPostForms(forms);

  if (postForms.length > 0 && (!contentType || contentType.includes('text/html'))) {
    const hasSameSiteCookie = (context.cookieFlags || []).some(c =>
      ['lax', 'strict'].includes((c.sameSite || '').toLowerCase())
    );
    const hasToken = hasCsrfToken(context.text || '');

    if (!hasToken && !hasSameSiteCookie) {
      findings.push(normalizeFinding({
        ruleId: 'A01-CSRF-001',
        owaspCategory: 'A01',
        severity: context.isLocalhost ? 'low' : 'medium',
        confidence: 'low',
        target: context.finalUrl,
        location: 'HTML forms',
        evidence: [
          `Tìm thấy ${postForms.length} form POST trong HTML nhưng chưa thấy token chống CSRF phổ biến.`,
          hasSameSiteCookie ? 'Đã thấy SameSite cookie.' : 'Không thấy cookie auth có SameSite=Lax/Strict.',
        ],
        remediation: 'Bổ sung anti-forgery token cho form POST và validate token ở backend.',
        references: ['https://owasp.org/www-community/attacks/csrf'],
        collector: 'blackbox',
      }));
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // 2. CORS misconfiguration -> vector CSRF (mới)
  // ─────────────────────────────────────────────────────────────────────────────
  const acao = h['access-control-allow-origin'] || '';
  const acac = h['access-control-allow-credentials'] || '';

  if (acao === '*' && acac.toLowerCase() === 'true') {
    findings.push(normalizeFinding({
      ruleId: 'A01-CSRF-002',
      owaspCategory: 'A01',
      title: 'CORS wildcard + Credentials: có thể dẫn đến CSRF qua cross-origin request',
      severity: context.isLocalhost ? 'medium' : 'high',
      confidence: 'high',
      target: context.finalUrl,
      location: 'CORS response headers',
      evidence: [
        'Access-Control-Allow-Origin: * kết hợp với Access-Control-Allow-Credentials: true',
        'Theo spec browser không nên cho phép, nhưng misconfiguration này rất nguy hiểm trên các cross-origin requests.',
        'Attacker có thể tạo page cross-origin gửi authenticated request.',
      ],
      remediation:
        'Không dùng wildcard (*) khi Allow-Credentials là true. ' +
        'Specify origin cụ thể từ whitelist. ' +
        'Implement CSRF token song song với CORS.',
      references: [
        'https://owasp.org/www-community/attacks/csrf',
        'https://portswigger.net/web-security/cors',
      ],
      collector: 'blackbox',
    }));
  }

  // Echo Origin kèm credentials
  const requestOrigin = requestHeaders['Origin'] || requestHeaders['origin'] || '';
  if (requestOrigin && acao === requestOrigin && acac.toLowerCase() === 'true') {
    findings.push(normalizeFinding({
      ruleId: 'A01-CSRF-003',
      owaspCategory: 'A01',
      title: 'Server phản chiếu Origin trong CORS với Allow-Credentials — CSRF risk',
      severity: context.isLocalhost ? 'low' : 'high',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'CORS response headers',
      evidence: [
        `Access-Control-Allow-Origin: ${acao} (echo của request Origin header)`,
        'Access-Control-Allow-Credentials: true',
        'Server có vẻ accept bất kỳ origin nào bằng cách echo lại — tương đương wildcard.',
      ],
      remediation:
        'Validate Origin header dựa trên server-side whitelist cứng. ' +
        'Không bao giờ echo lại Origin từ request.',
      references: [
        'https://owasp.org/www-community/attacks/csrf',
        'https://portswigger.net/web-security/cors/access-control-allow-origin',
      ],
      collector: 'blackbox',
    }));
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // 3. API JSON POST không có lớp bảo vệ bằng tiêu đề tùy chỉnh (mới)
  // ─────────────────────────────────────────────────────────────────────────────
  if (method === 'POST' && contentType.includes('application/json')) {
    const hasCustomHeader =
      requestHeaders['X-Requested-With'] ||
      requestHeaders['x-requested-with'] ||
      requestHeaders['X-CSRF-Token'] ||
      requestHeaders['x-csrf-token'] ||
      requestHeaders['X-XSRF-Token'] ||
      requestHeaders['x-xsrf-token'];

    const hasSameSiteCookieForJson = (context.cookieFlags || []).some(c =>
      ['lax', 'strict'].includes((c.sameSite || '').toLowerCase())
    );

    if (!hasCustomHeader && !hasSameSiteCookieForJson) {
      findings.push(normalizeFinding({
        ruleId: 'A01-CSRF-004',
        owaspCategory: 'A01',
        title: 'JSON POST API thiếu custom header CSRF protection',
        severity: context.isLocalhost ? 'info' : 'low',
        confidence: 'low',
        target: context.finalUrl,
        location: 'POST request headers',
        evidence: [
          'Request là POST với Content-Type: application/json',
          'Không thấy X-Requested-With, X-CSRF-Token, hoặc SameSite cookie',
          'Các JSON API cũng cần CSRF protection nếu dùng cookie-based auth.',
        ],
        remediation:
          'Thêm một trong: \n' +
          '1. Custom request header (X-Requested-With: XMLHttpRequest) được validate server-side\n' +
          '2. CSRF token trong request body hoặc header\n' +
          '3. SameSite=Lax hoặc Strict trên auth cookie',
        references: [
          'https://owasp.org/www-community/attacks/csrf',
          'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
        ],
        collector: 'blackbox',
      }));
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // 4. Gợi ý kiểm tra Referer/Origin (mới)
  // ─────────────────────────────────────────────────────────────────────────────
  // Nếu request tới endpoint thay đổi trạng thái mà không có Referer thì ghi nhận
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    const referer = requestHeaders['Referer'] || requestHeaders['referer'] || '';
    const origin = requestHeaders['Origin'] || requestHeaders['origin'] || '';

    if (!referer && !origin) {
      // Chỉ cảnh báo nếu đồng thời không thấy CSRF token
      const hasToken = hasCsrfToken(context.text || '');
      if (!hasToken) {
        findings.push(normalizeFinding({
          ruleId: 'A01-CSRF-005',
          owaspCategory: 'A01',
          title: `${method} request không có Referer/Origin header và không thấy CSRF token`,
          severity: 'info',
          confidence: 'low',
          target: context.finalUrl,
          location: 'request headers',
          evidence: [
            `Method: ${method}`,
            'Không có Referer hoặc Origin header trong request.',
            'Không tìm thấy CSRF token trong form/response.',
            'Lưu ý: Referer có thể bị strip bởi browser hoặc privacy settings.',
          ],
          remediation:
            'Implement CSRF token là biện pháp đáng tin cậy hơn Referer validation. ' +
            'Dùng SameSite cookie kết hợp với CSRF token.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'],
          collector: 'blackbox',
        }));
      }
    }
  }

  return findings;
}

module.exports = { runCsrfHeuristic };

/**
 * Quy tắc kinh nghiệm về tiêu đề bảo mật và Cache Control
 * Tham chiếu OWASP:
 *   - OTG-AUTHN-006: Kiểm thử điểm yếu cache của trình duyệt
 *   - OTG-CONFIG-007: Kiểm thử HTTP Strict Transport Security
 *   - Bổ sung: Thiếu tiêu đề bảo mật liên quan A01/A05
 *
 * Kiểm tra tiêu đề bảo mật HTTP bị thiếu/cấu hình sai,
 * làm tăng bề mặt tấn công cho việc vượt qua kiểm soát truy cập.
 */

const { normalizeFinding } = require('../../models/finding');

// Trang/đường dẫn có khả năng chứa nội dung nhạy cảm
const SENSITIVE_PATH_PATTERNS = [
  /\/(login|signin|auth|logout|account|profile|dashboard|admin|payment|checkout|order|invoice)/i,
  /\/(api|v\d+)\/(user|account|order|payment|auth)/i,
];

function isSensitivePath(url) {
  return SENSITIVE_PATH_PATTERNS.some(p => p.test(url));
}

function runSecurityHeadersHeuristic(context) {
  const findings = [];
  const headers = context.responseHeaders || {};
  const url = context.finalUrl || '';
  const contentType = (headers['content-type'] || headers['Content-Type'] || '').toLowerCase();
  const isHtml = contentType.includes('text/html');
  const isJson = contentType.includes('application/json');
  const isHttps = url.startsWith('https://');
  const isSensitive = isSensitivePath(url);

  // Chuẩn hóa tên header về chữ thường để tra cứu
  const h = {};
  for (const [k, v] of Object.entries(headers)) {
    h[k.toLowerCase()] = v;
  }

  // ----------------------------------------------------------------
  // 1. Cache-Control trên trang nhạy cảm (OTG-AUTHN-006)
  // ----------------------------------------------------------------
  if (isSensitive && (isHtml || isJson)) {
    const cacheControl = (h['cache-control'] || '').toLowerCase();
    const pragma = (h.pragma || '').toLowerCase();

    const hasNoStore = cacheControl.includes('no-store');
    const hasNoCache = cacheControl.includes('no-cache') || pragma.includes('no-cache');
    const hasMustRevalidate = cacheControl.includes('must-revalidate');

    if (!hasNoStore || !hasNoCache) {
      const missingDirectives = [];
      if (!hasNoStore) missingDirectives.push('no-store');
      if (!hasNoCache) missingDirectives.push('no-cache');
      if (!hasMustRevalidate) missingDirectives.push('must-revalidate');

      findings.push(normalizeFinding({
        ruleId: 'A01-CACHE-001',
        owaspCategory: 'A01',
        title: 'Trang nhạy cảm thiếu Cache-Control đúng cách',
        severity: context.isLocalhost ? 'info' : 'medium',
        confidence: 'medium',
        target: url,
        location: 'HTTP Cache-Control header',
        evidence: [
          `Cache-Control hiện tại: "${cacheControl || '(không có)'}"`,
          `Thiếu directive: ${missingDirectives.join(', ')}`,
          'Browser/proxy có thể cache sensitive data (credentials, PII, tokens).',
        ],
        remediation:
          'Thêm vào response: Cache-Control: no-cache, no-store, must-revalidate\nPragma: no-cache\nExpires: 0',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses',
          'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html',
        ],
        collector: 'blackbox',
      }));
    }
  }

  // ----------------------------------------------------------------
  // 2. HSTS (OTG-CONFIG-007)
  // ----------------------------------------------------------------
  if (isHttps) {
    const hsts = h['strict-transport-security'] || '';
    if (!hsts) {
      findings.push(normalizeFinding({
        ruleId: 'A01-HSTS-001',
        owaspCategory: 'A01',
        title: 'Thiếu HTTP Strict Transport Security (HSTS) header',
        severity: context.isLocalhost ? 'info' : 'medium',
        confidence: 'high',
        target: url,
        location: 'HTTP Strict-Transport-Security header',
        evidence: [
          'Server không gửi HSTS header.',
          'User có thể bị redirect từ HTTPS sang HTTP bởi attacker (SSL Strip).',
        ],
        remediation:
          'Thêm: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security',
          'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html',
        ],
        collector: 'blackbox',
      }));
    } else {
      // Kiểm tra giá trị max-age
      const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
      if (maxAgeMatch) {
        const maxAge = parseInt(maxAgeMatch[1], 10);
        if (maxAge < 15552000) { // Nhỏ hơn 180 ngày
          findings.push(normalizeFinding({
            ruleId: 'A01-HSTS-002',
            owaspCategory: 'A01',
            title: 'HSTS max-age quá ngắn',
            severity: 'low',
            confidence: 'high',
            target: url,
            location: 'Strict-Transport-Security header',
            evidence: [
              `max-age=${maxAge} giây (${Math.round(maxAge / 86400)} ngày)`,
              'Khuyến nghị ít nhất 1 năm (31536000).',
            ],
            remediation: 'Đặt max-age ít nhất 31536000 (1 năm) và thêm includeSubDomains.',
            references: [
              'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security',
            ],
            collector: 'blackbox',
          }));
        }
      }
    }
  }

  // ----------------------------------------------------------------
  // 3. X-Frame-Options / CSP frame-ancestors (Clickjacking, liên quan gián tiếp A01)
  // ----------------------------------------------------------------
  if (isHtml && isSensitive) {
    const xfo = h['x-frame-options'] || '';
    const csp = h['content-security-policy'] || '';
    const hasFrameProtection =
      xfo || /frame-ancestors/i.test(csp);

    if (!hasFrameProtection) {
      findings.push(normalizeFinding({
        ruleId: 'A01-FRAME-001',
        owaspCategory: 'A01',
        title: 'Trang nhạy cảm thiếu clickjacking protection',
        severity: context.isLocalhost ? 'info' : 'medium',
        confidence: 'medium',
        target: url,
        location: 'X-Frame-Options / CSP frame-ancestors',
        evidence: [
          'Không có X-Frame-Options hoặc CSP frame-ancestors.',
          'Trang có thể bị nhúng vào iframe để thực hiện Clickjacking.',
        ],
        remediation:
          'Thêm: X-Frame-Options: DENY hoặc SAMEORIGIN\n' +
          'Hoặc: Content-Security-Policy: frame-ancestors \'self\'',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-Side_Testing/09-Testing_for_Clickjacking',
          'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html',
        ],
        collector: 'blackbox',
      }));
    }
  }

  // ----------------------------------------------------------------
  // 4. X-Content-Type-Options
  // ----------------------------------------------------------------
  if (isHtml || isJson) {
    const xcto = h['x-content-type-options'] || '';
    if (xcto.toLowerCase() !== 'nosniff') {
      findings.push(normalizeFinding({
        ruleId: 'A01-MIME-001',
        owaspCategory: 'A01',
        title: 'Thiếu X-Content-Type-Options: nosniff',
        severity: 'low',
        confidence: 'high',
        target: url,
        location: 'X-Content-Type-Options header',
        evidence: [
          `X-Content-Type-Options: "${xcto || '(không có)'}"`,
          'Browser có thể MIME-sniff response và thực thi script không mong muốn.',
        ],
        remediation: 'Thêm: X-Content-Type-Options: nosniff',
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
        ],
        collector: 'blackbox',
      }));
    }
  }

  // ----------------------------------------------------------------
  // 5. CORS misconfiguration (liên quan CSRF và A01)
  // ----------------------------------------------------------------
  const acao = h['access-control-allow-origin'] || '';
  const acac = h['access-control-allow-credentials'] || '';

  if (acao === '*' && acac.toLowerCase() === 'true') {
    findings.push(normalizeFinding({
      ruleId: 'A01-CORS-001',
      owaspCategory: 'A01',
      title: 'CORS misconfiguration nguy hiểm: wildcard + credentials',
      severity: context.isLocalhost ? 'medium' : 'critical',
      confidence: 'high',
      target: url,
      location: 'CORS headers',
      evidence: [
        'Access-Control-Allow-Origin: *',
        'Access-Control-Allow-Credentials: true',
        'Kết hợp này cho phép bất kỳ origin nào gửi authenticated cross-origin requests.',
        'Theo spec, browser nên từ chối, nhưng misconfiguration này rất nguy hiểm.',
      ],
      remediation:
        'Không dùng wildcard (*) khi Allow-Credentials là true. ' +
        'Dùng allowlist origin cụ thể. ' +
        'Access-Control-Allow-Origin phải là origin cụ thể khi credentials được phép.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-Side_Testing/07-Testing_Cross_Origin_Resource_Sharing',
        'https://portswigger.net/web-security/cors',
      ],
      collector: 'blackbox',
    }));
  } else if (acao && acao !== '*') {
    // Kiểm tra xem origin có bị phản chiếu theo giá trị do attacker điều khiển không
    const requestOrigin = context.requestHeaders?.Origin || '';
    if (requestOrigin && acao === requestOrigin && acac.toLowerCase() === 'true') {
      findings.push(normalizeFinding({
        ruleId: 'A01-CORS-002',
        owaspCategory: 'A01',
        title: 'Server phản chiếu Origin header với Allow-Credentials — có thể bị CORS abuse',
        severity: context.isLocalhost ? 'low' : 'high',
        confidence: 'medium',
        target: url,
        location: 'CORS headers',
        evidence: [
          `Access-Control-Allow-Origin: ${acao} (echo của request Origin)`,
          'Access-Control-Allow-Credentials: true',
          'Server có vẻ accept bất kỳ Origin nào bằng cách echo lại.',
        ],
        remediation:
          'Validate Origin header dựa trên whitelist cứng, không echo lại Origin từ request.',
        references: [
          'https://portswigger.net/web-security/cors/access-control-allow-origin',
        ],
        collector: 'blackbox',
      }));
    }
  }

  return findings;
}

module.exports = { runSecurityHeadersHeuristic };

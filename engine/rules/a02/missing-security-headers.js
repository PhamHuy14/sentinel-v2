const { normalizeFinding } = require('../../models/finding');

const MIN_HSTS_MAX_AGE = 31536000; // 1 năm theo OWASP recommendation

/**
 * Parse giá trị Strict-Transport-Security header.
 * @param {string} hstsValue
 * @returns {{ maxAge: number|null, includeSubDomains: boolean, preload: boolean }}
 */
function parseHsts(hstsValue) {
  const result = { maxAge: null, includeSubDomains: false, preload: false };
  if (!hstsValue) return result;
  const parts = hstsValue.split(';').map((p) => p.trim().toLowerCase());
  for (const part of parts) {
    if (part.startsWith('max-age=')) {
      result.maxAge = parseInt(part.replace('max-age=', ''), 10);
    } else if (part === 'includesubdomains') {
      result.includeSubDomains = true;
    } else if (part === 'preload') {
      result.preload = true;
    }
  }
  return result;
}

/**
 * A02-HDR: Phát hiện các security response header bị thiếu hoặc cấu hình yếu.
 * Theo OWASP OTG-CONFIG-007 (HSTS) và OTG-CLIENT-009 (Clickjacking).
 *
 * @param {object}  context
 * @param {Headers|object} context.headers
 * @param {string}  context.finalUrl
 * @param {string}  context.protocol        - 'https:' | 'http:'
 * @param {string}  [context.contentType]
 * @param {boolean} [context.isLocalhost]
 * @param {boolean} [context.suppressInfo]  - Bỏ qua info-level findings (dùng cho CI)
 * @returns {Array} findings
 */
function runMissingSecurityHeaders(context) {
  const findings = [];
  const headers = context.headers || new Headers();
  const isHtml = (context.contentType || '').toLowerCase().includes('text/html');
  const isHttps = context.protocol === 'https:';
  const isLocal = !!context.isLocalhost;

  // -- X-Content-Type-Options ------------------------------------------------
  if (!headers.get('x-content-type-options')) {
    findings.push(normalizeFinding({
      ruleId: 'A02-HDR-001',
      owaspCategory: 'A02',
      title: 'Thiếu X-Content-Type-Options: nosniff',
      severity: isLocal ? 'low' : 'medium',
      confidence: 'high',
      target: context.finalUrl,
      location: 'response headers',
      evidence: [`Response từ ${context.finalUrl} không có X-Content-Type-Options.`],
      remediation:
        'Thêm header: X-Content-Type-Options: nosniff\n' +
        'Ngăn browser "sniff" content-type thực sự của response (MIME confusion attack).',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
  }

  // -- HSTS nâng cao ---------------------------------------------------------
  if (isHttps && !isLocal) {
    const hstsRaw = headers.get('strict-transport-security');

    if (!hstsRaw) {
      findings.push(normalizeFinding({
        ruleId: 'A02-HDR-002',
        owaspCategory: 'A02',
        title: 'Thiếu Strict-Transport-Security (HSTS) trên HTTPS',
        severity: 'medium',
        confidence: 'high',
        target: context.finalUrl,
        location: 'response headers',
        evidence: [`HTTPS response từ ${context.finalUrl} không có HSTS header.`],
        remediation:
          'Thêm: Strict-Transport-Security: max-age=31536000; includeSubDomains\n' +
          'Đảm bảo toàn bộ subdomain cũng hỗ trợ HTTPS trước khi bật includeSubDomains.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security',
        ],
        collector: 'blackbox',
      }));
    } else {
      const hsts = parseHsts(hstsRaw);

      // max-age quá ngắn
      if (hsts.maxAge !== null && hsts.maxAge < MIN_HSTS_MAX_AGE) {
        findings.push(normalizeFinding({
          ruleId: 'A02-HDR-004',
          owaspCategory: 'A02',
          title: `HSTS max-age quá ngắn (${hsts.maxAge}s < ${MIN_HSTS_MAX_AGE}s)`,
          severity: 'medium',
          confidence: 'high',
          target: context.finalUrl,
          location: 'response headers -> Strict-Transport-Security',
          evidence: [`Strict-Transport-Security: ${hstsRaw}`],
          remediation:
            `Tăng max-age lên ít nhất ${MIN_HSTS_MAX_AGE} (1 năm).\n` +
            'Ví dụ: Strict-Transport-Security: max-age=31536000; includeSubDomains',
          references: [
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security',
          ],
          collector: 'blackbox',
        }));
      }

      // Thiếu includeSubDomains
      if (!hsts.includeSubDomains && !context.suppressInfo) {
        findings.push(normalizeFinding({
          ruleId: 'A02-HDR-005',
          owaspCategory: 'A02',
          title: 'HSTS thiếu includeSubDomains',
          severity: 'low',
          confidence: 'medium',
          target: context.finalUrl,
          location: 'response headers -> Strict-Transport-Security',
          evidence: [`Strict-Transport-Security: ${hstsRaw}`],
          remediation:
            'Thêm includeSubDomains nếu tất cả subdomain đều hỗ trợ HTTPS.\n' +
            'Strict-Transport-Security: max-age=31536000; includeSubDomains',
          references: [
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
          ],
          collector: 'blackbox',
        }));
      }
    }
  }

  // -- Content-Security-Policy ----------------------------------------------
  if (isHtml && !headers.get('content-security-policy')) {
    findings.push(normalizeFinding({
      ruleId: 'A02-HDR-003',
      owaspCategory: 'A02',
      title: 'Thiếu Content-Security-Policy (CSP)',
      severity: isLocal ? 'low' : 'medium',
      confidence: 'high',
      target: context.finalUrl,
      location: 'response headers',
      evidence: [`HTML response từ ${context.finalUrl} chưa có CSP header.`],
      remediation:
        'Triển khai CSP phù hợp với ứng dụng. Bắt đầu với:\n' +
        "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'\n" +
        'Dùng CSP Evaluator (https://csp-evaluator.withgoogle.com/) để kiểm tra.',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
  }

  // -- X-Frame-Options (Clickjacking) ---------------------------------------
  if (isHtml) {
    const xfo = headers.get('x-frame-options');
    const csp = headers.get('content-security-policy') || '';
    const cspHasFrameAncestors = /frame-ancestors/i.test(csp);

    // Chỉ report nếu không có cả XFO lẫn CSP frame-ancestors
    if (!xfo && !cspHasFrameAncestors) {
      findings.push(normalizeFinding({
        ruleId: 'A02-HDR-006',
        owaspCategory: 'A02',
        title: 'Thiếu bảo vệ chống Clickjacking (X-Frame-Options hoặc CSP frame-ancestors)',
        severity: isLocal ? 'low' : 'medium',
        confidence: 'high',
        target: context.finalUrl,
        location: 'response headers',
        evidence: [
          'Không tìm thấy X-Frame-Options.',
          'CSP không có directive frame-ancestors.',
        ],
        remediation:
          'Thêm một trong hai cách:\n' +
          '1. X-Frame-Options: DENY  (hoặc SAMEORIGIN)\n' +
          "2. Content-Security-Policy: frame-ancestors 'none'  (cách được ưu tiên hơn)",
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking',
          'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html',
        ],
        collector: 'blackbox',
      }));
    }
  }

  // -- Referrer-Policy -------------------------------------------------------
  if (!context.suppressInfo && isHtml) {
    const rpRaw = headers.get('referrer-policy');
    if (!rpRaw) {
      findings.push(normalizeFinding({
        ruleId: 'A02-HDR-007',
        owaspCategory: 'A02',
        title: 'Thiếu Referrer-Policy header',
        severity: 'low',
        confidence: 'high',
        target: context.finalUrl,
        location: 'response headers',
        evidence: [`Response từ ${context.finalUrl} không có Referrer-Policy.`],
        remediation:
          'Thêm: Referrer-Policy: strict-origin-when-cross-origin\n' +
          'Ngăn URL đầy đủ (có thể chứa token/params nhạy cảm) bị rò rỉ qua Referer header.',
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
        ],
        collector: 'blackbox',
      }));
    } else {
      const unsafeValues = ['unsafe-url', 'no-referrer-when-downgrade'];
      if (unsafeValues.includes(rpRaw.toLowerCase())) {
        findings.push(normalizeFinding({
          ruleId: 'A02-HDR-007',
          owaspCategory: 'A02',
          title: `Referrer-Policy có giá trị không an toàn: "${rpRaw}"`,
          severity: 'low',
          confidence: 'high',
          target: context.finalUrl,
          location: 'response headers -> Referrer-Policy',
          evidence: [`Referrer-Policy: ${rpRaw}`],
          remediation:
            'Đổi Referrer-Policy sang giá trị an toàn hơn:\n' +
            '• strict-origin-when-cross-origin (recommended)\n' +
            '• no-referrer\n' +
            '• same-origin',
          references: [
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
          ],
          collector: 'blackbox',
        }));
      }
    }
  }

  return findings;
}

module.exports = { runMissingSecurityHeaders };

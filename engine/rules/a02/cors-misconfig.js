const { normalizeFinding } = require('../../models/finding');

const DANGEROUS_METHODS_FOR_CORS = ['PUT', 'DELETE', 'PATCH'];

function getHeader(headers, key) {
  if (!headers) return '';
  if (typeof headers.get === 'function') {
    return headers.get(key) || '';
  }
  return headers[key] || headers[key.toLowerCase()] || '';
}

function runCorsMisconfig(context) {
  const findings = [];
  const headers = context.headers || new Headers();

  const allowOrigin = String(getHeader(headers, 'access-control-allow-origin')).trim();
  const allowCredentials = String(getHeader(headers, 'access-control-allow-credentials')).trim();
  const allowMethods = String(getHeader(headers, 'access-control-allow-methods')).trim();
  const allowHeaders = String(getHeader(headers, 'access-control-allow-headers')).trim();
  const varyHeader = String(getHeader(headers, 'vary')).trim();

  if (!allowOrigin) return findings;

  if (allowOrigin === '*') {
    findings.push(normalizeFinding({
      ruleId: 'A02-CORS-001',
      owaspCategory: 'A02',
      title: 'CORS cho phép wildcard origin (*)',
      severity: 'medium',
      confidence: 'high',
      target: context.finalUrl,
      location: 'response headers',
      evidence: [
        'Access-Control-Allow-Origin: *',
        allowCredentials ? `Access-Control-Allow-Credentials: ${allowCredentials}` : '',
      ].filter(Boolean),
      remediation:
        'Thay thế "*" bằng allowlist origin cụ thể.\n' +
        'Chỉ dùng wildcard cho public API không có dữ liệu nhạy cảm.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing',
      ],
      collector: 'blackbox'
    }));
  }

  if (allowOrigin === '*' && allowCredentials.toLowerCase() === 'true') {
    findings.push(normalizeFinding({
      ruleId: 'A02-CORS-003',
      owaspCategory: 'A02',
      title: 'CORS: wildcard origin kết hợp Allow-Credentials - cấu hình nguy hiểm',
      severity: 'high',
      confidence: 'high',
      target: context.finalUrl,
      location: 'response headers',
      evidence: [
        'Access-Control-Allow-Origin: *',
        'Access-Control-Allow-Credentials: true',
        'Cấu hình này bị browser từ chối nhưng cho thấy server không kiểm soát CORS đúng cách.',
      ],
      remediation:
        'Không dùng wildcard khi Access-Control-Allow-Credentials: true.\n' +
        'Chỉ định origin cụ thể: Access-Control-Allow-Origin: https://trusted.example.com',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing',
        'https://fetch.spec.whatwg.org/#cors-protocol-and-credentials',
      ],
      collector: 'blackbox'
    }));
  }

  const requestOrigin = context.requestOrigin;
  if (requestOrigin && allowOrigin !== '*' && allowOrigin === requestOrigin) {
    findings.push(normalizeFinding({
      ruleId: 'A02-CORS-002',
      owaspCategory: 'A02',
      title: 'CORS: server phản chiếu (reflect) Origin từ request không kiểm tra',
      severity: 'high',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'response headers',
      evidence: [
        `Request Origin: ${requestOrigin}`,
        `Access-Control-Allow-Origin: ${allowOrigin}`,
        'Server echo nguyên xi Origin -> bất kỳ domain nào cũng được phép cross-origin.',
      ],
      remediation:
        'Validate Origin so với allowlist cứng trước khi echo lại.\n' +
        'Không dùng pattern như: res.setHeader("Access-Control-Allow-Origin", req.headers.origin)',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing',
      ],
      collector: 'blackbox'
    }));
  }

  if (allowMethods) {
    const foundDangerous = DANGEROUS_METHODS_FOR_CORS.filter((m) =>
      allowMethods.toUpperCase().includes(m)
    );
    if (foundDangerous.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A02-CORS-004',
        owaspCategory: 'A02',
        title: 'CORS cho phép methods có thể thay đổi dữ liệu',
        severity: 'low',
        confidence: 'medium',
        target: context.finalUrl,
        location: 'response headers',
        evidence: [
          `Access-Control-Allow-Methods: ${allowMethods}`,
          `Methods đáng chú ý: ${foundDangerous.join(', ')}`,
        ],
        remediation:
          'Giới hạn Access-Control-Allow-Methods chỉ cho phép các method thực sự cần thiết.\n' +
          'VD: Access-Control-Allow-Methods: GET, POST',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing',
        ],
        collector: 'blackbox'
      }));
    }
  }

  if (allowHeaders.trim() === '*') {
    findings.push(normalizeFinding({
      ruleId: 'A02-CORS-005',
      owaspCategory: 'A02',
      title: 'CORS cho phép wildcard request headers',
      severity: 'low',
      confidence: 'high',
      target: context.finalUrl,
      location: 'response headers',
      evidence: ['Access-Control-Allow-Headers: *'],
      remediation:
        'Chỉ định danh sách header cụ thể được phép.\n' +
        'VD: Access-Control-Allow-Headers: Content-Type, Authorization',
      references: [
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers',
      ],
      collector: 'blackbox'
    }));
  }

  if (allowOrigin && allowOrigin !== '*' && !varyHeader.toLowerCase().includes('origin')) {
    findings.push(normalizeFinding({
      ruleId: 'A02-CORS-006',
      owaspCategory: 'A02',
      title: 'Thiếu "Vary: Origin" khi CORS origin là dynamic',
      severity: 'low',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'response headers',
      evidence: [
        `Access-Control-Allow-Origin: ${allowOrigin}`,
        `Vary: ${varyHeader || '(không có)'}`,
        'Thiếu Vary: Origin có thể gây cache poisoning qua proxy.',
      ],
      remediation:
        'Thêm "Vary: Origin" vào response khi Access-Control-Allow-Origin là dynamic.\n' +
        'Điều này đảm bảo proxy/CDN không cache nhầm response cho origin khác.',
      references: [
        'https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches',
      ],
      collector: 'blackbox'
    }));
  }

  return findings;
}

module.exports = { runCorsMisconfig };

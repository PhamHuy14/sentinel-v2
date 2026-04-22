const { normalizeFinding } = require('../../models/finding');

const WEBDAV_METHODS = ['PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK'];

function runDangerousMethods(context) {
  const findings = [];
  const allow = context.allowMethods || '';
  if (!allow) return findings;

  const methods = allow.split(',').map((m) => m.trim().toUpperCase());

  if (methods.includes('PUT')) {
    findings.push(normalizeFinding({
      ruleId: 'A02-METHOD-002',
      owaspCategory: 'A02',
      title: 'HTTP PUT method đang được bật',
      severity: 'high',
      confidence: 'high',
      target: context.scannedUrl,
      location: 'Allow header',
      evidence: [`Allow: ${allow}`],
      remediation:
        'Tắt PUT method trừ khi đây là REST API có xác thực và phân quyền đầy đủ.\n' +
        '• Apache: <LimitExcept GET POST> Deny from all </LimitExcept>\n' +
        '• nginx: limit_except GET POST { deny all; }',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
      ],
      collector: 'blackbox'
    }));
  }

  if (methods.includes('DELETE')) {
    findings.push(normalizeFinding({
      ruleId: 'A02-METHOD-003',
      owaspCategory: 'A02',
      title: 'HTTP DELETE method đang được bật',
      severity: 'high',
      confidence: 'high',
      target: context.scannedUrl,
      location: 'Allow header',
      evidence: [`Allow: ${allow}`],
      remediation:
        'Tắt DELETE method trừ khi cần thiết và có kiểm soát phân quyền chặt chẽ.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
      ],
      collector: 'blackbox'
    }));
  }

  if (methods.includes('CONNECT')) {
    findings.push(normalizeFinding({
      ruleId: 'A02-METHOD-004',
      owaspCategory: 'A02',
      title: 'HTTP CONNECT method đang được bật',
      severity: 'medium',
      confidence: 'high',
      target: context.scannedUrl,
      location: 'Allow header',
      evidence: [`Allow: ${allow}`],
      remediation:
        'Tắt CONNECT method. CONNECT có thể cho phép dùng server như một proxy để tấn công bên thứ ba.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
      ],
      collector: 'blackbox'
    }));
  }

  if (methods.includes('TRACE')) {
    findings.push(normalizeFinding({
      ruleId: 'A02-METHOD-006',
      owaspCategory: 'A02',
      title: 'HTTP TRACE method đang bật - có nguy cơ Cross-Site Tracing (XST)',
      severity: 'medium',
      confidence: 'high',
      target: context.scannedUrl,
      location: 'Allow header',
      evidence: [`Allow: ${allow}`],
      remediation:
        'Tắt TRACE method trên web server.\n' +
        '• Apache: TraceEnable Off\n' +
        '• nginx: Không hỗ trợ natively, dùng rewrite rule để block\n' +
        'TRACE có thể bị khai thác trong XST attack để bypass HttpOnly cookie protection.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
        'https://www.cgisecurity.com/whitehat-mirror/WH-WhitePaper_XST_ebook.pdf',
      ],
      collector: 'blackbox'
    }));
  }

  const foundWebdav = WEBDAV_METHODS.filter((m) => methods.includes(m));
  if (foundWebdav.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A02-METHOD-005',
      owaspCategory: 'A02',
      title: 'WebDAV methods đang được bật',
      severity: 'medium',
      confidence: 'high',
      target: context.scannedUrl,
      location: 'Allow header',
      evidence: [
        `Allow: ${allow}`,
        `WebDAV methods tìm thấy: ${foundWebdav.join(', ')}`,
      ],
      remediation:
        'Tắt WebDAV nếu không cần thiết. WebDAV có thể cho phép browse, upload và xóa file.\n' +
        '• Apache: Tắt module mod_dav\n' +
        '• IIS: Tắt WebDAV trong IIS Manager',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
      ],
      collector: 'blackbox'
    }));
  }

  return findings;
}

module.exports = { runDangerousMethods };

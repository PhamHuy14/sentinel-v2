const { normalizeFinding } = require('../../models/finding');

const MAX_BODY_SCAN = 500 * 1024; // 500 KB để tránh regex quá chậm

/**
 * A02-TLS: Phát hiện các vấn đề transport layer security.
 * Theo OWASP OTG-CRYPST-001 va OTG-CRYPST-003.
 *
 * @param {object} context
 * @param {string} context.finalUrl
 * @param {string} context.protocol
 * @param {string} [context.text]
 * @param {string} [context.contentType]
 * @param {boolean} [context.isLocalhost]
 * @param {object} [context.tlsInfo]
 * @returns {Array} findings
 */
function runTransportSecurity(context) {
  const findings = [];
  const { finalUrl, protocol, isLocalhost, tlsInfo } = context;
  const html = String(context.text || '').slice(0, MAX_BODY_SCAN);
  const isHtml = String(context.contentType || '').toLowerCase().includes('text/html');
  const isHttps = protocol === 'https:';

  if (isHttps && isHtml && html) {
    const mixedUrls = [];
    const srcPattern = /(?:src|href|action)=["']?(http:\/\/[^"'\s>]+)/gi;
    let m;
    while ((m = srcPattern.exec(html)) !== null && mixedUrls.length < 5) {
      const url = m[1];
      if (!url.includes('example.com') && !url.includes('localhost')) {
        mixedUrls.push(url);
      }
    }
    if (mixedUrls.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A02-TLS-001',
        owaspCategory: 'A02',
        title: 'Mixed Content: tai nguyen HTTP ben trong trang HTTPS',
        severity: 'high',
        confidence: 'high',
        target: finalUrl,
        location: 'response body',
        evidence: [
          'Trang HTTPS tải tài nguyên qua HTTP không mã hóa:',
          ...mixedUrls,
        ],
        remediation:
          'Thay tất cả URL tài nguyên thành HTTPS hoặc dùng protocol-relative URLs (//...).\n' +
          'Thêm CSP directive: upgrade-insecure-requests hoặc block-all-mixed-content.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels',
          'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content',
        ],
        collector: 'blackbox',
      }));
    }
  }

  if (isHttps && isHtml && html) {
    const formPattern = /<form[^>]+action=["']?(http:\/\/[^"'\s>]+)/gi;
    const httpForms = [];
    let fm;
    while ((fm = formPattern.exec(html)) !== null && httpForms.length < 3) {
      httpForms.push(fm[1]);
    }
    if (httpForms.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A02-TLS-002',
        owaspCategory: 'A02',
        title: 'Form submit credentials qua HTTP endpoint trên trang HTTPS',
        severity: 'high',
        confidence: 'high',
        target: finalUrl,
        location: 'response body → <form action>',
        evidence: [
          'Các form action trỏ về HTTP:',
          ...httpForms,
        ],
        remediation:
          'Đổi tất cả form action sang HTTPS. Thông tin đăng nhập gửi qua HTTP có thể bị chặn đọc.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels',
        ],
        collector: 'blackbox',
      }));
    }
  }

  if (!isHttps && !isLocalhost) {
    const productionDomainPattern = /^(www\.|app\.|api\.|portal\.|admin\.)/i;
    let hostname = '';
    try {
      hostname = new URL(finalUrl).hostname;
    } catch (_e) {
      hostname = '';
    }

    const looksLikeProduction =
      productionDomainPattern.test(hostname) ||
      (hostname &&
        !hostname.includes('.local') &&
        !hostname.includes('.test') &&
        !hostname.includes('.dev') &&
        !hostname.includes('.internal'));

    if (looksLikeProduction) {
      findings.push(normalizeFinding({
        ruleId: 'A02-TLS-003',
        owaspCategory: 'A02',
        title: 'Ứng dụng phục vụ qua HTTP không mã hóa',
        severity: 'medium',
        confidence: 'medium',
        target: finalUrl,
        location: 'URL scheme',
        evidence: [`URL: ${finalUrl}`, 'Protocol: HTTP (không có TLS)'],
        remediation:
          'Triển khai TLS/HTTPS cho toàn bộ ứng dụng.\n' +
          'Thêm redirect HTTP -> HTTPS và bật HSTS.\n' +
          'Dùng Let\'s Encrypt để cấp chứng chỉ miễn phí.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_TLS',
        ],
        collector: 'blackbox',
      }));
    }
  }

  if (isHttps && tlsInfo && tlsInfo.protocol) {
    const tlsProto = String(tlsInfo.protocol).toLowerCase();
    if (tlsProto.includes('ssl') || tlsProto === 'tlsv1' || tlsProto === 'tlsv1.1') {
      const isCritical = tlsProto.includes('ssl');
      findings.push(normalizeFinding({
        ruleId: 'A02-TLS-004',
        owaspCategory: 'A02',
        title: `Sử dụng protocol TLS/SSL lỗi thời: ${tlsInfo.protocol}`,
        severity: isCritical ? 'critical' : 'high',
        confidence: 'high',
        target: finalUrl,
        location: 'TLS handshake',
        evidence: [
          `Negotiated protocol: ${tlsInfo.protocol}`,
          tlsInfo.cipher ? `Cipher: ${tlsInfo.cipher}` : '',
        ].filter(Boolean),
        remediation:
          'Chỉ cho phép TLS 1.2 và TLS 1.3.\n' +
          'Tắt SSLv2, SSLv3, TLS 1.0 và TLS 1.1 trong cấu hình server.\n' +
          '• Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n' +
          '• nginx: ssl_protocols TLSv1.2 TLSv1.3;',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_TLS',
        ],
        collector: 'blackbox',
      }));
    }
  }

  return findings;
}

module.exports = { runTransportSecurity };

const { normalizeFinding } = require('../../models/finding');

const A04_REF = 'https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/';
const OTG_CRYPT_001 = 'https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security';
const OTG_CRYPT_003 = 'https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels';

const MAX_BODY_SCAN = 500 * 1024;

function isHtmlContent(context) {
  const ct = String(context.contentType || '').toLowerCase();
  const body = String(context.text || '');
  return ct.includes('text/html') || /<html|<head|<body|<script|<form/i.test(body);
}

function runTransportSecurityA04(context) {
  const findings = [];
  try {
    const protocol = String(context.protocol || '');
    const isHttps = protocol === 'https:';
    const isLocalhost = !!context.isLocalhost;
    const finalUrl = context.finalUrl || context.scannedUrl || '';
    const html = String(context.text || '').slice(0, MAX_BODY_SCAN);

    if (protocol === 'http:' && !isLocalhost) {
      findings.push(normalizeFinding({
        ruleId: 'A04-TRANSPORT-001',
        owaspCategory: 'A04',
        title: 'Ứng dụng production phục vụ qua HTTP không mã hóa',
        severity: 'high',
        confidence: 'medium',
        target: finalUrl,
        location: 'protocol',
        evidence: [`URL sử dụng HTTP: ${finalUrl}`],
        remediation: 'Bắt buộc HTTPS cho toàn bộ traffic và cấu hình redirect HTTP -> HTTPS.',
        references: [A04_REF, OTG_CRYPT_001, OTG_CRYPT_003],
        collector: 'blackbox'
      }));
    }

    const reqHeaders = context.requestHeaders || {};
    const authHeader = String(
      reqHeaders.authorization || reqHeaders.Authorization || ''
    );
    if (protocol === 'http:' && /^Basic\s+/i.test(authHeader)) {
      findings.push(normalizeFinding({
        ruleId: 'A04-TRANSPORT-002',
        owaspCategory: 'A04',
        title: 'Basic Authorization được gửi qua HTTP',
        severity: 'high',
        confidence: 'high',
        target: finalUrl,
        location: 'request header: Authorization',
        evidence: ['Authorization: Basic ... qua kênh HTTP không mã hóa'],
        remediation: 'Không dùng Basic Auth trên HTTP. Chuyển sang HTTPS và ưu tiên token-based auth.',
        references: [A04_REF, OTG_CRYPT_003],
        collector: 'blackbox'
      }));
    }

    if (!isHttps || !isHtmlContent(context)) return findings;

    const mixed = [];
    const mixedPatterns = [
      /(?:src|href)=["'](http:\/\/[^"']+)["']/gi,
      /url\(["']?(http:\/\/[^"')]+)["']?\)/gi,
    ];

    for (const re of mixedPatterns) {
      let m;
      while ((m = re.exec(html)) !== null && mixed.length < 5) {
        mixed.push(m[1]);
      }
    }

    if (mixed.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A04-TRANSPORT-003',
        owaspCategory: 'A04',
        title: 'Trang HTTPS tải tài nguyên qua HTTP (mixed content)',
        severity: 'medium',
        confidence: 'medium',
        target: finalUrl,
        location: 'response body (HTML/CSS)',
        evidence: mixed,
        remediation: 'Chuyển toàn bộ resource URL sang HTTPS hoặc dùng CSP upgrade-insecure-requests.',
        references: [A04_REF, OTG_CRYPT_003],
        collector: 'blackbox'
      }));
    }

    const insecureFormActions = [];
    const formRe = /<form[^>]+action=["'](http:\/\/[^"']+)["']/gi;
    let fm;
    while ((fm = formRe.exec(html)) !== null && insecureFormActions.length < 5) {
      insecureFormActions.push(fm[1]);
    }
    if (insecureFormActions.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A04-TRANSPORT-004',
        owaspCategory: 'A04',
        title: 'Form action trên trang HTTPS trỏ về endpoint HTTP',
        severity: 'high',
        confidence: 'high',
        target: finalUrl,
        location: 'response body -> form action',
        evidence: insecureFormActions,
        remediation: 'Bắt buộc form action gửi về HTTPS để tránh lộ dữ liệu submit.',
        references: [A04_REF, OTG_CRYPT_003],
        collector: 'blackbox'
      }));
    }
  } catch {
    return findings;
  }

  return findings;
}

module.exports = { runTransportSecurityA04 };

const { normalizeFinding } = require('../../models/finding');

const A04_REF = 'https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/';
const OTG_CONFIG_007 = 'https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security';
const OTG_CLIENT_010 = 'https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets';

const MAX_BODY_SCAN = 500 * 1024;

function isHtmlContent(context) {
  const ct = String(context.contentType || '').toLowerCase();
  const body = String(context.text || '');
  return ct.includes('text/html') || /<html|<head|<body|<script|<form/i.test(body);
}

function runHstsAndWebsocketA04(context) {
  const findings = [];
  try {
    const protocol = String(context.protocol || '');
    const isHttps = protocol === 'https:';
    const isLocalhost = !!context.isLocalhost;
    const finalUrl = context.finalUrl || context.scannedUrl || '';
    const headers = context.responseHeaders || {};

    if (isHttps && !isLocalhost) {
      const hsts = String(headers['strict-transport-security'] || headers['Strict-Transport-Security'] || '');
      if (!hsts.trim()) {
        findings.push(normalizeFinding({
          ruleId: 'A04-HSTS-001',
          owaspCategory: 'A04',
          title: 'HTTPS response thiếu Strict-Transport-Security (HSTS)',
          severity: 'medium',
          confidence: 'medium',
          target: finalUrl,
          location: 'response header: Strict-Transport-Security',
          evidence: ['Không tìm thấy header HSTS trên HTTPS response'],
          remediation: 'Thêm HSTS với max-age đủ dài, includeSubDomains và preload khi phù hợp.',
          references: [A04_REF, OTG_CONFIG_007],
          collector: 'blackbox'
        }));
      }
    }

    if (!isHttps || !isHtmlContent(context)) return findings;

    const body = String(context.text || '').slice(0, MAX_BODY_SCAN);
    const wsMatches = [];
    const wsRe = /ws:\/\/[^"'\s)]+/gi;
    let m;
    while ((m = wsRe.exec(body)) !== null && wsMatches.length < 5) {
      wsMatches.push(m[0]);
    }

    if (wsMatches.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A04-WS-001',
        owaspCategory: 'A04',
        title: 'Trang HTTPS chứa kết nối WebSocket không mã hóa (ws://)',
        severity: 'medium',
        confidence: 'high',
        target: finalUrl,
        location: 'response body (HTML/JS)',
        evidence: wsMatches,
        remediation: 'Dùng wss:// thay cho ws:// để bảo vệ confidentiality/integrity của WebSocket traffic.',
        references: [A04_REF, OTG_CLIENT_010],
        collector: 'blackbox'
      }));
    }
  } catch {
    return findings;
  }

  return findings;
}

module.exports = { runHstsAndWebsocketA04 };

const { normalizeFinding } = require('../../models/finding');

function runMissingSecurityHeaders(context) {
  const findings = [];
  const headers = context.headers || new Headers();
  const isHtml = (context.contentType || '').toLowerCase().includes('text/html');
  const isLocalhost = !!context.isLocalhost;

  if (!headers.get('x-content-type-options')) {
    findings.push(normalizeFinding({
      ruleId: 'A02-HDR-001',
      owaspCategory: 'A02',
      title: 'Thiếu X-Content-Type-Options',
      severity: isLocalhost ? 'low' : 'medium',
      confidence: 'high',
      target: context.finalUrl,
      location: 'response headers',
      evidence: [`Response từ ${context.finalUrl} không có X-Content-Type-Options.`],
      remediation: 'Thêm header `X-Content-Type-Options: nosniff` trong middleware hoặc reverse proxy.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'],
      collector: 'blackbox'
    }));
  }

  if (context.protocol === 'https:' && !isLocalhost && !headers.get('strict-transport-security')) {
    findings.push(normalizeFinding({
      ruleId: 'A02-HDR-002',
      owaspCategory: 'A02',
      title: 'Thiếu HSTS trên HTTPS',
      severity: 'medium',
      confidence: 'high',
      target: context.finalUrl,
      location: 'response headers',
      evidence: [`Response HTTPS từ ${context.finalUrl} không có Strict-Transport-Security.`],
      remediation: 'Bật HSTS cho môi trường production HTTPS.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'],
      collector: 'blackbox'
    }));
  }

  if (isHtml && !headers.get('content-security-policy')) {
    findings.push(normalizeFinding({
      ruleId: 'A02-HDR-003',
      owaspCategory: 'A02',
      title: 'Thiếu Content-Security-Policy',
      severity: isLocalhost ? 'low' : 'medium',
      confidence: 'high',
      target: context.finalUrl,
      location: 'response headers',
      evidence: [`Response HTML từ ${context.finalUrl} chưa có CSP.`],
      remediation: 'Bổ sung CSP phù hợp với script, style và asset đang dùng.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'],
      collector: 'blackbox'
    }));
  }

  return findings;
}

module.exports = { runMissingSecurityHeaders };

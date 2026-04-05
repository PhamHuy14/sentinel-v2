const { normalizeFinding } = require('../../models/finding');

function runHttpInsecure(context) {
  const findings = [];
  if (context.protocol === 'http:' && !context.isLocalhost) {
    findings.push(normalizeFinding({
      ruleId: 'A04-HTTP-001',
      owaspCategory: 'A04',
      title: 'Ứng dụng phục vụ qua HTTP không mã hóa',
      severity: 'high',
      confidence: 'high',
      target: context.finalUrl,
      location: 'protocol',
      evidence: [`URL sử dụng HTTP thay vì HTTPS: ${context.finalUrl}`],
      remediation: 'Chuyển toàn bộ traffic sang HTTPS. Dùng redirect 301 từ HTTP → HTTPS. Bật HSTS sau khi HTTPS ổn định.',
      references: ['https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/'],
      collector: 'blackbox'
    }));
  }
  return findings;
}

function runSensitiveDataExposure(context) {
  const findings = [];
  const text = context.text || '';
  const sensitivePatterns = [
    { re: /["']password["']\s*:\s*["'][^"']{3,}/i, label: 'Password field trong JSON response' },
    { re: /["']secret["']\s*:\s*["'][^"']{8,}/i, label: 'Secret field trong JSON response' },
    { re: /["']api[_-]?key["']\s*:\s*["'][^"']{8,}/i, label: 'API key trong response body' },
    { re: /-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----/, label: 'Private key lộ trong response' },
    { re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, label: 'JWT token trong response body' },
    { re: /\b[0-9]{16}\b/, label: 'Có thể là số thẻ tín dụng (16 chữ số liền)' },
  ];
  for (const pat of sensitivePatterns) {
    if (pat.re.test(text)) {
      findings.push(normalizeFinding({
        ruleId: 'A04-SENS-001',
        owaspCategory: 'A04',
        title: 'Có dấu hiệu dữ liệu nhạy cảm lộ trong response',
        severity: 'high',
        confidence: 'medium',
        target: context.finalUrl,
        location: 'response body',
        evidence: [pat.label],
        remediation: 'Không trả dữ liệu nhạy cảm về client. Mask hoặc loại bỏ các trường password/secret/key khỏi API response.',
        references: ['https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/'],
        collector: 'blackbox'
      }));
      break;
    }
  }
  return findings;
}

function runMixedContent(context) {
  const findings = [];
  if (context.protocol !== 'https:') return findings;
  const text = context.text || '';
  const httpResources = [
    ...text.matchAll(/src=["']http:\/\/[^"']+["']/gi),
    ...text.matchAll(/href=["']http:\/\/[^"']+["']/gi),
  ].slice(0, 5);
  if (httpResources.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A04-MIXED-001',
      owaspCategory: 'A04',
      title: 'Trang HTTPS load resource qua HTTP (mixed content)',
      severity: 'medium',
      confidence: 'high',
      target: context.finalUrl,
      location: 'HTML resource links',
      evidence: httpResources.map(m => m[0].slice(0, 100)),
      remediation: 'Đổi tất cả resource URLs sang HTTPS hoặc protocol-relative (//). Mixed content bị block bởi browser hiện đại.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content'],
      collector: 'blackbox'
    }));
  }
  return findings;
}

function runCookieSecureOnHttps(context) {
  if (context.protocol !== 'https:' || context.isLocalhost) return [];
  const insecureCookies = (context.setCookies || []).filter(c => !/\bsecure\b/i.test(c));
  if (!insecureCookies.length) return [];
  return [normalizeFinding({
    ruleId: 'A04-COOKIE-SEC-001',
    owaspCategory: 'A04',
    title: 'Cookie trên HTTPS không có Secure flag — có thể gửi qua HTTP',
    severity: context.isLocalhost ? 'low' : 'medium',
    confidence: 'high',
    target: context.finalUrl,
    location: 'Set-Cookie headers',
    evidence: insecureCookies.slice(0, 3).map(c => `${c.split('=')[0]}: thiếu Secure`),
    remediation: 'Thêm Secure attribute vào mọi Set-Cookie khi chạy HTTPS.',
    references: ['https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/'],
    collector: 'blackbox'
  })];
}

module.exports = { runHttpInsecure, runSensitiveDataExposure, runMixedContent, runCookieSecureOnHttps };

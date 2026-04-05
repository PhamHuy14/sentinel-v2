const { normalizeFinding } = require('../../models/finding');

function runDebugExposure(context) {
  const html = context.text || '';
  const findings = [];
  const titles = [
    { marker: /swagger ui/i, title: 'Có dấu hiệu Swagger UI public' },
    { marker: /phpinfo\(/i, title: 'Có dấu hiệu phpinfo public' },
    { marker: /actuator/i, title: 'Có dấu hiệu actuator/debug endpoint public' }
  ];
  for (const t of titles) {
    if (t.marker.test(html)) {
      findings.push(normalizeFinding({
        ruleId: 'A02-DEBUG-001',
        owaspCategory: 'A02',
        title: t.title,
        severity: 'medium',
        confidence: 'medium',
        target: context.finalUrl,
        location: 'response body',
        evidence: ['HTML chứa dấu hiệu trang debug/tooling công khai.'],
        remediation: 'Ẩn hoặc giới hạn quyền truy cập các endpoint debug/tooling trên môi trường public.',
        references: ['https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/'],
        collector: 'blackbox'
      }));
    }
  }
  return findings;
}

module.exports = { runDebugExposure };

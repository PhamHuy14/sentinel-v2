const { normalizeFinding } = require('../../models/finding');

function runForcedBrowsing(context) {
  const findings = [];
  for (const path of ['/admin', '/swagger', '/debug']) {
    const info = context.surfaceStatus?.[path];
    if (!info || !info.status) continue;
    if (info.status === 200 && !info.redirectedToLogin) {
      findings.push(normalizeFinding({
        ruleId: 'A01-FB-001',
        owaspCategory: 'A01',
        title: 'Có bề mặt quản trị hoặc tooling truy cập được trực tiếp',
        severity: context.isLocalhost ? 'low' : 'medium',
        confidence: 'medium',
        target: `${context.origin}${path}`,
        location: path,
        evidence: [`Endpoint ${path} trả về HTTP ${info.status} và không có dấu hiệu redirect/login gate.`],
        remediation: 'Giới hạn quyền truy cập hoặc loại bỏ bề mặt không cần public.',
        references: ['https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/'],
        collector: 'blackbox'
      }));
    }
  }
  return findings;
}

module.exports = { runForcedBrowsing };

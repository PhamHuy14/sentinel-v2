const { normalizeFinding } = require('../../models/finding');

function runCommandInjectionHeuristic(context) {
  const text = context.text || '';
  if (/uid=\d+\(|root:x:0:0:|cmd\.exe|powershell/i.test(text)) {
    return [normalizeFinding({
      ruleId: 'A05-CMD-001',
      owaspCategory: 'A05',
      title: 'Có dấu hiệu command injection / OS command exposure',
      severity: 'critical',
      confidence: 'low',
      target: context.finalUrl,
      location: 'response body',
      evidence: ['Response chứa chuỗi giống output lệnh hệ điều hành.'],
      remediation: 'Loại bỏ shell invocation dựa trên input người dùng và dùng allowlist/parameterization phù hợp.',
      references: ['https://owasp.org/Top10/2025/A05_2025-Injection/'],
      collector: 'blackbox'
    })];
  }
  return [];
}

module.exports = { runCommandInjectionHeuristic };

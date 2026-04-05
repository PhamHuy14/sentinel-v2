const { normalizeFinding } = require('../../models/finding');

function runMalformedInput(context) {
  if (context.status >= 500) {
    return [normalizeFinding({
      ruleId: 'A10-MAL-001',
      owaspCategory: 'A10',
      title: 'Ứng dụng trả lỗi server ở đầu vào hiện tại, cần test thêm fail-safe behavior',
      severity: 'medium',
      confidence: 'low',
      target: context.finalUrl,
      location: 'HTTP status',
      evidence: [`HTTP status hiện tại: ${context.status}`],
      remediation: 'Xử lý đầu vào lỗi theo hướng fail-safe, nhất quán và không làm crash ứng dụng.',
      references: ['https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/'],
      collector: 'blackbox'
    })];
  }
  return [];
}

module.exports = { runMalformedInput };

const { normalizeFinding } = require('../../models/finding');

function runExceptionLeakage(context) {
  if (context.missingPathProbe?.hasVerboseErrors) {
    return [normalizeFinding({
      ruleId: 'A10-EX-001',
      owaspCategory: 'A10',
      title: 'Có dấu hiệu lộ exception/stack trace khi gặp tình huống bất thường',
      severity: 'high',
      confidence: 'high',
      target: context.missingPathProbe.url,
      location: 'error response',
      evidence: ['Response lỗi chứa chuỗi giống stack trace hoặc exception.'],
      remediation: 'Ẩn chi tiết lỗi với client, log nội bộ đầy đủ và dùng fail-safe response nhất quán.',
      references: ['https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/'],
      collector: 'blackbox'
    })];
  }
  return [];
}

module.exports = { runExceptionLeakage };

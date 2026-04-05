const { normalizeFinding } = require('../../models/finding');

function runAuthEventLogging(context) {
  const corpus = (context.codeFiles || []).map((f) => f?.content || '').join('\n');
  const findings = [];
  const hasLoginCode = /login|signin|PasswordSignIn|SignInManager/i.test(corpus);
  const hasLogging = /logger|ilogger|loginformation|logwarning|logerror/i.test(corpus);
  if (hasLoginCode && !hasLogging) {
    findings.push(normalizeFinding({
      ruleId: 'A09-LOG-001',
      owaspCategory: 'A09',
      title: 'Có luồng auth nhưng chưa thấy dấu hiệu logging rõ ràng trong source mẫu',
      severity: 'medium',
      confidence: 'low',
      target: 'project source',
      location: 'codebase',
      evidence: ['Phát hiện dấu hiệu auth flow nhưng không thấy pattern logging phổ biến trong tập file đã quét.'],
      remediation: 'Log login success/fail, password reset, role change và sự kiện admin quan trọng.',
      references: ['https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/'],
      collector: 'source'
    }));
  }
  return findings;
}

module.exports = { runAuthEventLogging };

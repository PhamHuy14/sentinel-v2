const { normalizeFinding } = require('../../models/finding');

function runAccountEnumeration(context) {
  const findings = [];
  if (context.authHints?.hasForgotPasswordHint && /email not found|user not found|account does not exist/i.test(context.text || '')) {
    findings.push(normalizeFinding({
      ruleId: 'A07-ENUM-001',
      owaspCategory: 'A07',
      title: 'Có dấu hiệu account enumeration',
      severity: 'medium',
      confidence: 'low',
      target: context.finalUrl,
      location: 'response body',
      evidence: ['Trang/reset flow chứa thông báo có thể làm lộ tài khoản tồn tại hay không.'],
      remediation: 'Dùng thông báo chung, không phân biệt rõ tài khoản có tồn tại hay không.',
      references: ['https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/'],
      collector: 'blackbox'
    }));
  }
  return findings;
}

module.exports = { runAccountEnumeration };

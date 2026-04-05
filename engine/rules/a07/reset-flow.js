const { normalizeFinding } = require('../../models/finding');

function runResetFlow(context) {
  if (context.authHints?.hasForgotPasswordHint && !/captcha|rate limit|try again later/i.test(context.text || '')) {
    return [normalizeFinding({
      ruleId: 'A07-RESET-001',
      owaspCategory: 'A07',
      title: 'Reset password flow cần rà soát thêm throttling/abuse controls',
      severity: 'low',
      confidence: 'low',
      target: context.finalUrl,
      location: 'password reset flow',
      evidence: ['Phát hiện hint reset password nhưng chưa thấy dấu hiệu protection rõ ràng từ giao diện.'],
      remediation: 'Bổ sung throttling, generic messages và xác minh bổ sung cho reset flow.',
      references: ['https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/'],
      collector: 'blackbox'
    })];
  }
  return [];
}

module.exports = { runResetFlow };

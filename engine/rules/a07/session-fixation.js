const { normalizeFinding } = require('../../models/finding');

function runSessionFixation(context) {
  const setCookies = context.setCookies || [];
  const sessionLike = setCookies.find((c) => /session|auth|identity|token/i.test(c));
  const hasAuthHint = context.authHints?.hasLoginHint || false;
  if (hasAuthHint && sessionLike && !/secure/i.test(sessionLike)) {
    return [normalizeFinding({
      ruleId: 'A07-SESSION-001',
      owaspCategory: 'A07',
      title: 'Session cookie trong luồng auth có thuộc tính yếu',
      severity: 'medium',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'Set-Cookie',
      evidence: [sessionLike],
      remediation: 'Đảm bảo rotate session hợp lý và áp dụng Secure/HttpOnly/SameSite cho cookie xác thực.',
      references: ['https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/'],
      collector: 'blackbox'
    })];
  }
  return [];
}

module.exports = { runSessionFixation };

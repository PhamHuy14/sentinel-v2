const { normalizeFinding } = require('../../models/finding');
const { collectCookieIssues } = require('../../collectors/blackbox/header-collector');

function runCookieFlags(context) {
  const setCookies = context.setCookies || [];
  const issues = collectCookieIssues(setCookies);
  return issues.map((issue) => normalizeFinding({
    ruleId: 'A02-COOKIE-001',
    owaspCategory: 'A02',
    title: 'Cookie thiếu thuộc tính bảo mật',
    severity: 'medium',
    confidence: 'high',
    target: context.finalUrl,
    location: 'Set-Cookie',
    evidence: [issue],
    remediation: 'Đối với cookie nhạy cảm, thêm HttpOnly, Secure và SameSite.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'],
    collector: 'blackbox'
  }));
}

module.exports = { runCookieFlags };

const { normalizeFinding } = require('../../models/finding');
const { hasCsrfToken, detectPostForms } = require('../../collectors/blackbox/form-analyzer');

function runCsrfHeuristic(context) {
  const forms = context.forms || [];
  const postForms = detectPostForms(forms);
  if (!postForms.length) return [];

  const contentType = (context.contentType || '').toLowerCase();
  if (contentType && !contentType.includes('text/html')) return [];

  const hasSameSiteCookie = (context.cookieFlags || []).some(c =>
    ['lax', 'strict'].includes((c.sameSite || '').toLowerCase())
  );
  const hasToken = hasCsrfToken(context.text || '');
  if (hasToken || hasSameSiteCookie) return [];

  return [normalizeFinding({
    ruleId: 'A01-CSRF-001',
    owaspCategory: 'A01',
    title: 'Form POST có thể thiếu anti-CSRF token',
    severity: context.isLocalhost ? 'low' : 'medium',
    confidence: 'low',
    target: context.finalUrl,
    location: 'HTML forms',
    evidence: [
      `Tìm thấy ${postForms.length} form POST trong HTML nhưng chưa thấy token chống CSRF phổ biến.`,
      hasSameSiteCookie ? 'Đã thấy SameSite cookie.' : 'Không thấy cookie auth có SameSite=Lax/Strict.'
    ],
    remediation: 'Bổ sung anti-forgery token cho form POST và validate token ở backend.',
    references: ['https://owasp.org/www-community/attacks/csrf'],
    collector: 'blackbox'
  })];
}

module.exports = { runCsrfHeuristic };

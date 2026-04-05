const { normalizeFinding } = require('../../models/finding');

function runIdorHeuristic(context) {
  const html = context.text || '';
  const matches = html.match(/(?:[?&/])(id|userId|orderId|productId|categoryId)=?\d+/gi) || [];
  const unique = [...new Set(matches)].slice(0, 8);
  if (!unique.length) return [];
  return [normalizeFinding({
    ruleId: 'A01-IDOR-001',
    owaspCategory: 'A01',
    title: 'Có dấu hiệu endpoint/object identifier cần review quyền truy cập',
    severity: 'medium',
    confidence: 'medium',
    target: context.finalUrl,
    location: 'response body',
    evidence: [`Các mẫu định danh tìm thấy: ${unique.join(', ')}`],
    remediation: 'Rà soát ownership check và authorization cho các endpoint thao tác theo ID.',
    references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References'],
    collector: 'blackbox'
  })];
}

module.exports = { runIdorHeuristic };

const { normalizeFinding } = require('../../models/finding');

function runSqliErrorBased(context) {
  const text = context.text || '';
  if (/sql syntax|mysql|postgres|sqlite|odbc|sqlserver|database error/i.test(text)) {
    return [normalizeFinding({
      ruleId: 'A05-SQLI-001',
      owaspCategory: 'A05',
      title: 'Có dấu hiệu lộ lỗi cơ sở dữ liệu / SQL error leakage',
      severity: 'high',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'response body',
      evidence: ['Response chứa chuỗi gợi ý lỗi SQL hoặc database error.'],
      remediation: 'Ẩn lỗi chi tiết với người dùng cuối và rà soát query parameterization.',
      references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection'],
      collector: 'blackbox'
    })];
  }
  return [];
}

module.exports = { runSqliErrorBased };

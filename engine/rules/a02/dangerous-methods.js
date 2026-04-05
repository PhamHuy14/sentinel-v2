const { normalizeFinding } = require('../../models/finding');

function runDangerousMethods(context) {
  const allow = context.allowMethods || '';
  if (/\bTRACE\b/i.test(allow)) {
    return [normalizeFinding({
      ruleId: 'A02-METHOD-001',
      owaspCategory: 'A02',
      title: 'TRACE method đang được bật',
      severity: 'medium',
      confidence: 'high',
      target: context.scannedUrl,
      location: 'Allow header',
      evidence: [`Allow: ${allow}`],
      remediation: 'Tắt TRACE trên reverse proxy hoặc web server nếu không có nhu cầu đặc biệt.',
      references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods'],
      collector: 'blackbox'
    })];
  }
  return [];
}

module.exports = { runDangerousMethods };

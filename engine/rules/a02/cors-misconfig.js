const { normalizeFinding } = require('../../models/finding');

function runCorsMisconfig(context) {
  const findings = [];
  const headers = context.headers || new Headers();
  const allowOrigin = headers.get('access-control-allow-origin');
  const allowCredentials = headers.get('access-control-allow-credentials');
  if (allowOrigin === '*') {
    findings.push(normalizeFinding({
      ruleId: 'A02-CORS-001',
      owaspCategory: 'A02',
      title: 'CORS cho phép wildcard origin',
      severity: 'medium',
      confidence: 'high',
      target: context.finalUrl,
      location: 'response headers',
      evidence: [`Access-Control-Allow-Origin: *`, allowCredentials ? `Access-Control-Allow-Credentials: ${allowCredentials}` : ''].filter(Boolean),
      remediation: 'Giới hạn origin theo allowlist cụ thể; không kết hợp wildcard với dữ liệu nhạy cảm.',
      references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing'],
      collector: 'blackbox'
    }));
  }
  return findings;
}

module.exports = { runCorsMisconfig };

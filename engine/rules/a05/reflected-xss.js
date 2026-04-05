const { normalizeFinding } = require('../../models/finding');

function runReflectedXss(context) {
  const text = context.text || '';
  const findings = [];
  const markers = ['<script>alert(1337)</script>', 'OWASP_XSS_PROBE_2025'];
  for (const marker of markers) {
    if (text.includes(marker)) {
      findings.push(normalizeFinding({
        ruleId: 'A05-XSS-001',
        owaspCategory: 'A05',
        title: 'Có dấu hiệu reflected XSS hoặc phản chiếu input chưa encode',
        severity: 'high',
        confidence: 'medium',
        target: context.finalUrl,
        location: 'response body',
        evidence: [`Marker phản chiếu lại trong response: ${marker}`],
        remediation: 'Encode output theo đúng context và tránh render input người dùng trực tiếp vào HTML/script.',
        references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting'],
        collector: 'blackbox'
      }));
    }
  }
  return findings;
}

module.exports = { runReflectedXss };

const { normalizeFinding } = require('../../models/finding');

function runGenericProjectChecks(context) {
  const findings = [];
  const codeContent = (context.codeFiles || []).map((f) => f?.content || '').join('\n');
  const configContent = (context.configFiles || []).map((f) => f?.content || '').join('\n');

  if (!/validate|sanitize|escape|encode|parameterized|prepared statement/i.test(codeContent)) {
    findings.push(normalizeFinding({
      ruleId: 'GEN-INPUT-001',
      owaspCategory: 'A03',
      title: 'Chưa thấy dấu hiệu validation/escaping input rõ ràng (heuristic)',
      severity: 'medium',
      confidence: 'low',
      target: 'project source',
      location: 'codebase',
      evidence: ['Phát hiện không thấy pattern validation hoặc escaping phổ biến trong code samples.'],
      remediation: 'Bổ sung validation input ở frontend/backend; escape output theo context.',
      references: ['https://owasp.org/Top10/2025/A03_2025-Injection/'],
      collector: 'source'
    }));
  }

  if (!/content-security-policy|x-frame-options|x-content-type|strict-transport|hsts/i.test(configContent) &&
      !/app\.use.*security|helmet|security headers/i.test(codeContent)) {
    findings.push(normalizeFinding({
      ruleId: 'GEN-HEADERS-001',
      owaspCategory: 'A02',
      title: 'Chưa tìm thấy cấu hình security headers (heuristic)',
      severity: 'medium',
      confidence: 'low',
      target: 'project config',
      location: 'middleware/config',
      evidence: ['Không thấy configuration cho Content-Security-Policy, X-Frame-Options hoặc security middleware.'],
      remediation: 'Thêm security headers middleware hoặc web.config; sử dụng helmet (Node.js) hoặc tương đương.',
      references: ['https://owasp.org/Top10/2025/A02_2025-Cryptographic_Failures/'],
      collector: 'source'
    }));
  }

  if ((context.files || []).length > 50) {
    findings.push(normalizeFinding({
      ruleId: 'GEN-SCALE-001',
      owaspCategory: 'A04',
      title: 'Project kích thước lớn - cần security review toàn diện',
      severity: 'low',
      confidence: 'high',
      target: 'project scale',
      location: 'project metrics',
      evidence: [`Project có ${context.files.length} files - kích thước lớn, cần design review.`],
      remediation: 'Thực hiện threat modeling, architecture review, và security testing chi tiết.',
      references: ['https://owasp.org/Top10/2025/A04_2025-Insecure_Design/'],
      collector: 'source'
    }));
  }

  return findings;
}

module.exports = { runGenericProjectChecks };

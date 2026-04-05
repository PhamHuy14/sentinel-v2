const { normalizeFinding } = require('../../models/finding');

function runNpmDependencyRisk(context) {
  const findings = [];
  const text = context.packageJson || '';
  if (!text) return findings;
  try {
    const data = JSON.parse(text);
    const deps = { ...(data.dependencies || {}), ...(data.devDependencies || {}) };
    const count = Object.keys(deps).length;
    if (count > 80) {
      findings.push(normalizeFinding({
        ruleId: 'A03-NPM-001',
        owaspCategory: 'A03',
        title: 'Dự án có dependency footprint lớn',
        severity: 'low',
        confidence: 'high',
        target: context.packageJsonPath,
        location: 'package.json',
        evidence: [`Tổng số dependencies/devDependencies: ${count}`],
        remediation: 'Rà soát dependency không dùng đến, pin version có chủ đích và kiểm soát chuỗi cung ứng package.',
        references: ['https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/'],
        collector: 'source'
      }));
    }
    for (const [name, version] of Object.entries(deps)) {
      if (/latest|\*|x$/i.test(String(version))) {
        findings.push(normalizeFinding({
          ruleId: 'A03-NPM-002',
          owaspCategory: 'A03',
          title: 'Dependency dùng version quá lỏng',
          severity: 'medium',
          confidence: 'high',
          target: context.packageJsonPath,
          location: `dependency: ${name}`,
          evidence: [`${name}: ${version}`],
          remediation: 'Pin version rõ ràng thay vì dùng latest, * hoặc x.',
          references: ['https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/'],
          collector: 'source'
        }));
      }
    }
  } catch { /* ignore parse errors */ }
  return findings;
}

module.exports = { runNpmDependencyRisk };

const { normalizeFinding } = require('../../models/finding');

function runNugetDependencyRisk(context) {
  const findings = [];
  for (const file of context.csprojFiles || []) {
    const matches = [...file.content.matchAll(/<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"/gi)];
    if (matches.length > 35) {
      findings.push(normalizeFinding({
        ruleId: 'A03-NUGET-001',
        owaspCategory: 'A03',
        title: 'Project có số lượng NuGet package đáng kể',
        severity: 'low',
        confidence: 'high',
        target: file.path,
        location: '.csproj',
        evidence: [`Số PackageReference: ${matches.length}`],
        remediation: 'Rà soát package không dùng và quản lý version có chủ đích.',
        references: ['https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/'],
        collector: 'source'
      }));
    }
  }
  return findings;
}

module.exports = { runNugetDependencyRisk };

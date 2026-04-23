const { normalizeFinding } = require('../../models/finding');

function runNugetDependencyRisk(context) {
  const findings = [];
  try {
    for (const file of context.csprojFiles || []) {
      const content = file.content || '';

      const matches = [
        ...content.matchAll(/<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"/gi)
      ];

      // ── A03-NUGET-001: Quá nhiều NuGet packages ─────────────────────────────
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

      // ── A03-NUGET-002: Version wildcard / floating range ────────────────────
      for (const m of matches) {
        const [, pkgName, pkgVersion] = m;
        // NuGet wildcard: "1.0.*"  hoặc "*"
        // NuGet floating: "1.0.0-*" (pre-release floating)
        if (/\*|\+/.test(pkgVersion)) {
          findings.push(normalizeFinding({
            ruleId: 'A03-NUGET-002',
            owaspCategory: 'A03',
            title: 'NuGet package dùng version wildcard',
            severity: 'medium',
            confidence: 'high',
            target: file.path,
            location: `PackageReference: ${pkgName}`,
            evidence: [`${pkgName} Version="${pkgVersion}"`],
            remediation:
              'Wildcard version trong NuGet cho phép restore package ở version cao hơn bất ngờ. ' +
              'Pin version cụ thể và dùng Central Package Management (Directory.Packages.props) để kiểm soát toàn dự án.',
            references: [
              'https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/',
              'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration'
            ],
            collector: 'source'
          }));
        }
      }

      // ── A03-NUGET-003: AllowUnsafeBlocks enabled ────────────────────────────
      if (/<AllowUnsafeBlocks>\s*true\s*<\/AllowUnsafeBlocks>/i.test(content)) {
        findings.push(normalizeFinding({
          ruleId: 'A03-NUGET-003',
          owaspCategory: 'A03',
          title: 'AllowUnsafeBlocks được bật trong project',
          severity: 'low',
          confidence: 'high',
          target: file.path,
          location: '.csproj → <AllowUnsafeBlocks>',
          evidence: ['<AllowUnsafeBlocks>true</AllowUnsafeBlocks> tìm thấy trong .csproj'],
          remediation:
            'Unsafe code mở rộng attack surface khi kết hợp với vulnerable component. ' +
            'Chỉ bật khi thực sự cần thiết (interop thấp cấp), tách riêng vào assembly độc lập, ' +
            'và review kỹ tất cả unsafe block.',
          references: [
            'https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/',
            'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration'
          ],
          collector: 'source'
        }));
      }
    }
  } catch {
    return findings;
  }

  return findings;
}

module.exports = { runNugetDependencyRisk };

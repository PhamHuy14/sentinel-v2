const { normalizeFinding } = require('../../models/finding');

// .NET Target Frameworks đã đạt EOL (End of Life) — không còn nhận security patch
// Nguồn: https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-framework
const EOL_FRAMEWORKS = new Set([
  'net20', 'net35', 'net40', 'net45', 'net451', 'net452',
  'net46', 'net461', 'net462', 'net47', 'net471', 'net472',
  'netcoreapp1.0', 'netcoreapp1.1', 'netcoreapp2.0', 'netcoreapp2.1', 'netcoreapp2.2',
  'netcoreapp3.0',
  // .NET 5 EOL 2022-05
  'net5.0', 'net5.0-windows',
  // .NET 6 EOL 2024-11 (LTS nhưng đã hết support theo chu kỳ)
  'net6.0', 'net6.0-windows', 'net6.0-android', 'net6.0-ios'
]);

// web.config targetFramework versions cũ
const EOL_WEBCONFIG_VERSIONS = ['1.0', '1.1', '2.0', '3.5', '4.0', '4.5', '4.5.1', '4.5.2', '4.6', '4.6.1', '4.6.2', '4.7', '4.7.1', '4.7.2'];

function runDotnetFrameworkVersionRisk(context) {
  const findings = [];
  try {
    // ── A03-DOTNET-001: TargetFramework lỗi thời trong .csproj ──────────────
    for (const file of context.csprojFiles || []) {
      const content = file.content || '';

      // Hỗ trợ cả <TargetFramework> và <TargetFrameworks> (multi-target)
      const singleMatch = content.match(/<TargetFramework>([^<]+)<\/TargetFramework>/i);
      const multiMatch = content.match(/<TargetFrameworks>([^<]+)<\/TargetFrameworks>/i);

      const rawValue = (singleMatch || multiMatch || [])[1] || '';
      const frameworks = rawValue.split(';').map(f => f.trim().toLowerCase()).filter(Boolean);

      for (const fw of frameworks) {
        if (EOL_FRAMEWORKS.has(fw)) {
          findings.push(normalizeFinding({
            ruleId: 'A03-DOTNET-001',
            owaspCategory: 'A03',
            title: `Target framework "${fw}" đã đạt End-of-Life, không còn nhận security patch`,
            severity: 'high',
            confidence: 'high',
            target: file.path,
            location: `.csproj → <TargetFramework>`,
            evidence: [`TargetFramework: ${fw}`],
            remediation:
              'EOL framework không nhận security patch — component có known vulnerability sẽ không được vá. ' +
              'Nâng cấp lên .NET 8 (LTS, support đến 2026-11) hoặc .NET 9. ' +
              'Với .NET Framework, nâng lên 4.8.x là phiên bản cuối cùng vẫn được support.',
            references: [
              'https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/',
              'https://dotnet.microsoft.com/en-us/platform/support/policy',
              'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration'
            ],
            collector: 'source'
          }));
        }
      }
    }

    // ── A03-DOTNET-002: httpRuntime targetFramework trong web.config ─────────
    for (const file of context.webConfigFiles || []) {
      const content = file.content || '';

      // <httpRuntime targetFramework="4.5" ... />
      const runtimeMatch = content.match(/<httpRuntime[^>]+targetFramework\s*=\s*"([^"]+)"/i);
      if (runtimeMatch) {
        const tfVersion = runtimeMatch[1].trim();
        if (EOL_WEBCONFIG_VERSIONS.includes(tfVersion)) {
          findings.push(normalizeFinding({
            ruleId: 'A03-DOTNET-002',
            owaspCategory: 'A03',
            title: `httpRuntime targetFramework "${tfVersion}" trong web.config đã EOL`,
            severity: 'medium',
            confidence: 'high',
            target: file.path,
            location: 'web.config → <httpRuntime targetFramework>',
            evidence: [`targetFramework="${tfVersion}" trong <httpRuntime>`],
            remediation:
              'web.config targetFramework xác định behavior của ASP.NET pipeline. ' +
              'Version cũ có thể sử dụng các default không an toàn (ViewState encryption, request validation). ' +
              'Cập nhật lên 4.8 và review security settings tương ứng.',
            references: [
              'https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/',
              'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration'
            ],
            collector: 'source'
          }));
        }
      }
    }
  } catch {
    return findings;
  }

  return findings;
}

module.exports = { runDotnetFrameworkVersionRisk };

const { normalizeFinding } = require('../../models/finding');

function runNpmDependencyRisk(context) {
  const findings = [];
  try {
    const text = context.packageJson || '';
    if (!text) return findings;

    const data = JSON.parse(text);
    const deps = { ...(data.dependencies || {}), ...(data.devDependencies || {}) };
    const count = Object.keys(deps).length;

    // ── A03-NPM-001: Quá nhiều dependencies ──────────────────────────────────
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
      const v = String(version);

      // ── A03-NPM-002: Version quá lỏng (latest / * / x) ─────────────────────
      if (/^(latest|\*|x)$/i.test(v) || /\bx\b/.test(v)) {
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

      // ── A03-NPM-003: Local path dependency (file: / link:) ──────────────────
      if (/^(file:|link:)/i.test(v)) {
        findings.push(normalizeFinding({
          ruleId: 'A03-NPM-003',
          owaspCategory: 'A03',
          title: 'Dependency trỏ đến local path, bỏ qua registry integrity',
          severity: 'medium',
          confidence: 'high',
          target: context.packageJsonPath,
          location: `dependency: ${name}`,
          evidence: [`${name}: ${version}`],
          remediation:
            'Local path dependency bypass npm registry integrity check và signature verification. ' +
            'Chỉ dùng trong monorepo với workspace protocol, không dùng cho external package.',
          references: [
            'https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/',
            'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration'
          ],
          collector: 'source'
        }));
      }

      // ── A03-NPM-004: Dependency từ git URL trực tiếp ─────────────────────────
      if (/^(github:|gitlab:|bitbucket:|git\+https?:\/\/|git:\/\/|git:)/i.test(v)) {
        findings.push(normalizeFinding({
          ruleId: 'A03-NPM-004',
          owaspCategory: 'A03',
          title: 'Dependency cài trực tiếp từ git repository',
          severity: 'medium',
          confidence: 'high',
          target: context.packageJsonPath,
          location: `dependency: ${name}`,
          evidence: [`${name}: ${version}`],
          remediation:
            'OWASP khuyến nghị third-party libraries phải được security assess trước khi tích hợp. ' +
            'Git dependency không qua registry scan, không có audit trail. ' +
            'Publish package lên registry nội bộ hoặc dùng version từ npm registry.',
          references: [
            'https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/',
            'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration'
          ],
          collector: 'source'
        }));
      }
    }

    // ── A03-NPM-005: Thiếu lockfile ──────────────────────────────────────────
    if (context.hasLockfile === false) {
      findings.push(normalizeFinding({
        ruleId: 'A03-NPM-005',
        owaspCategory: 'A03',
        title: 'Không có lockfile (package-lock.json / yarn.lock / pnpm-lock.yaml)',
        severity: 'high',
        confidence: 'high',
        target: context.packageJsonPath,
        location: 'package.json',
        evidence: ['Không tìm thấy lockfile trong cùng thư mục với package.json'],
        remediation:
          'Commit lockfile vào source control để đảm bảo reproducible build. ' +
          'Thiếu lockfile cho phép npm install giải quyết version khác nhau giữa các môi trường, ' +
          'tạo nguy cơ dependency confusion hoặc cài version có vulnerability.',
        references: ['https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/'],
        collector: 'source'
      }));
    }

    // ── A03-NPM-006: Lifecycle script đáng ngờ ───────────────────────────────
    const dangerousScripts = ['preinstall', 'install', 'postinstall'];
    const scripts = data.scripts || {};
    for (const scriptName of dangerousScripts) {
      if (scripts[scriptName]) {
        findings.push(normalizeFinding({
          ruleId: 'A03-NPM-006',
          owaspCategory: 'A03',
          title: `Lifecycle script "${scriptName}" có thể thực thi code tùy ý khi cài package`,
          severity: 'medium',
          confidence: 'medium',
          target: context.packageJsonPath,
          location: `scripts.${scriptName}`,
          evidence: [`${scriptName}: ${scripts[scriptName]}`],
          remediation:
            'Lifecycle scripts chạy tự động khi npm install, là vector phổ biến trong supply chain attack ' +
            '(event-stream, node-ipc). Rà soát nội dung script, tránh dùng nếu không cần thiết, ' +
            'và cân nhắc dùng --ignore-scripts trong CI pipeline.',
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

module.exports = { runNpmDependencyRisk };

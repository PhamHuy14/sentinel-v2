const { normalizeFinding } = require('../../models/finding');

// ─── A03: Supply Chain ────────────────────────────────────────────────────────

function runPackageLockConsistency(context) {
  const findings = [];
  const packageJsonText = context.packageJson || '';
  const packageLockText = context.packageLockJson || '';
  if (!packageJsonText || !packageLockText) return findings;
  try {
    const lock = JSON.parse(packageLockText);
    if (lock.lockfileVersion === 1) {
      findings.push(normalizeFinding({
        ruleId: 'A03-LOCK-001',
        owaspCategory: 'A03',
        title: 'package-lock.json dùng lockfileVersion 1 (cũ)',
        severity: 'low',
        confidence: 'high',
        target: context.packageJsonPath,
        location: 'package-lock.json',
        evidence: ['lockfileVersion: 1 — npm v7+ dùng v2/v3 với security tốt hơn'],
        remediation: 'Chạy `npm install` với npm 7+ để upgrade lên lockfile v2/v3. Commit file mới.',
        references: ['https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/'],
        collector: 'source'
      }));
    }
    const noIntegrityPkgs = [];
    for (const [name, info] of Object.entries(lock.packages || {})) {
      if (name && !name.startsWith('node_modules/node_modules') && info && !info.integrity && !info.dev) {
        noIntegrityPkgs.push(name.replace('node_modules/', ''));
        if (noIntegrityPkgs.length >= 3) break;
      }
    }
    if (noIntegrityPkgs.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A03-LOCK-002',
        owaspCategory: 'A03',
        title: 'Một số package thiếu integrity hash trong package-lock.json',
        severity: 'medium',
        confidence: 'medium',
        target: context.packageJsonPath,
        location: 'package-lock.json',
        evidence: [`Packages thiếu integrity: ${noIntegrityPkgs.join(', ')}`],
        remediation: 'Chạy `npm ci` thay vì `npm install`. `npm ci` sẽ kiểm tra integrity hash của từng package.',
        references: ['https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/'],
        collector: 'source'
      }));
    }
  } catch { /* ignore */ }
  return findings;
}

function runTyposquattingRisk(context) {
  const findings = [];
  const packageJsonText = context.packageJson || '';
  if (!packageJsonText) return findings;
  const knownTypos = new Map([
    ['lodash', ['loadash', 'lodahs']],
    ['express', ['exprss', 'expresss']],
    ['react', ['reeact', 'reacts']],
    ['axios', ['axois', 'axio']],
    ['moment', ['momnet']],
    ['chalk', ['chak']],
    ['cross-env', ['cross-eve', 'crossenv']],
    ['webpack', ['webpak']],
  ]);
  try {
    const pkg = JSON.parse(packageJsonText);
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    const depNames = Object.keys(deps);
    for (const [legit, typos] of knownTypos) {
      for (const typo of typos) {
        if (depNames.includes(typo)) {
          findings.push(normalizeFinding({
            ruleId: 'A03-TYPO-001',
            owaspCategory: 'A03',
            title: `Package "${typo}" có thể là typosquat của "${legit}"`,
            severity: 'high',
            confidence: 'medium',
            target: context.packageJsonPath,
            location: `dependency: ${typo}`,
            evidence: [`"${typo}" trông giống typo của package phổ biến "${legit}"`],
            remediation: `Kiểm tra package "${typo}" là chủ đích hay chỉ là gõ nhầm. Nếu thực ra cần "${legit}", hãy sửa tên và chạy lại npm install.`,
            references: ['https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/'],
            collector: 'source'
          }));
        }
      }
    }
  } catch { /* ignore */ }
  return findings;
}

// ─── A08: Bảo mật CI/CD ───────────────────────────────────────────────────────

function runCiCdSecurityGates(context) {
  const findings = [];
  const allFiles = [...(context.configFiles || []), ...(context.textFiles || [])];
  const ciFiles = allFiles.filter(f => /\.github\/workflows|\.gitlab-ci|jenkinsfile|\.circleci/i.test(f.path));
  if (ciFiles.length === 0) return findings;

  const hasSast = ciFiles.some(f => /sast|sonar|semgrep|eslint.*security|bandit|snyk/i.test(f.content));
  const hasDependencyCheck = ciFiles.some(f => /npm audit|snyk|dependabot|dependency.?check/i.test(f.content));

  if (!hasSast) {
    findings.push(normalizeFinding({
      ruleId: 'A08-CI-001',
      owaspCategory: 'A08',
      title: 'Pipeline CI/CD không có dấu hiệu chạy SAST',
      severity: 'medium',
      confidence: 'low',
      target: ciFiles[0]?.path || 'CI config',
      location: 'CI/CD pipeline',
      evidence: ['Không phát hiện công cụ SAST (Semgrep, SonarQube, ESLint Security) trong workflow CI'],
      remediation: 'Tích hợp SAST vào pipeline CI. Có thể dùng Semgrep cho team nhỏ và chặn merge khi SAST thất bại.',
      references: ['https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/'],
      collector: 'source'
    }));
  }

  if (!hasDependencyCheck) {
    findings.push(normalizeFinding({
      ruleId: 'A08-CI-002',
      owaspCategory: 'A08',
      title: 'Pipeline CI/CD không có bước quét lỗ hổng dependency',
      severity: 'medium',
      confidence: 'low',
      target: ciFiles[0]?.path || 'CI config',
      location: 'CI/CD pipeline',
      evidence: ['Không phát hiện npm audit, Snyk hoặc Dependabot trong workflow CI'],
      remediation: 'Thêm `npm audit --audit-level=high` hoặc Snyk vào CI. Có thể dùng Dependabot trên GitHub để tạo PR tự động.',
      references: ['https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/'],
      collector: 'source'
    }));
  }
  return findings;
}

// ─── A09: Logging ─────────────────────────────────────────────────────────────

function runSensitiveDataInLogs(context) {
  const findings = [];
  const codeFiles = context.codeFiles || [];
  for (const file of codeFiles) {
    const content = file.content || '';
    if (/console\.log|logger\.(info|debug|log)/i.test(content)) {
      const logLines = content.split('\n').filter(line =>
        /console\.log|logger\.(info|debug|log)/i.test(line) &&
        /password|passwd|secret|token|api.?key|credential/i.test(line)
      );
      if (logLines.length > 0) {
        findings.push(normalizeFinding({
          ruleId: 'A09-SENSLOG-001',
          owaspCategory: 'A09',
          title: 'Có code log dữ liệu nhạy cảm (password/token)',
          severity: 'high',
          confidence: 'medium',
          target: file.path,
          location: file.path,
          evidence: logLines.slice(0, 2).map(l => l.trim().slice(0, 100)),
          remediation: 'Không bao giờ ghi log password, token hoặc secret. Dùng masking, ví dụ chỉ giữ 4 ký tự đầu + "***".',
          references: ['https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/'],
          collector: 'source'
        }));
        break;
      }
    }
  }
  return findings;
}

function runStructuredLogging(context) {
  const codeFiles = context.codeFiles || [];
  const corpus = codeFiles.map(f => f.content || '').join('\n');
  const hasLogging = /logger|console\.log|winston|pino|serilog|nlog/i.test(corpus);
  if (!hasLogging) return [];
  const hasStructuredLog = /winston|pino|bunyan|serilog|nlog|log4net/i.test(corpus);
  const usesConsoleOnly = /console\.(log|error|warn)/i.test(corpus) && !hasStructuredLog;
  if (usesConsoleOnly) {
    return [normalizeFinding({
      ruleId: 'A09-STRUCT-001',
      owaspCategory: 'A09',
      title: 'Sử dụng console.log thay vì logger có cấu trúc',
      severity: 'low',
      confidence: 'low',
      target: 'project source',
      location: 'codebase',
      evidence: ['Phát hiện console.log nhưng không thấy winston/pino/bunyan hoặc tương đương'],
      remediation: 'Dùng winston hoặc pino thay cho console.log. Log dạng JSON sẽ dễ tìm kiếm và tích hợp SIEM hơn.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html'],
      collector: 'source'
    })];
  }
  return [];
}

module.exports = {
  runPackageLockConsistency,
  runTyposquattingRisk,
  runCiCdSecurityGates,
  runSensitiveDataInLogs,
  runStructuredLogging
};

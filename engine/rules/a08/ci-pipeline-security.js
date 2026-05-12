const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện CI/CD Pipeline Security Issues
 * Tham chiếu: OWASP A08, WSTG-CONF, CWE-1357
 *
 * Nâng cấp so với runCiCdSecurityGates trong supply-chain-enhanced.js:
 *  1. Giữ: thiếu SAST và dependency check trong pipeline
 *  2. [NEW] GitHub Actions dùng unpinned action version (@main, @master, @latest)
 *  3. [NEW] Secrets hardcoded trong CI config (env: PASSWORD=xxx)
 *  4. [NEW] Docker base image không pinned (FROM ubuntu:latest)
 *  5. [NEW] Thiếu secret scanning trong pipeline
 *  6. [NEW] allow_failure: true trên security step (bypass security gate)
 *  7. [NEW] Pipeline chạy với quyền quá rộng (permissions: write-all)
 */

function runCiPipelineSecurity(context) {
  const findings = [];

  const allFiles = [
    ...(context.configFiles || []),
    ...(context.textFiles || []),
    ...(context.ciFiles || []),
  ];

  // Lọc CI/CD files
  const ciFiles = allFiles.filter(f =>
    /\.github[\\/]workflows[\\/].*\.ya?ml$|\.gitlab-ci\.ya?ml$|jenkinsfile$|\.circleci[\\/]config\.ya?ml$/i.test(f.path)
  );

  if (ciFiles.length === 0) return findings;

  // ── 1. Thiếu SAST ──────────────────────────────────────────────────────────
  const hasSast = ciFiles.some(f =>
    /sast|sonar|semgrep|eslint.*security|bandit|snyk|codeql|checkmarx|veracode/i.test(f.content)
  );
  if (!hasSast) {
    findings.push(normalizeFinding({
      ruleId: 'A08-CI-001',
      owaspCategory: 'A08',
      title: 'CI/CD pipeline không có bước SAST (Static Application Security Testing)',
      severity: 'medium',
      confidence: 'low',
      target: ciFiles[0].path,
      location: 'CI/CD pipeline config',
      evidence: ['Không phát hiện SAST tool (Semgrep, SonarQube, CodeQL, Bandit, ESLint-security) trong workflow.'],
      remediation:
        'Tích hợp SAST vào pipeline và block merge khi thất bại. ' +
        'Free options: GitHub CodeQL, Semgrep OSS, Bandit (Python).',
      references: [
        'https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/',
        'https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html',
      ],
      collector: 'source',
    }));
  }

  // ── 2. Thiếu dependency scanning ───────────────────────────────────────────
  const hasDepscan = ciFiles.some(f =>
    /npm audit|yarn audit|snyk|dependabot|dependency.?check|trivy|grype|osvscanner/i.test(f.content)
  );
  if (!hasDepscan) {
    findings.push(normalizeFinding({
      ruleId: 'A08-CI-002',
      owaspCategory: 'A08',
      title: 'CI/CD pipeline không có bước quét lỗ hổng dependency',
      severity: 'medium',
      confidence: 'low',
      target: ciFiles[0].path,
      location: 'CI/CD pipeline config',
      evidence: ['Không phát hiện npm audit, Snyk, Dependabot, Trivy hoặc tương đương trong workflow.'],
      remediation:
        'Thêm `npm audit --audit-level=high` hoặc Snyk vào CI. ' +
        'GitHub: bật Dependabot alerts + security updates.',
      references: ['https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/'],
      collector: 'source',
    }));
  }

  // ── 3. Thiếu secret scanning ───────────────────────────────────────────────
  const hasSecretScan = ciFiles.some(f =>
    /trufflehog|gitleaks|detect-secrets|secret.*scan|git-secrets|trivy.*secret/i.test(f.content)
  );
  if (!hasSecretScan) {
    findings.push(normalizeFinding({
      ruleId: 'A08-CI-003',
      owaspCategory: 'A08',
      title: 'CI/CD pipeline không có bước quét secret/credential bị commit nhầm',
      severity: 'medium',
      confidence: 'low',
      target: ciFiles[0].path,
      location: 'CI/CD pipeline config',
      evidence: ['Không phát hiện secret scanner (TruffleHog, Gitleaks, detect-secrets) trong workflow.'],
      remediation:
        'Thêm Gitleaks hoặc TruffleHog vào pipeline để phát hiện API key, password bị commit nhầm. ' +
        'GitHub Advanced Security đã tích hợp secret scanning.',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html',
        'https://github.com/gitleaks/gitleaks',
      ],
      collector: 'source',
    }));
  }

  // ── 4. GitHub Actions unpinned version (@main/@master/@latest) ─────────────
  for (const file of ciFiles) {
    if (!file.path.includes('.github')) continue;
    const unpinnedActions = [...file.content.matchAll(/uses:\s*([^\s@]+@(?:main|master|latest|HEAD))/g)];
    if (unpinnedActions.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A08-CI-004',
        owaspCategory: 'A08',
        title: 'GitHub Actions dùng unpinned action version (@main/@master/@latest)',
        severity: 'high',
        confidence: 'high',
        target: file.path,
        location: file.path,
        evidence: [
          ...unpinnedActions.slice(0, 3).map(m => `uses: ${m[1]}`),
          'Unpinned actions: nếu repo upstream bị compromise, action độc hại sẽ chạy trong pipeline.',
        ],
        remediation:
          'Pin actions theo commit SHA: `uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675` ' +
          'thay vì `uses: actions/checkout@v3`. Dùng Dependabot để tự động update SHA.',
        references: [
          'https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions',
          'https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html',
        ],
        collector: 'source',
      }));
      break;
    }
  }

  // ── 5. Hardcoded secret trong CI config ────────────────────────────────────
  for (const file of ciFiles) {
    const lines = file.content.split('\n');
    const secretLines = lines.filter(line => {
      // Dòng có pattern: KEY: value (không phải ${{ secrets.X }} hoặc $VAR)
      return /(?:password|passwd|secret|api_key|apikey|token|credential|private_key)\s*:\s*['"a-zA-Z0-9+/=_-]{8,}/i.test(line)
        && !/\$\{\{|\$[A-Z_]+\b|secrets\./i.test(line);
    });
    if (secretLines.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A08-CI-005',
        owaspCategory: 'A08',
        title: 'Có thể có hardcoded credential trong CI/CD config',
        severity: 'critical',
        confidence: 'medium',
        target: file.path,
        location: file.path,
        evidence: secretLines.slice(0, 2).map(l => l.trim().slice(0, 100)),
        remediation:
          'Không hardcode secret trong CI config. Dùng CI/CD secret store: ' +
          'GitHub Actions Secrets, GitLab CI Variables, AWS Secrets Manager, HashiCorp Vault.',
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html',
          'https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/',
        ],
        collector: 'source',
      }));
      break;
    }
  }

  // ── 6. Security step có allow_failure / continue-on-error ──────────────────
  for (const file of ciFiles) {
    const content = file.content;
    // Tìm block có security tool + allow_failure/continue-on-error gần nhau
    const securityWithFailure = /(?:sast|snyk|semgrep|bandit|npm audit)[^#\n]*\n(?:[^\n]*\n){0,5}[^\n]*(?:allow_failure:\s*true|continue-on-error:\s*true)/i.test(content)
      || /(?:allow_failure:\s*true|continue-on-error:\s*true)[^\n]*\n(?:[^\n]*\n){0,5}[^\n]*(?:sast|snyk|semgrep|bandit|npm audit)/i.test(content);

    if (securityWithFailure) {
      findings.push(normalizeFinding({
        ruleId: 'A08-CI-006',
        owaspCategory: 'A08',
        title: 'Security step trong CI có allow_failure=true — security gate bị bypass',
        severity: 'high',
        confidence: 'low',
        target: file.path,
        location: file.path,
        evidence: [
          'Security scan step có allow_failure: true hoặc continue-on-error: true.',
          'Pipeline sẽ deploy dù security scan thất bại — security gate vô hiệu hóa.',
        ],
        remediation:
          'Loại bỏ allow_failure/continue-on-error khỏi security steps. ' +
          'Nếu cần unblock build tạm thời: dùng audit-only mode nhưng set deadline bắt buộc fix.',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html'],
        collector: 'source',
      }));
      break;
    }
  }

  // ── 7. GitHub Actions permissions quá rộng ─────────────────────────────────
  for (const file of ciFiles) {
    if (!file.path.includes('.github')) continue;
    if (/permissions:\s*write-all|permissions:\s*\n\s+contents:\s*write.*\n\s+packages:\s*write/i.test(file.content)) {
      findings.push(normalizeFinding({
        ruleId: 'A08-CI-007',
        owaspCategory: 'A08',
        title: 'GitHub Actions workflow có permissions quá rộng (write-all)',
        severity: 'medium',
        confidence: 'high',
        target: file.path,
        location: file.path,
        evidence: [
          'permissions: write-all cấp quyền ghi trên toàn bộ scope.',
          'Nếu workflow bị inject (Script injection), attacker có thể push code, modify secrets, publish packages.',
        ],
        remediation:
          'Áp dụng least-privilege: chỉ khai báo permission cần thiết. ' +
          'Ví dụ: `permissions: contents: read` cho workflow chỉ cần đọc code.',
        references: [
          'https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token',
          'https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html',
        ],
        collector: 'source',
      }));
      break;
    }
  }

  // ── 8. Docker image unpinned trong CI ──────────────────────────────────────
  const dockerFiles = allFiles.filter(f => /dockerfile$/i.test(f.path));
  for (const file of dockerFiles) {
    const unpinnedFrom = [...file.content.matchAll(/^FROM\s+([^\s:@]+):latest\b/gim)];
    if (unpinnedFrom.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A08-CI-008',
        owaspCategory: 'A08',
        title: 'Dockerfile dùng :latest tag — image không được pin version cụ thể',
        severity: 'medium',
        confidence: 'high',
        target: file.path,
        location: file.path,
        evidence: unpinnedFrom.slice(0, 2).map(m => `FROM ${m[1]}:latest`),
        remediation:
          'Pin image bằng digest SHA256: `FROM node:20.11.0-alpine@sha256:abc123...` ' +
          'hoặc ít nhất là minor version: `FROM node:20.11.0-alpine`. ' +
          'Dùng Dependabot hoặc Renovate để tự động update.',
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html',
          'https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/',
        ],
        collector: 'source',
      }));
      break;
    }
  }

  return findings;
}

module.exports = { runCiPipelineSecurity };

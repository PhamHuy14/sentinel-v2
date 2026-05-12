const { normalizeFinding } = require('../../models/finding');
const path = require('path');

// ── OWASP OTG-CONFIG-003: File extensions nhạy cảm ──────────────────────────
// ── OWASP OTG-CONFIG-004: Backup / Unreferenced / Old files ─────────────────

/**
 * Pattern cho backup/temp files (OTG-CONFIG-004)
 * OWASP Testing Guide đề cập cụ thể: .bak, .old, .orig, ~ (Emacs backup)
 */
const BACKUP_FILE_PATTERNS = [
  { pattern: /\.(bak|old|orig|save|sav)$/i,    label: 'backup file extension' },
  { pattern: /\.swp$/i,                         label: 'vim swap file' },
  { pattern: /^~/,                              label: 'temporary backup file' },
  { pattern: /~$/,                              label: 'Emacs backup file' },
  { pattern: /\.tmp$/i,                         label: 'temporary file' },
  { pattern: /\.(1|2|3)$/,                     label: 'numeric backup copy' },
  { pattern: /copy\s+of\s+/i,                  label: 'copy of file' },
  { pattern: /\.(log)$/i,                       label: 'log file in source tree' },
];

/**
 * Pattern cho secrets / credentials files (OTG-CONFIG-003 + supply chain risk)
 */
const SECRETS_FILE_PATTERNS = [
  { pattern: /^\.env(\.|$)/i,                              label: '.env secrets file',          severity: 'high' },
  { pattern: /^\.env\.(local|prod|production|staging)$/i, label: 'environment-specific secrets', severity: 'high' },
  { pattern: /\.(pem|key|p12|pfx|jks|keystore)$/i,        label: 'private key or certificate',  severity: 'high' },
  { pattern: /^(id_rsa|id_ecdsa|id_ed25519)(\.pub)?$/i,   label: 'SSH key file',               severity: 'high' },
  { pattern: /secrets?\.(json|yaml|yml|toml)$/i,           label: 'secrets config file',        severity: 'high' },
  { pattern: /credentials?\.(json|yaml|yml)$/i,            label: 'credentials file',           severity: 'high' },
  { pattern: /serviceaccountkey\.json$/i,                  label: 'GCP service account key',    severity: 'high' },
  { pattern: /google.*credentials.*\.json$/i,              label: 'Google credentials file',    severity: 'high' },
  { pattern: /\.aws\/(credentials|config)$/i,              label: 'AWS credentials file',       severity: 'high' },
  { pattern: /terraform\.tfvars$/i,                        label: 'Terraform variables (may contain secrets)', severity: 'medium' },
  { pattern: /\.(htpasswd|htaccess)$/i,                    label: '.htpasswd / .htaccess file', severity: 'medium' },
];

/**
 * Required .gitignore patterns để cover sensitive files
 */
const REQUIRED_GITIGNORE_PATTERNS = [
  { pattern: /^\.env/m,               label: '.env* files' },
  { pattern: /\*\.pem/m,              label: '*.pem certificates' },
  { pattern: /\*\.key/m,              label: '*.key private keys' },
  { pattern: /\*\.p12|pfx/m,          label: '*.p12/*.pfx keystores' },
  { pattern: /id_rsa|id_ecdsa/m,      label: 'SSH private keys' },
];

function runSensitiveFileExposureRisk(context) {
  const findings = [];
  try {
    const sourceFiles = context.sourceFiles || [];
    if (!context.repoRoot && sourceFiles.length === 0) return findings;

    // ── A03-FILE-001: Backup / temp files trong source tree ─────────────────
    for (const filePath of sourceFiles) {
      const basename = path.basename(filePath);
      for (const { pattern, label } of BACKUP_FILE_PATTERNS) {
        if (pattern.test(basename)) {
          findings.push(normalizeFinding({
            ruleId: 'A03-FILE-001',
            owaspCategory: 'A03',
            title: `File backup/temp "${basename}" có trong source tree`,
            severity: 'medium',
            confidence: 'high',
            target: filePath,
            location: filePath,
            evidence: [`${label}: ${basename}`],
            remediation:
              'OWASP OTG-CONFIG-004 khuyến nghị review "old, backup and unreferenced files". ' +
              'File backup thường chứa source code cũ với vulnerability đã bị sửa trong bản mới, ' +
              'hoặc expose thông tin cấu trúc hệ thống. Xóa khỏi repository và thêm pattern vào .gitignore.',
            references: [
              'https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/',
              'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information'
            ],
            collector: 'source'
          }));
          break; // một finding per file
        }
      }
    }

    // ── A03-FILE-002: Secrets / credentials file bị commit ──────────────────
    for (const filePath of sourceFiles) {
      const basename = path.basename(filePath).toLowerCase();
      const normalizedPath = filePath.replace(/\\/g, '/').toLowerCase();

      for (const { pattern, label, severity } of SECRETS_FILE_PATTERNS) {
        if (pattern.test(basename) || pattern.test(normalizedPath)) {
          findings.push(normalizeFinding({
            ruleId: 'A03-FILE-002',
            owaspCategory: 'A03',
            title: `File nhạy cảm "${path.basename(filePath)}" có thể chứa secrets bị commit vào source`,
            severity,
            confidence: 'high',
            target: filePath,
            location: filePath,
            evidence: [`${label}: ${filePath}`],
            remediation:
              'Secrets trong source control là supply chain risk nghiêm trọng — bất kỳ ai có repo access đều đọc được. ' +
              'Xóa file khỏi git history (git filter-repo), rotate toàn bộ credentials bị lộ ngay lập tức, ' +
              'và dùng secret manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) hoặc biến môi trường CI.',
            references: [
              'https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/',
              'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information'
            ],
            collector: 'source'
          }));
          break;
        }
      }
    }

    // ── A03-FILE-003: .gitignore thiếu hoặc không cover sensitive patterns ───
    if (!context.gitignoreContent) {
      // Không có .gitignore
      findings.push(normalizeFinding({
        ruleId: 'A03-FILE-003',
        owaspCategory: 'A03',
        title: 'Không có .gitignore — sensitive files có thể bị commit vô tình',
        severity: 'medium',
        confidence: 'high',
        target: context.repoRoot || '.gitignore',
        location: '.gitignore',
        evidence: ['Không tìm thấy .gitignore tại root của repository'],
        remediation:
          'Tạo .gitignore với ít nhất các pattern: .env*, *.pem, *.key, *.p12, id_rsa, id_ecdsa, secrets.json. ' +
          'Dùng gitignore.io để generate template phù hợp với tech stack.',
        references: [
          'https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/',
          'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information'
        ],
        collector: 'source'
      }));
    } else {
      // Có .gitignore — kiểm tra từng required pattern
      const gitignore = context.gitignoreContent;
      const missingPatterns = REQUIRED_GITIGNORE_PATTERNS.filter(({ pattern }) => !pattern.test(gitignore));

      if (missingPatterns.length > 0) {
        findings.push(normalizeFinding({
          ruleId: 'A03-FILE-003',
          owaspCategory: 'A03',
          title: '.gitignore thiếu pattern bảo vệ cho sensitive files',
          severity: 'medium',
          confidence: 'medium',
          target: context.repoRoot ? `${context.repoRoot}/.gitignore` : '.gitignore',
          location: '.gitignore',
          evidence: missingPatterns.map(p => `Thiếu pattern cho: ${p.label}`),
          remediation:
            'Bổ sung các pattern sau vào .gitignore: ' +
            missingPatterns.map(p => p.label).join(', ') + '. ' +
            'Chạy "git rm --cached <file>" để untrack file đã lỡ commit trước đó.',
          references: [
            'https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/',
            'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information'
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

module.exports = { runSensitiveFileExposureRisk };

const { normalizeFinding } = require('../../models/finding');

const FILE_PATTERNS = [
  {
    ruleId: 'A02-FILE-002',
    titleFn: (url) => `.env file có thể truy cập công khai: ${url}`,
    severity: 'critical',
    pattern: /\.(env|env\.local|env\.production|env\.staging|env\.development)$/i,
    remediation:
      'Ngay lập tức xóa hoặc block quyền truy cập .env files từ web.\n' +
      'Thêm rule deny trong nginx/Apache:\n' +
      '  location ~ /\\.env { deny all; }\n' +
      'Kiểm tra git log để đảm bảo file chưa bị commit.',
    reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information',
  },
  {
    ruleId: 'A02-FILE-004',
    titleFn: (url) => `Version control metadata có thể truy cập: ${url}`,
    severity: 'high',
    pattern: /(\/.git\/HEAD|\/.git\/config|\/.svn\/entries|\/.hg\/|\/\.DS_Store)$/i,
    remediation:
      'Block quyền truy cập thư mục .git, .svn, .hg từ web server.\n' +
      'nginx: location ~ /\\.(git|svn|hg) { deny all; }\n' +
      'Apache: RedirectMatch 404 /\\.git',
    reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information',
  },
  {
    ruleId: 'A02-FILE-001',
    titleFn: (url) => `File backup/cũ có thể truy cập: ${url}`,
    severity: 'high',
    pattern: /\.(bak|old|orig|backup|copy|tmp|temp|save|~)$|\.(php|asp|jsp|html?|js|css)\.(bak|old|orig|backup|copy|tmp)$/i,
    remediation:
      'Xóa tất cả file backup khỏi webroot.\n' +
      'Cấu hình web server từ chối serve các extension này:\n' +
      '  location ~* \\.(bak|old|orig|backup|tmp)$ { return 404; }',
    reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information',
  },
  {
    ruleId: 'A02-FILE-003',
    titleFn: (url) => `Archive/compressed file có thể truy cập: ${url}`,
    severity: 'high',
    pattern: /\.(zip|tar\.gz|tgz|tar\.bz2|tar|rar|7z|gz)$/i,
    remediation:
      'Xóa archive files khỏi webroot. Nếu cần serve, dùng authenticated download.\n' +
      'Archive có thể chứa toàn bộ source code và configuration.',
    reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information',
  },
  {
    ruleId: 'A02-FILE-005',
    titleFn: (url) => `Debug/info page có thể truy cập: ${url}`,
    severity: 'high',
    pattern: /(phpinfo\.php|info\.php|test\.php|server-status|server-info|\.htaccess|web\.config|wp-config\.php\.bak)$/i,
    remediation:
      'Xóa hoặc block quyền truy cập các debug/config endpoint này.\n' +
      'phpinfo() không bao giờ nên public trên production.',
    reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration',
  },
];

function runSensitiveFileExposure(context) {
  const findings = [];
  const probeResults = context.probeResults || [];

  for (const probe of probeResults) {
    if (!probe || probe.status !== 200) continue;

    const contentType = String(probe.contentType || '').toLowerCase();
    const isTextContent =
      !contentType ||
      contentType.includes('text') ||
      contentType.includes('application/json') ||
      contentType.includes('application/xml') ||
      contentType.includes('application/zip') ||
      contentType.includes('octet-stream');

    if (!isTextContent) continue;

    for (const fp of FILE_PATTERNS) {
      if (fp.pattern.test(probe.url)) {
        findings.push(normalizeFinding({
          ruleId: fp.ruleId,
          owaspCategory: 'A02',
          title: fp.titleFn(probe.url),
          severity: fp.severity,
          confidence: 'high',
          target: context.finalUrl,
          location: probe.url,
          evidence: [
            `URL: ${probe.url}`,
            `HTTP Status: ${probe.status}`,
            `Content-Type: ${probe.contentType || 'unknown'}`,
            probe.bodySnippet ? `Body preview: ${String(probe.bodySnippet).slice(0, 100)}...` : '',
          ].filter(Boolean),
          remediation: fp.remediation,
          references: [fp.reference],
          collector: 'blackbox',
        }));
        break;
      }
    }
  }

  return findings;
}

module.exports = { runSensitiveFileExposure };

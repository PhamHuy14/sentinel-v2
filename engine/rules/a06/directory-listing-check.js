const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện Directory Listing (Open Directory Browsing)
 * Tham chiếu OWASP WSTG: WSTG-CONF-04 (Review Old Backup and Unreferenced Files)
 *
 * Directory listing bị kích hoạt cho phép attacker liệt kê toàn bộ
 * file/thư mục, phát hiện file nhạy cảm, backup, source code, config.
 */

// Pattern nhận diện directory listing page của các web server
const DIRECTORY_LISTING_PATTERNS = [
  // Apache
  {
    re: /<title>Index of \/|<h1>Index of \//i,
    server: 'Apache',
    evidence: 'Trang directory listing của Apache ("Index of /...")',
  },
  // Nginx
  {
    re: /<title>Index of \/.*<\/title>\s*<\/head>\s*<body.*><h1>Index of \//is,
    server: 'Nginx',
    evidence: 'Trang directory listing của Nginx',
  },
  // Generic (nhiều server dùng mẫu này)
  {
    re: /<pre><img[^>]+> <a href="\?C=\w&amp;O=\w">/i,
    server: 'Apache (sort links)',
    evidence: 'Trang directory listing của Apache có kèm sort links',
  },
  // IIS Directory Browsing
  {
    re: /\[To Parent Directory\]|<br>.*\d+\s+(AM|PM).*\s+\d+\s+<a\s+href=/i,
    server: 'IIS',
    evidence: 'Trang Directory Browsing của IIS ([To Parent Directory])',
  },
  // Python SimpleHTTPServer / http.server
  {
    re: /Directory listing for \/|<title>Directory listing for/i,
    server: 'Python SimpleHTTPServer',
    evidence: 'Trang directory listing của Python http.server',
  },
  // Node.js serve / file server
  {
    re: /<title>listing directory \/|<h1>Index<\/h1>.*<table>.*<tr><th/is,
    server: 'Node.js static file server',
    evidence: 'Trang directory listing của Node.js static file server',
  },
];

// Pattern nhận diện file nhạy cảm thường lộ trong directory listing
const SENSITIVE_FILE_IN_LISTING = [
  { re: /\.env["'\s]|\.env\b/,    label: 'File .env bị lộ trong danh sách thư mục' },
  { re: /\.sql["'\s]|dump\.sql/i, label: 'File SQL dump bị lộ trong danh sách thư mục' },
  { re: /\.bak["'\s]|\.backup\b/i, label: 'File backup bị lộ trong danh sách thư mục' },
  { re: /id_rsa|id_dsa|\.pem["'\s]/i, label: 'File private key bị lộ trong danh sách thư mục' },
  { re: /wp-config\.php|config\.php|database\.php/i, label: 'File cấu hình PHP bị lộ trong danh sách thư mục' },
  { re: /\.git\/|\.svn\//,         label: 'Thư mục mã nguồn (VCS) bị lộ trong danh sách thư mục' },
];

function runDirectoryListingCheck(context) {
  const text = context.text || '';
  const status = context.status || 0;
  const findings = [];

  // Chỉ phân tích response 200
  if (status !== 200) return findings;

  // Phát hiện directory listing
  const listingMatch = DIRECTORY_LISTING_PATTERNS.find(({ re }) => re.test(text));
  if (!listingMatch) return findings;

  // Kiểm tra thêm file nhạy cảm trong listing
  const sensitiveFiles = SENSITIVE_FILE_IN_LISTING.filter(({ re }) => re.test(text));
  const evidence = [listingMatch.evidence];
  let severity = 'medium';

  if (sensitiveFiles.length > 0) {
    severity = 'critical';
    evidence.push(...sensitiveFiles.map(f => f.label));
  }

  findings.push(normalizeFinding({
    ruleId: 'A06-DIRLIST-001',
    owaspCategory: 'A06',
    title: `Directory listing bị bật — lộ danh sách file/thư mục`,
    severity,
    confidence: 'high',
    target: context.finalUrl,
    location: 'response body',
    evidence,
    remediation:
      'Tắt directory listing trong web server config: ' +
      'Apache: `Options -Indexes` trong .htaccess hoặc VirtualHost. ' +
      'Nginx: loại bỏ `autoindex on;`. ' +
      'IIS: tắt Directory Browsing trong IIS Manager. ' +
      'Đảm bảo mỗi thư mục có index file.',
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information',
    ],
    collector: 'blackbox',
  }));

  return findings;
}

module.exports = { runDirectoryListingCheck };

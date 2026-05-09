const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện Framework/Technology Version Disclosure trong response body
 * Tham chiếu OWASP WSTG: WSTG-CONF-02
 *
 * Phân biệt với A02's server-header-exposure.js (kiểm tra headers):
 * Rule này kiểm tra version leak trong *nội dung HTML* — meta tags,
 * HTML comments, generator tags, footer text.
 */

const VERSION_PATTERNS = [
  // WordPress version trong meta generator
  { re: /<meta\s+name=["']generator["']\s+content=["']WordPress\s+([\d.]+)["']/i,
    tech: 'WordPress', groupIdx: 1, severity: 'medium' },

  // Joomla version
  { re: /<meta\s+name=["']generator["']\s+content=["']Joomla!\s+([\d.]+)/i,
    tech: 'Joomla!', groupIdx: 1, severity: 'medium' },

  // Drupal version
  { re: /Drupal\s+([\d.]+)\s+\(https?:\/\/www\.drupal\.org\)/i,
    tech: 'Drupal', groupIdx: 1, severity: 'medium' },

  // Laravel mix version hint
  { re: /laravel-mix\/([\d.]+)/i,
    tech: 'Laravel Mix', groupIdx: 1, severity: 'low' },

  // PHP version in X-Powered-By (body reflection)
  { re: /PHP\/([\d.]+(?:\.\d+)?)/i,
    tech: 'PHP', groupIdx: 1, severity: 'high' },

  // ASP.NET version
  { re: /ASP\.NET\s+Version:([\d.]+)/i,
    tech: 'ASP.NET', groupIdx: 1, severity: 'high' },

  // Apache version in error pages
  { re: /Apache\/([\d.]+(?:\.\d+)?) \(/i,
    tech: 'Apache', groupIdx: 1, severity: 'high' },

  // Nginx version in error pages
  { re: /nginx\/([\d.]+)/i,
    tech: 'Nginx', groupIdx: 1, severity: 'high' },

  // Spring Boot version
  { re: /Spring(?:Boot)?\s+v?([\d.]+\.\w+)/i,
    tech: 'Spring Boot', groupIdx: 1, severity: 'medium' },

  // Django version
  { re: /Django\s+v?([\d.]+)/i,
    tech: 'Django', groupIdx: 1, severity: 'medium' },

  // Bootstrap version (thông tin ít nhạy hơn)
  { re: /Bootstrap\s+v([\d.]+)/i,
    tech: 'Bootstrap', groupIdx: 1, severity: 'info' },

  // jQuery version
  { re: /jquery(?:\.min)?\.js\?ver=([\d.]+)|jquery-([\d.]+)(?:\.min)?\.js/i,
    tech: 'jQuery', groupIdx: 1, severity: 'info' },

  // Powered-by text in HTML footer
  { re: /Powered by\s+([A-Za-z0-9 ]+)\s+v?([\d.]+)/i,
    tech: 'Generic (Powered by)', groupIdx: 2, severity: 'low' },

  // HTML comment version leaks
  { re: /<!--.*version\s*[=:]\s*([\d.]+).*-->/i,
    tech: 'Version in HTML comment', groupIdx: 1, severity: 'low' },
];

function runFrameworkDisclosureCheck(context) {
  const text = context.text || '';
  const contentType = (context.contentType || '').toLowerCase();
  const findings = [];

  // Chỉ check HTML response
  if (!contentType.includes('html') && !contentType.includes('text')) {
    if (!text.trimStart().startsWith('<!') && !text.includes('<html')) return findings;
  }

  const detected = [];
  for (const { re, tech, groupIdx, severity } of VERSION_PATTERNS) {
    const match = text.match(re);
    if (match) {
      const version = match[groupIdx] || match[1] || 'unknown';
      // Bỏ qua info-level nếu không có version cụ thể
      if (severity === 'info' && version === 'unknown') continue;
      detected.push({ tech, version, severity });
    }
  }

  if (detected.length === 0) return findings;

  // Nhóm theo severity cao nhất
  const maxSev = ['critical', 'high', 'medium', 'low', 'info']
    .find(s => detected.some(d => d.severity === s)) || 'info';

  // Lọc chỉ lấy high/medium/critical để báo cáo (info quá nhiều sẽ noise)
  const significant = detected.filter(d =>
    ['critical', 'high', 'medium'].includes(d.severity)
  );

  if (significant.length === 0 && maxSev !== 'high') return findings;

  const reportList = significant.length > 0 ? significant : detected;

  findings.push(normalizeFinding({
    ruleId: 'A06-VERSION-001',
    owaspCategory: 'A06',
    title: 'Version thông tin framework/technology bị lộ trong HTML response',
    severity: maxSev,
    confidence: 'high',
    target: context.finalUrl,
    location: 'response body (HTML content)',
    evidence: reportList.map(d => `Phát hiện ${d.tech} phiên bản ${d.version} trong response`),
    remediation:
      'Ẩn version thông tin khỏi response: ' +
      'Xóa generator meta tag. Dùng versioning-less CDN URL. ' +
      'Cấu hình web server không include version trong error page. ' +
      'Strip X-Powered-By, Server headers với version.',
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration',
    ],
    collector: 'blackbox',
  }));

  return findings;
}

module.exports = { runFrameworkDisclosureCheck };

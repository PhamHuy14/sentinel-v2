const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện Default Page / Default Content
 * Tham chiếu OWASP WSTG: WSTG-CONF-02 (Test Application Platform Configuration)
 *
 * Phát hiện trang mặc định của web server / framework / CMS còn tồn tại trong production.
 * Những trang này tiết lộ thông tin về công nghệ sử dụng và thể hiện misconfiguration.
 *
 * Lưu ý: Khác với A01's runSensitiveEndpointExposure (kiểm tra access control),
 * rule này phân tích *nội dung response* để xác nhận đây là default content.
 */

// Mẫu nhận diện trang mặc định của web server
const SERVER_DEFAULT_PATTERNS = [
  // Apache httpd
  {
    re: /It works!.*Apache|<title>Apache2? (?:Ubuntu|Debian|CentOS|Test) Default Page/is,
    server: 'Apache HTTP Server',
    severity: 'medium',
  },
  {
    re: /This is the default welcome page used to test the correct operation.*Apache/is,
    server: 'Apache HTTP Server (welcome page)',
    severity: 'medium',
  },

  // Nginx
  {
    re: /<title>Welcome to nginx!<\/title>|<h1>Welcome to nginx!<\/h1>/i,
    server: 'Nginx',
    severity: 'medium',
  },

  // IIS
  {
    re: /IIS Windows Server|<title>IIS Windows Server<\/title>|Internet Information Services/i,
    server: 'Microsoft IIS',
    severity: 'medium',
  },

  // Tomcat
  {
    re: /<title>Apache Tomcat.*<\/title>.*Apache Software Foundation/is,
    server: 'Apache Tomcat',
    severity: 'medium',
  },
  {
    re: /Apache Tomcat.*<small>Version \d+\.\d+\.\d+<\/small>/i,
    server: 'Apache Tomcat (version exposed)',
    severity: 'high',
  },

  // Lighttpd
  {
    re: /lighttpd.*placeholder.*page|<title>lighttpd.*<\/title>/i,
    server: 'Lighttpd',
    severity: 'medium',
  },

  // Caddy
  {
    re: /Caddy.*web server|This site is powered by Caddy/i,
    server: 'Caddy Web Server',
    severity: 'low',
  },
];

// Mẫu nhận diện trang mặc định PHP / language runtime
const PHP_DEFAULT_PATTERNS = [
  // phpinfo()
  {
    re: /<title>phpinfo\(\)<\/title>|PHP Version \d+\.\d+\.\d+.*(?:Build Date|Configure Command)/is,
    label: 'phpinfo() page — lộ cấu hình PHP chi tiết',
    severity: 'critical',
  },
  {
    re: /Zend Engine v\d+\.\d+\.\d+.*with Zend OPcache/is,
    label: 'phpinfo() — Zend Engine info',
    severity: 'critical',
  },
];

// Mẫu nhận diện CMS default
const CMS_DEFAULT_PATTERNS = [
  {
    re: /Just another WordPress site|<meta name="generator" content="WordPress \d/i,
    cms: 'WordPress',
    severity: 'low',
  },
  {
    re: /Joomla! - the dynamic portal engine and content management system/i,
    cms: 'Joomla!',
    severity: 'low',
  },
  {
    re: /Drupal \d+ \(https?:\/\/www\.drupal\.org\)|X-Generator.*Drupal/i,
    cms: 'Drupal',
    severity: 'low',
  },
  {
    re: /Powered by MediaWiki|<meta name="generator" content="MediaWiki/i,
    cms: 'MediaWiki',
    severity: 'info',
  },
];

// Mẫu nhận diện framework/development server
const FRAMEWORK_DEFAULT_PATTERNS = [
  {
    re: /Django.*The install worked successfully|<h1>It worked!<\/h1>.*Django/is,
    framework: 'Django',
    severity: 'medium',
  },
  {
    re: /Laravel.*application is ready!|<title>Laravel<\/title>.*<!DOCTYPE html>/is,
    framework: 'Laravel',
    severity: 'medium',
  },
  {
    re: /Ruby on Rails default.*congratulations|<h1>Welcome aboard<\/h1>/i,
    framework: 'Ruby on Rails',
    severity: 'medium',
  },
  {
    re: /Express \/\s*<br>.*Cannot GET|<pre>Cannot (GET|POST) \//i,
    framework: 'Express.js (default error page)',
    severity: 'low',
  },
  {
    re: /Whitelabel Error Page.*This application has no explicit mapping/i,
    framework: 'Spring Boot (Whitelabel error page)',
    severity: 'medium',
  },
  {
    re: /Flask.*Werkzeug.*Debugger|Werkzeug Interactive Debugger/i,
    framework: 'Flask Werkzeug Debugger — CRITICAL: cho phép code execution',
    severity: 'critical',
  },
];

function runDefaultPageCheck(context) {
  const text = context.text || '';
  const findings = [];

  // Kiểm tra web server default pages
  for (const { re, server, severity } of SERVER_DEFAULT_PATTERNS) {
    if (re.test(text)) {
      findings.push(normalizeFinding({
        ruleId: 'A06-DEFAULT-001',
        owaspCategory: 'A06',
        title: `Trang mặc định của ${server} còn tồn tại — Security Misconfiguration`,
        severity,
        confidence: 'high',
        target: context.finalUrl,
        location: 'response body',
        evidence: [
          `Phát hiện nội dung đặc trưng của trang mặc định ${server}.`,
          'Trang mặc định tiết lộ thông tin về web server và thể hiện cấu hình chưa đúng.',
        ],
        remediation:
          `Xóa hoặc thay thế trang mặc định của ${server} bằng nội dung ứng dụng thực tế. ` +
          'Xóa sample content, test page. Cấu hình VirtualHost/Server Block phù hợp.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration',
        ],
        collector: 'blackbox',
      }));
      break;
    }
  }

  // Kiểm tra phpinfo()
  for (const { re, label, severity } of PHP_DEFAULT_PATTERNS) {
    if (re.test(text)) {
      findings.push(normalizeFinding({
        ruleId: 'A06-DEFAULT-002',
        owaspCategory: 'A06',
        title: 'phpinfo() page bị lộ — tiết lộ toàn bộ cấu hình PHP',
        severity,
        confidence: 'high',
        target: context.finalUrl,
        location: 'response body',
        evidence: [
          label,
          'phpinfo() tiết lộ: phiên bản PHP, cấu hình, extension, path, environment variables.',
          'Attacker có thể dùng thông tin này để xây dựng exploit phù hợp.',
        ],
        remediation:
          'Xóa ngay phpinfo() khỏi production. ' +
          'Không bao giờ deploy code debug lên production environment.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration',
        ],
        collector: 'blackbox',
      }));
      break;
    }
  }

  // Kiểm tra CMS default content
  for (const { re, cms, severity } of CMS_DEFAULT_PATTERNS) {
    if (re.test(text)) {
      findings.push(normalizeFinding({
        ruleId: 'A06-DEFAULT-003',
        owaspCategory: 'A06',
        title: `CMS ${cms} phiên bản bị tiết lộ qua nội dung trang`,
        severity,
        confidence: 'high',
        target: context.finalUrl,
        location: 'response body / meta tags',
        evidence: [
          `Phát hiện nội dung/metadata đặc trưng của ${cms} trong response.`,
          'Biết CMS và phiên bản giúp attacker tìm CVE phù hợp.',
        ],
        remediation:
          `Ẩn version thông tin của ${cms}. Xóa generator meta tag. ` +
          'Luôn cập nhật CMS và plugin lên phiên bản mới nhất.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration',
        ],
        collector: 'blackbox',
      }));
      break;
    }
  }

  // Kiểm tra framework default pages
  for (const { re, framework, severity } of FRAMEWORK_DEFAULT_PATTERNS) {
    if (re.test(text)) {
      findings.push(normalizeFinding({
        ruleId: 'A06-DEFAULT-004',
        owaspCategory: 'A06',
        title: `Trang mặc định / debug của ${framework} bị lộ`,
        severity,
        confidence: 'high',
        target: context.finalUrl,
        location: 'response body',
        evidence: [
          `Phát hiện nội dung đặc trưng của ${framework} default/error page.`,
          severity === 'critical' ? '⚠️  DEBUG MODE CÓ THỂ CHO PHÉP ARBITRARY CODE EXECUTION!' :
            'Framework default page tiết lộ thông tin cấu trúc ứng dụng.',
        ],
        remediation:
          severity === 'critical'
            ? `Tắt ngay Werkzeug debugger trong production! Set DEBUG=False. KHÔNG BAO GIỜ deploy debug mode.`
            : `Cấu hình ứng dụng ${framework} đúng cách cho production. Disable development defaults.`,
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration',
        ],
        collector: 'blackbox',
      }));
      break;
    }
  }

  return findings;
}

module.exports = { runDefaultPageCheck };

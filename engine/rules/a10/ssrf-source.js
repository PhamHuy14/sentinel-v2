const { normalizeFinding } = require('../../models/finding');
const {
  buildSourceRemediationPlan,
  evidenceWithLocation,
  locatePattern,
} = require('../../utils/source-locator');

const USER_CONTROLLED_FETCH = [
  {
    re: /(?:fetch|axios\.get|axios\.post|axios\s*\(|https?\.get|https?\.request|got\s*\(|needle\.get|superagent\.get)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|user\.|config\.url)/i,
    label: 'fetch/axios với URL từ req.query/req.body - SSRF direct',
    lang: 'JavaScript',
    severity: 'critical',
  },
  {
    re: /const\s+url\s*=\s*(?:req\.|request\.)(?:query|params|body)\.\w+[;\n][\s\S]{0,200}(?:fetch|axios|https?\.get)\s*\(\s*url/i,
    label: 'URL từ request được dùng trực tiếp trong HTTP request',
    lang: 'JavaScript',
    severity: 'critical',
  },
  {
    re: /(?:requests\.get|requests\.post|urllib\.request\.urlopen|httpx\.get|aiohttp\.ClientSession.*get)\s*\(\s*(?:request\.|req\.|flask\.request\.|params\.|data\.)/i,
    label: 'Python requests/urllib với URL từ request data',
    lang: 'Python',
    severity: 'critical',
  },
  {
    re: /new\s+URL\s*\(\s*(?:request\.getParameter|request\.getAttribute|param\.|req\.)\s*/i,
    label: 'Java new URL() với request parameter - SSRF',
    lang: 'Java',
    severity: 'critical',
  },
  {
    re: /RestTemplate|WebClient|HttpClient.*(?:getParameter|getAttribute|getQueryString)/i,
    label: 'Java RestTemplate/WebClient với user-controlled URL',
    lang: 'Java',
    severity: 'high',
  },
  {
    re: /curl_setopt\s*\(\s*\$\w+\s*,\s*CURLOPT_URL\s*,\s*\$_(?:GET|POST|REQUEST)/i,
    label: 'PHP curl_setopt CURLOPT_URL với $_GET/$_POST - SSRF',
    lang: 'PHP',
    severity: 'critical',
  },
  {
    re: /file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)/i,
    label: 'PHP file_get_contents với user input - SSRF + LFI',
    lang: 'PHP',
    severity: 'critical',
  },
];

const URL_VALIDATION_ANTIPATTERNS = [
  {
    re: /(?:url|href|target|src)\s*\.startsWith\s*\(\s*['"]https?:\/\//i,
    label: 'Validate URL chỉ bằng startsWith("http") có thể bypass bằng http://169.254.169.254',
    severity: 'medium',
  },
  {
    re: /(?:allowedDomains|whitelist|allowList).*includes\s*\(\s*new\s+URL\s*\(|url.*includes\s*\(\s*allowedDomain/i,
    label: 'Domain allowlist check có thể bị bypass bằng URL như http://evil.com?trusted.domain.com',
    severity: 'medium',
  },
];

const DANGEROUS_SCHEMES = [
  {
    re: /(?:file|gopher|dict|sftp|ldap|ftp):\/\//i,
    inContext: /(?:fetch|axios|curl|request|urlopen|file_get_contents|url=)/i,
    label: 'URL scheme nguy hiểm (file://, gopher://, dict://) được dùng trong HTTP request',
    severity: 'high',
  },
];

const UNVALIDATED_REDIRECT_SOURCE = [
  {
    re: /res\.redirect\s*\(\s*(?:req\.|request\.)(?:query|params|body)\.\w+\s*\)/i,
    label: 'Express res.redirect với req.query - open redirect + SSRF via redirect',
    lang: 'Node.js',
    severity: 'high',
  },
  {
    re: /header\s*\(\s*["']Location:\s*["']\s*\.\s*\$_(?:GET|POST|REQUEST)/i,
    label: 'PHP header(Location:) với $_GET - open redirect',
    lang: 'PHP',
    severity: 'high',
  },
  {
    re: /HttpServletResponse.*sendRedirect\s*\(\s*request\.getParameter/i,
    label: 'Java sendRedirect với request.getParameter - open redirect',
    lang: 'Java',
    severity: 'high',
  },
];

const SSRF_REFS = [
  'https://owasp.org/Top10/2025/A10_2025-Server_Side_Request_Forgery/',
  'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
];

function sourceFinding({ path, locator, evidence, remediation, suggestedTo, ...partial }) {
  return normalizeFinding({
    ...partial,
    target: path,
    location: locator ? `${path}:${locator.lineStart}` : path,
    evidence: evidenceWithLocation(evidence, locator),
    remediation,
    remediationPlan: buildSourceRemediationPlan({
      filePath: path,
      locator,
      summary: remediation,
      suggestedTo,
    }),
    collector: 'source',
  });
}

function runSsrfSource(context) {
  const findings = [];
  const codeFiles = context.codeFiles || [];

  for (const file of codeFiles) {
    const content = file?.content || '';
    const path = file?.path || '';
    if (!content.trim()) continue;

    for (const { re, label, lang, severity } of USER_CONTROLLED_FETCH) {
      const locator = locatePattern(content, {
        re,
        focusPatterns: [
          /(?:fetch|axios|https?\.get|https?\.request|got|needle|superagent|requests\.|urlopen|RestTemplate|WebClient|curl_setopt|file_get_contents)/i,
          /(?:req\.|request\.|params\.|query\.|body\.|\$_(?:GET|POST|REQUEST))/i,
        ],
      });
      if (locator) {
        const remediation =
          'Implement URL allowlist nghiêm ngặt: parse URL, resolve DNS, chặn IP private/loopback/metadata, so sánh hostname với allowlist và chỉ cho phép scheme http/https.';
        findings.push(sourceFinding({
          ruleId: 'A10-SSRF-SRC-001',
          owaspCategory: 'A10',
          title: 'SSRF risk: HTTP request với URL từ user input',
          severity,
          confidence: 'medium',
          path,
          locator,
          evidence: [
            `[${lang}] ${label}`,
            'Server thực hiện HTTP request đến URL do người dùng cung cấp; SSRF có thể xảy ra.',
          ],
          remediation,
          suggestedTo:
            'Validate URL bằng allowlist tập trung trước khi gọi fetch/axios/request; reject hostname/IP nội bộ và metadata service.',
          references: [
            ...SSRF_REFS,
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery',
          ],
        }));
        break;
      }
    }

    for (const { re, label, severity } of URL_VALIDATION_ANTIPATTERNS) {
      const locator = locatePattern(content, {
        re,
        focusPatterns: [/startsWith|includes|allowList|whitelist|allowedDomains/i],
      });
      if (locator) {
        const remediation =
          'URL allowlist cần check sau DNS resolution: parse URL, resolve hostname, verify IP, rồi so sánh chính xác với allowlist.';
        findings.push(sourceFinding({
          ruleId: 'A10-SSRF-SRC-002',
          owaspCategory: 'A10',
          title: 'URL validation yếu có thể bị bypass dẫn đến SSRF',
          severity,
          confidence: 'low',
          path,
          locator,
          evidence: [label],
          remediation,
          suggestedTo:
            'Không dùng includes/startsWith để tin URL; chuyển sang parser URL, hostname allowlist chính xác và IP range denylist.',
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html#application-layer-defense',
          ],
        }));
        break;
      }
    }

    for (const { re, inContext, label, severity } of DANGEROUS_SCHEMES) {
      const locator = locatePattern(content, {
        re,
        focusPatterns: [/file:\/\/|gopher:\/\/|dict:\/\/|sftp:\/\/|ldap:\/\/|ftp:\/\//i],
      });
      if (locator && inContext.test(content)) {
        const remediation =
          'Chỉ cho phép scheme https:// hoặc http:// khi thật sự cần; reject file, gopher, dict, sftp, ldap, ftp và data.';
        findings.push(sourceFinding({
          ruleId: 'A10-SSRF-SRC-003',
          owaspCategory: 'A10',
          title: 'URL scheme nguy hiểm được chấp nhận trong HTTP request',
          severity,
          confidence: 'medium',
          path,
          locator,
          evidence: [
            label,
            'file:// cho phép đọc file hệ thống. gopher:// cho phép tương tác với internal TCP services.',
          ],
          remediation,
          suggestedTo: 'Thêm scheme allowlist ở hàm validate URL trước khi thực hiện request server-side.',
          references: SSRF_REFS,
        }));
        break;
      }
    }

    for (const { re, label, lang, severity } of UNVALIDATED_REDIRECT_SOURCE) {
      const locator = locatePattern(content, {
        re,
        focusPatterns: [/redirect|Location:|sendRedirect/i, /(?:req\.|request\.|\$_(?:GET|POST|REQUEST))/i],
      });
      if (locator) {
        const remediation =
          'Validate redirect destination: chỉ cho phép relative path hoặc domain được whitelist; không redirect URL tuyệt đối từ user input nếu chưa kiểm tra.';
        findings.push(sourceFinding({
          ruleId: 'A10-SSRF-SRC-004',
          owaspCategory: 'A10',
          title: 'Open redirect với user-controlled URL có thể kết hợp SSRF',
          severity,
          confidence: 'medium',
          path,
          locator,
          evidence: [
            `[${lang}] ${label}`,
            'Open redirect có thể bypass SSRF protection nếu server follow redirect.',
          ],
          remediation,
          suggestedTo: 'Chỉ redirect relative path hoặc URL đã parse và khớp allowlist chính xác.',
          references: [
            ...SSRF_REFS,
            'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html',
          ],
        }));
        break;
      }
    }
  }

  return findings;
}

module.exports = { runSsrfSource };

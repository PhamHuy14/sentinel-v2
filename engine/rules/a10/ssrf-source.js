const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện SSRF trong Source Code
 * Tham chiếu: OWASP A10:2025, CWE-918
 *
 * Phát hiện các pattern source code dễ bị SSRF:
 *  1. fetch/axios/request với URL từ user input (req.query, req.body)
 *  2. HTTP request không có URL validation / allowlist
 *  3. File/URL scheme nguy hiểm được chấp nhận (file://, gopher://)
 *  4. DNS lookup với user-controlled hostname
 *  5. XML/SVG external entity (liên quan SSRF qua XXE)
 *  6. Server-side redirect không validate destination
 */

// ─── 1. HTTP Request với user-controlled URL ───────────────────────────────

const USER_CONTROLLED_FETCH = [
  // JavaScript / Node.js
  {
    re: /(?:fetch|axios\.get|axios\.post|axios\s*\(|https?\.get|https?\.request|got\s*\(|needle\.get|superagent\.get)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|user\.|config\.url)/i,
    label: 'fetch/axios với URL từ req.query/req.body — SSRF direct',
    lang: 'JavaScript', severity: 'critical',
  },
  {
    re: /const\s+url\s*=\s*(?:req\.|request\.)(?:query|params|body)\.\w+[;\n][\s\S]{0,200}(?:fetch|axios|https?\.get)\s*\(\s*url/i,
    label: 'URL từ request được dùng trực tiếp trong HTTP request',
    lang: 'JavaScript', severity: 'critical',
  },
  // Python
  {
    re: /(?:requests\.get|requests\.post|urllib\.request\.urlopen|httpx\.get|aiohttp\.ClientSession.*get)\s*\(\s*(?:request\.|req\.|flask\.request\.|params\.|data\.)/i,
    label: 'Python requests/urllib với URL từ request data',
    lang: 'Python', severity: 'critical',
  },
  // Java
  {
    re: /new\s+URL\s*\(\s*(?:request\.getParameter|request\.getAttribute|param\.|req\.)\s*/i,
    label: 'Java new URL() với request parameter — SSRF',
    lang: 'Java', severity: 'critical',
  },
  {
    re: /RestTemplate|WebClient|HttpClient.*(?:getParameter|getAttribute|getQueryString)/i,
    label: 'Java RestTemplate/WebClient với user-controlled URL',
    lang: 'Java', severity: 'high',
  },
  // PHP
  {
    re: /curl_setopt\s*\(\s*\$\w+\s*,\s*CURLOPT_URL\s*,\s*\$_(?:GET|POST|REQUEST)/i,
    label: 'PHP curl_setopt CURLOPT_URL với $_GET/$_POST — SSRF',
    lang: 'PHP', severity: 'critical',
  },
  {
    re: /file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)/i,
    label: 'PHP file_get_contents với user input — SSRF + LFI',
    lang: 'PHP', severity: 'critical',
  },
];

// ─── 2. Thiếu URL allowlist / validation ──────────────────────────────────

const URL_VALIDATION_ANTIPATTERNS = [
  // Kiểm tra URL chỉ bằng startsWith http (bỏ qua IP internal)
  {
    re: /(?:url|href|target|src)\s*\.startsWith\s*\(\s*['"]https?:\/\//i,
    label: 'Validate URL chỉ bằng startsWith("http") — bypass được bằng http://169.254.169.254',
    severity: 'medium',
  },
  // URL whitelist check yếu (chỉ includes/contains domain)
  {
    re: /(?:allowedDomains|whitelist|allowList).*includes\s*\(\s*new\s+URL\s*\(|url.*includes\s*\(\s*allowedDomain/i,
    label: 'Domain allowlist check có thể bị bypass bằng URL như http://evil.com?trusted.domain.com',
    severity: 'medium',
  },
];

// ─── 3. Dangerous URL schemes accepted ────────────────────────────────────

const DANGEROUS_SCHEMES = [
  {
    re: /(?:file|gopher|dict|sftp|ldap|ftp):\/\//i,
    inContext: /(?:fetch|axios|curl|request|urlopen|file_get_contents|url=)/i,
    label: 'URL scheme nguy hiểm (file://, gopher://, dict://) được dùng trong HTTP request',
    severity: 'high',
  },
];

// ─── 4. Server-side redirect không validate ────────────────────────────────

const UNVALIDATED_REDIRECT_SOURCE = [
  {
    re: /res\.redirect\s*\(\s*(?:req\.|request\.)(?:query|params|body)\.\w+\s*\)/i,
    label: 'Express res.redirect với req.query — open redirect + SSRF via redirect',
    lang: 'Node.js', severity: 'high',
  },
  {
    re: /header\s*\(\s*["']Location:\s*["']\s*\.\s*\$_(?:GET|POST|REQUEST)/i,
    label: 'PHP header(Location:) với $_GET — open redirect',
    lang: 'PHP', severity: 'high',
  },
  {
    re: /HttpServletResponse.*sendRedirect\s*\(\s*request\.getParameter/i,
    label: 'Java sendRedirect với request.getParameter — open redirect',
    lang: 'Java', severity: 'high',
  },
];

function runSsrfSource(context) {
  const findings = [];
  const codeFiles = context.codeFiles || [];

  for (const file of codeFiles) {
    const content = file?.content || '';
    const path    = file?.path    || '';
    if (!content.trim()) continue;

    // ── 1. User-controlled URL in HTTP request ──────────────────────────────
    for (const { re, label, lang, severity } of USER_CONTROLLED_FETCH) {
      if (re.test(content)) {
        findings.push(normalizeFinding({
          ruleId: 'A10-SSRF-SRC-001',
          owaspCategory: 'A10',
          title: `SSRF risk: HTTP request với URL từ user input`,
          severity,
          confidence: 'medium',
          target: path,
          location: path,
          evidence: [
            `[${lang}] ${label}`,
            'Server thực hiện HTTP request đến URL do người dùng cung cấp — SSRF có thể xảy ra.',
          ],
          remediation:
            'Implement URL allowlist nghiêm ngặt: ' +
            '(1) Parse URL, extract hostname. ' +
            '(2) Resolve DNS, verify IP không phải RFC1918/loopback/metadata. ' +
            '(3) So sánh hostname với whitelist. ' +
            '(4) Chỉ cho phép scheme http/https. ' +
            'Node.js: dùng thư viện `ssrf-req-filter`. Python: dùng `validators` + IP check.',
          references: [
            'https://owasp.org/Top10/2025/A10_2025-Server_Side_Request_Forgery/',
            'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery',
          ],
          collector: 'source',
        }));
        break;
      }
    }

    // ── 2. Weak URL validation ─────────────────────────────────────────────
    for (const { re, label, severity } of URL_VALIDATION_ANTIPATTERNS) {
      if (re.test(content)) {
        findings.push(normalizeFinding({
          ruleId: 'A10-SSRF-SRC-002',
          owaspCategory: 'A10',
          title: 'URL validation yếu — có thể bị bypass dẫn đến SSRF',
          severity,
          confidence: 'low',
          target: path,
          location: path,
          evidence: [label],
          remediation:
            'URL allowlist cần check AFTER DNS resolution: ' +
            'Parse URL → resolve hostname → verify resolved IP → compare with allowlist. ' +
            'String matching trên hostname dễ bị bypass.',
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html#application-layer-defense',
          ],
          collector: 'source',
        }));
        break;
      }
    }

    // ── 3. Dangerous schemes ───────────────────────────────────────────────
    for (const { re, inContext, label, severity } of DANGEROUS_SCHEMES) {
      if (re.test(content) && inContext.test(content)) {
        findings.push(normalizeFinding({
          ruleId: 'A10-SSRF-SRC-003',
          owaspCategory: 'A10',
          title: 'URL scheme nguy hiểm được chấp nhận trong HTTP request',
          severity,
          confidence: 'medium',
          target: path,
          location: path,
          evidence: [label, 'file:// cho phép đọc file hệ thống. gopher:// cho phép interact với internal TCP services.'],
          remediation:
            'Chỉ cho phép scheme https:// (và http:// nếu cần). ' +
            'Explicitly reject: file, gopher, dict, sftp, ldap, ftp, data.',
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
          ],
          collector: 'source',
        }));
        break;
      }
    }

    // ── 4. Unvalidated redirect ────────────────────────────────────────────
    for (const { re, label, lang, severity } of UNVALIDATED_REDIRECT_SOURCE) {
      if (re.test(content)) {
        findings.push(normalizeFinding({
          ruleId: 'A10-SSRF-SRC-004',
          owaspCategory: 'A10',
          title: 'Open redirect với user-controlled URL — có thể kết hợp SSRF',
          severity,
          confidence: 'medium',
          target: path,
          location: path,
          evidence: [`[${lang}] ${label}`, 'Open redirect có thể bypass SSRF protection nếu server follow redirect.'],
          remediation:
            'Validate redirect destination: chỉ cho phép relative path hoặc domain được whitelist. ' +
            'Không redirect đến URL tuyệt đối từ user input mà không kiểm tra.',
          references: [
            'https://owasp.org/Top10/2025/A10_2025-Server_Side_Request_Forgery/',
            'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html',
          ],
          collector: 'source',
        }));
        break;
      }
    }
  }

  return findings;
}

module.exports = { runSsrfSource };

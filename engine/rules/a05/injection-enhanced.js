// engine/rules/a05/injection-enhanced.js
const { normalizeFinding } = require('../../models/finding');

/**
 * Bộ quy tắc Injection nâng cao (A05)
 * Tham chiếu OWASP WSTG: WSTG-INPV-05 đến WSTG-INPV-15
 *
 * Nâng cấp so với bản gốc:
 *  1. runSstiHeuristic: Chỉ dùng marker đặc trưng, không check số 49 chung chung (giữ nguyên fix)
 *  2. runSqliEnhanced: Thêm signature cho MSSQL xp_cmdshell, information_schema leak
 *  3. runNoSqliHeuristic: Thêm nhiều MongoDB/Redis error pattern
 *  4. runXxeHeuristic: Thêm OOB XXE indicator (SSRF endpoint trong XML response)
 *  5. runPrototypePollutionHeuristic: Giữ nguyên
 *  6. [NEW] runLdapInjectionHeuristic: Phát hiện LDAP error trong response
 *  7. [NEW] runXpathInjectionHeuristic: Phát hiện XPath error trong response
 *  8. [NEW] runCrlfHeuristic: Phát hiện CRLF / HTTP response splitting indicator
 *  9. [NEW] runLog4ShellHeuristic: Phát hiện Log4j JNDI payload reflection
 * 10. [NEW] runSsrfHeuristic: Phát hiện SSRF — nội dung metadata cloud hoặc internal response
 */

// ─────────────────────────────────────────────────────────────────────────────
// 1. SSTI (Server-Side Template Injection)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * BUG FIX: Phiên bản cũ dùng `/\b49\b/` để detect SSTI (math eval 7*7=49).
 * Pattern này khớp bất kỳ trang nào chứa số 49 — gây FALSE POSITIVE rất cao:
 * "49 results found", "version 1.49", "$49.99", v.v.
 *
 * FIX: Chỉ giữ lại SSTI_PROBE_7777 marker (marker đặc trưng hơn).
 */
function runSstiHeuristic(context) {
  const text = context.text || '';

  if (/SSTI_PROBE_7777/i.test(text)) {
    return [normalizeFinding({
      ruleId: 'A05-SSTI-001',
      owaspCategory: 'A05',
      title: 'Có dấu hiệu Server-Side Template Injection (SSTI)',
      severity: 'critical',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'response body',
      evidence: [
        'SSTI probe marker "SSTI_PROBE_7777" được reflect/evaluate trong response.',
        'SSTI có thể dẫn đến Remote Code Execution.',
      ],
      remediation:
        'Không dùng user input trực tiếp trong template string. ' +
        'Dùng sandbox hoặc static template với data binding.',
      references: [
        'https://portswigger.net/web-security/server-side-template-injection',
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-Side_Template_Injection',
      ],
      collector: 'blackbox',
    })];
  }
  return [];
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. SQL Injection — Error-based (nâng cao)
// ─────────────────────────────────────────────────────────────────────────────

const SQLI_PATTERNS = [
  { re: /sql syntax|you have an error in your sql syntax/i,          db: 'MySQL',            severity: 'high' },
  { re: /pg_query\(\)|postgres.*error|pgsql.*error|PSQLException/i,  db: 'PostgreSQL',       severity: 'high' },
  { re: /sqlite.*error|sqliteexception|SQLiteException/i,            db: 'SQLite',           severity: 'high' },
  { re: /microsoft.*odbc.*sql|ole db.*provider.*sql|mssql/i,        db: 'MSSQL',            severity: 'high' },
  { re: /ora-\d{5}|oracle.*error|OracleException/i,                  db: 'Oracle',           severity: 'high' },
  { re: /unclosed quotation mark|quoted string not properly terminated/i, db: 'Generic SQL', severity: 'medium' },
  { re: /column.*doesn't exist|relation.*does not exist/i,           db: 'PostgreSQL/Generic', severity: 'medium' },
  // MSSQL xp_cmdshell indicator
  { re: /xp_cmdshell|sp_executesql|OPENROWSET/i,                     db: 'MSSQL (stored proc)', severity: 'critical' },
  // Information schema leak
  { re: /information_schema\.(tables|columns)|table_name.*from.*information_schema/i, db: 'SQL (schema leak)', severity: 'high' },
  // Generic DB error messages
  { re: /java\.sql\.(SQLException|SQLSyntaxErrorException)/i,        db: 'Java JDBC',        severity: 'high' },
  { re: /System\.Data\.SqlClient\.SqlException/i,                    db: '.NET SqlClient',   severity: 'high' },
  { re: /PDOException.*SQLSTATE/i,                                   db: 'PHP PDO',          severity: 'high' },
];

function runSqliEnhanced(context) {
  const text = context.text || '';
  const findings = [];

  for (const pat of SQLI_PATTERNS) {
    if (pat.re.test(text)) {
      findings.push(normalizeFinding({
        ruleId: 'A05-SQLI-002',
        owaspCategory: 'A05',
        title: `Lỗi ${pat.db} database lộ trong response`,
        severity: pat.severity,
        confidence: 'high',
        target: context.finalUrl,
        location: 'response body',
        evidence: [`Phát hiện error message của ${pat.db} trong HTTP response`],
        remediation:
          'Dùng parameterized queries/prepared statements. ' +
          'Ẩn database errors phía client, chỉ log nội bộ. ' +
          'Implement WAF rule cho SQL error message.',
        references: [
          'https://owasp.org/Top10/2025/A05_2025-Injection/',
          'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
        ],
        collector: 'blackbox',
      }));
      break; // Chỉ cần 1 finding per URL để tránh spam
    }
  }
  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. NoSQL Injection
// ─────────────────────────────────────────────────────────────────────────────

function runNoSqliHeuristic(context) {
  const text = context.text || '';

  const patterns = [
    { re: /\$where|Cannot read property.*of null|Cannot read properties of null/i, label: 'MongoDB JS injection / null dereference' },
    { re: /MongoError|MongoServerError|BSONTypeError/i,                             label: 'Đối tượng lỗi MongoDB' },
    { re: /E11000 duplicate key error/i,                                            label: 'Lỗi MongoDB duplicate key' },
    { re: /MongoNetworkError|MongoTimeoutError/i,                                   label: 'Lỗi MongoDB network/timeout' },
    // Redis
    { re: /WRONGTYPE Operation|ERR wrong number of arguments for/i,                 label: 'Lỗi lệnh Redis' },
    { re: /NOAUTH Authentication required/i,                                        label: 'Lỗi Redis authentication (cấu hình sai)' },
    // Cassandra
    { re: /com\.datastax\..*DriverException|InvalidQueryException/i,                label: 'Lỗi driver Cassandra' },
    // CouchDB
    { re: /\{"error":"(bad_request|not_found|compilation_error)"/i,                 label: 'Phản hồi lỗi CouchDB' },
  ];

  const matches = patterns.filter(({ re }) => re.test(text));
  if (matches.length === 0) return [];

  return [normalizeFinding({
    ruleId: 'A05-NOSQL-001',
    owaspCategory: 'A05',
    title: 'Có dấu hiệu NoSQL error exposure',
    severity: 'high',
    confidence: 'medium',
    target: context.finalUrl,
    location: 'response body',
    evidence: matches.map(m => m.label),
    remediation:
      'Validate và sanitize input trước khi dùng trong NoSQL query. ' +
      'Không dùng $where với untrusted input. Ẩn error details.',
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection',
      'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
    ],
    collector: 'blackbox',
  })];
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. XXE (XML External Entity)
// ─────────────────────────────────────────────────────────────────────────────

function runXxeHeuristic(context) {
  const text = context.text || '';
  const contentType = (context.contentType || '').toLowerCase();

  const isXml = contentType.includes('xml') || text.trimStart().startsWith('<?xml');
  if (!isXml) return [];

  const indicators = [
    { re: /file:\/\/|\/etc\/passwd|\/etc\/shadow/i,        label: 'Dấu hiệu truy cập File system (file:// hoặc đường dẫn nhạy cảm)' },
    { re: /localhost|127\.0\.0\.1|169\.254\.169\.254/i,    label: 'Dấu hiệu SSRF/SSRF-like qua XXE (localhost/metadata IP)' },
    { re: /<!DOCTYPE[^>]*\[.*<!ENTITY/si,                  label: 'Khai báo DOCTYPE với ENTITY trong XML' },
    { re: /&\w+;(?!amp;|lt;|gt;|quot;|apos;)/,             label: 'Tham chiếu Custom XML entity (có thể mở rộng XXE)' },
  ];

  const matches = indicators.filter(({ re }) => re.test(text));
  if (matches.length === 0) return [];

  return [normalizeFinding({
    ruleId: 'A05-XXE-001',
    owaspCategory: 'A05',
    title: 'Có dấu hiệu XML External Entity (XXE) vulnerability',
    severity: 'high',
    confidence: 'low',
    target: context.finalUrl,
    location: 'XML response',
    evidence: matches.map(m => m.label),
    remediation:
      'Disable XML external entity processing trong parser config. ' +
      'Dùng safe XML parser (FEATURE_SECURE_PROCESSING = true). ' +
      'Consider JSON thay XML nếu không bắt buộc.',
    references: [
      'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
      'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html',
    ],
    collector: 'blackbox',
  })];
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Prototype Pollution
// ─────────────────────────────────────────────────────────────────────────────

function runPrototypePollutionHeuristic(context) {
  const text = context.text || '';

  if (/"__proto__"\s*:|"constructor"\s*:\s*\{/i.test(text)) {
    return [normalizeFinding({
      ruleId: 'A05-PROTO-001',
      owaspCategory: 'A05',
      title: 'Có dấu hiệu __proto__ hoặc constructor trong JSON response',
      severity: 'medium',
      confidence: 'low',
      target: context.finalUrl,
      location: 'JSON response body',
      evidence: ['Response chứa __proto__ hoặc constructor key — kiểm tra prototype pollution vulnerability'],
      remediation:
        'Sanitize JSON input, reject keys như __proto__, prototype, constructor. ' +
        'Dùng Object.create(null) hoặc JSON schema validation.',
      references: ['https://portswigger.net/web-security/prototype-pollution'],
      collector: 'blackbox',
    })];
  }
  return [];
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. [NEW] LDAP Injection
// ─────────────────────────────────────────────────────────────────────────────

const LDAP_ERROR_PATTERNS = [
  { re: /javax\.naming\.(NamingException|directory\.InvalidAttributeValueException)/i, label: 'Ngoại lệ Java JNDI/LDAP NamingException' },
  { re: /LDAPException|LdapException|com\.sun\.jndi\.ldap/i,                          label: 'Lớp ngoại lệ Java LDAP' },
  { re: /LDAP:.*error code \d+/i,                                                     label: 'Mã lỗi LDAP trong response' },
  { re: /Invalid DN syntax|object class violation/i,                                  label: 'Lỗi LDAP DN/schema' },
  { re: /\bCN=|OU=|DC=\b.*\bCN=|OU=|DC=\b/i,                                        label: 'Thành phần LDAP Distinguished Name (DN) trong response' },
  { re: /Active Directory.*error|LDAP bind.*failed/i,                                 label: 'Lỗi Active Directory / LDAP bind' },
  { re: /\bldap_search\b|\bldap_bind\b|\bldap_connect\b/i,                           label: 'Tên hàm PHP LDAP trong response' },
];

function runLdapInjectionHeuristic(context) {
  const text = context.text || '';
  const matches = LDAP_ERROR_PATTERNS.filter(({ re }) => re.test(text));
  if (matches.length === 0) return [];

  return [normalizeFinding({
    ruleId: 'A05-LDAP-001',
    owaspCategory: 'A05',
    title: 'Có dấu hiệu LDAP error hoặc LDAP Injection',
    severity: 'high',
    confidence: 'medium',
    target: context.finalUrl,
    location: 'response body',
    evidence: matches.map(m => m.label),
    remediation:
      'Escape tất cả ký tự đặc biệt LDAP trước khi dùng trong filter/DN: `(`, `)`, `*`, `\\`, `NUL`. ' +
      'Dùng parameterized LDAP query hoặc LDAP library có built-in escaping. ' +
      'Ẩn LDAP error messages khỏi response.',
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection',
      'https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html',
    ],
    collector: 'blackbox',
  })];
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. [NEW] XPath Injection
// ─────────────────────────────────────────────────────────────────────────────

const XPATH_ERROR_PATTERNS = [
  { re: /XPathException|XPath.*error|invalid XPath expression/i,         label: 'Ngoại lệ/Thông báo lỗi XPath' },
  { re: /javax\.xml\.xpath\.XPathExpressionException/i,                  label: 'Ngoại lệ Java XPathExpressionException' },
  { re: /SimpleXML.*error|DOMXPath.*error/i,                             label: 'Lỗi PHP SimpleXML/DOMXPath' },
  { re: /XslTransformException|XsltException/i,                          label: 'Ngoại lệ .NET XSLT/XPath' },
  { re: /unterminated string literal.*XPath|expected.*node.*XPath/i,    label: 'Chi tiết lỗi cú pháp XPath trong response' },
];

function runXpathInjectionHeuristic(context) {
  const text = context.text || '';
  const matches = XPATH_ERROR_PATTERNS.filter(({ re }) => re.test(text));
  if (matches.length === 0) return [];

  return [normalizeFinding({
    ruleId: 'A05-XPATH-001',
    owaspCategory: 'A05',
    title: 'Có dấu hiệu XPath error — khả năng XPath Injection',
    severity: 'high',
    confidence: 'medium',
    target: context.finalUrl,
    location: 'response body',
    evidence: matches.map(m => m.label),
    remediation:
      'Không concatenate user input vào XPath expression. ' +
      'Dùng parameterized XPath hoặc XQuery variable binding. ' +
      'Escape ký tự đặc biệt XPath: `\'`, `"`, `[`, `]`.',
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection',
      'https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html',
    ],
    collector: 'blackbox',
  })];
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. [NEW] CRLF / HTTP Response Splitting
// ─────────────────────────────────────────────────────────────────────────────

function runCrlfHeuristic(context) {
  const text = context.text || '';
  const findings = [];

  // Kiểm tra CRLF được reflect trong response header (qua Location, Set-Cookie)
  const locationHeader = context.headers?.get?.('location') || context.responseHeaders?.['location'] || '';
  const hasCrlfInLocation = /(%0d%0a|%0a|%0d|\r\n|\r|\n)/i.test(locationHeader);
  if (hasCrlfInLocation) {
    findings.push(normalizeFinding({
      ruleId: 'A05-CRLF-001',
      owaspCategory: 'A05',
      title: 'Có dấu hiệu CRLF injection trong Location header',
      severity: 'high',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'Location response header',
      evidence: [
        `Location header chứa ký tự CRLF hoặc URL-encoded CRLF: ${locationHeader.slice(0, 100)}`,
        'HTTP response splitting có thể dẫn đến XSS, cache poisoning, hoặc session fixation.',
      ],
      remediation:
        'Strip ký tự \\r, \\n khỏi giá trị trước khi đưa vào response header. ' +
        'Dùng allowlist characters khi build redirect URL.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling',
        'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
  }

  // Kiểm tra CRLF marker được reflect trong response body (từ probe)
  if (/CRLF_PROBE_TEST\r\n|\r\nCRLF_PROBE_TEST/i.test(text)) {
    findings.push(normalizeFinding({
      ruleId: 'A05-CRLF-002',
      owaspCategory: 'A05',
      title: 'CRLF probe marker được phản chiếu trong response — HTTP Response Splitting xác nhận',
      severity: 'high',
      confidence: 'high',
      target: context.finalUrl,
      location: 'response body',
      evidence: ['Probe marker CRLF_PROBE_TEST được reflect kèm CRLF sequences.'],
      remediation:
        'Không phản chiếu user input trực tiếp vào response header. ' +
        'Encode hoặc strip CRLF sequences.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling',
      ],
      collector: 'blackbox',
    }));
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. [NEW] Log4Shell (CVE-2021-44228) JNDI injection indicator
// ─────────────────────────────────────────────────────────────────────────────

function runLog4ShellHeuristic(context) {
  const text = context.text || '';

  // Nếu server echo lại JNDI lookup string chưa xử lý, đó là dấu hiệu xấu
  // Hoặc nếu response chứa error chỉ ra JNDI lookup được thực thi
  const jndiPatterns = [
    { re: /\$\{jndi:(ldap|rmi|dns|http|iiop):\/\//i,    label: 'Payload JNDI lookup được phản chiếu trong response' },
    { re: /log4j.*jndi|jndi.*ldap.*lookup/i,             label: 'Tham chiếu Log4j JNDI trong error/response' },
    { re: /SocketException.*ldap|ConnectException.*jndi/i, label: 'Lỗi mạng khi thực hiện JNDI lookup (Dấu hiệu OOB)' },
  ];

  const matches = jndiPatterns.filter(({ re }) => re.test(text));
  if (matches.length === 0) return [];

  return [normalizeFinding({
    ruleId: 'A05-LOG4J-001',
    owaspCategory: 'A05',
    title: 'Có dấu hiệu Log4Shell (CVE-2021-44228) — JNDI lookup trong response',
    severity: 'critical',
    confidence: 'medium',
    target: context.finalUrl,
    location: 'response body',
    evidence: matches.map(m => m.label),
    remediation:
      'Nâng cấp Log4j lên 2.17.1+ ngay lập tức. ' +
      'Set `log4j2.formatMsgNoLookups=true` hoặc dùng env `LOG4J_FORMAT_MSG_NO_LOOKUPS=true`. ' +
      'Block JNDI outbound trên firewall.',
    references: [
      'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228',
      'https://www.cisa.gov/uscert/ncas/alerts/aa21-356a',
      'https://logging.apache.org/log4j/2.x/security.html',
    ],
    collector: 'blackbox',
  })];
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. [NEW] SSRF (Server-Side Request Forgery) indicators in response
// ─────────────────────────────────────────────────────────────────────────────

function runSsrfHeuristic(context) {
  const text = context.text || '';
  const findings = [];

  // AWS metadata service content
  const awsMetadata = [
    { re: /ami-[0-9a-f]{8,17}/i,                        label: 'AWS AMI ID trong response (EC2 metadata)' },
    { re: /"InstanceId"\s*:\s*"i-[0-9a-f]{8,17}"/i,    label: 'AWS EC2 InstanceId trong response' },
    { re: /"AccessKeyId"\s*:\s*"ASIA|AKIA[A-Z0-9]{16}"/i, label: 'AWS credentials trong response (SSRF tới metadata)' },
    { re: /169\.254\.169\.254/,                          label: 'IP AWS metadata (169.254.169.254) trong response' },
  ];

  // GCP metadata service
  const gcpMetadata = [
    { re: /metadata\.google\.internal/i,                label: 'GCP metadata endpoint trong response' },
    { re: /"computeMetadata\/v1/i,                      label: 'GCP Compute Metadata API path trong response' },
  ];

  // Internal network indicators
  const internalNetwork = [
    { re: /Connection refused.*127\.|ECONNREFUSED.*127\./i, label: 'Kết nối bị từ chối tới localhost — Dấu hiệu SSRF internal probe' },
    { re: /192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\./,
      label: 'IP mạng nội bộ (RFC1918) trong response (có thể là SSRF/truy cập mạng nội bộ)' },
  ];

  const allPatterns = [...awsMetadata, ...gcpMetadata, ...internalNetwork];
  const matches = allPatterns.filter(({ re }) => re.test(text));

  if (matches.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A05-SSRF-001',
      owaspCategory: 'A05',
      title: 'Có dấu hiệu SSRF — thông tin nội bộ/cloud metadata trong response',
      severity: 'critical',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'response body',
      evidence: matches.map(m => m.label),
      remediation:
        'Validate và whitelist URL schemes/domains trước khi server-side request. ' +
        'Block outbound requests đến metadata IP (169.254.x.x) và RFC1918. ' +
        'Không phản chiếu nội dung fetch được về client.',
      references: [
        'https://owasp.org/Top10/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/',
        'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
  }

  return findings;
}

module.exports = {
  runSstiHeuristic,
  runSqliEnhanced,
  runNoSqliHeuristic,
  runXxeHeuristic,
  runPrototypePollutionHeuristic,
  runLdapInjectionHeuristic,
  runXpathInjectionHeuristic,
  runCrlfHeuristic,
  runLog4ShellHeuristic,
  runSsrfHeuristic,
};

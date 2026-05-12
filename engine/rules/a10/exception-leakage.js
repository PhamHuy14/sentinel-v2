const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện Exception / Stack Trace Leakage trong response
 * Tham chiếu: CWE-209, OWASP A10:2025 (Mishandling of Exceptional Conditions)
 *
 * Nâng cấp so với bản gốc (chỉ check missingPathProbe.hasVerboseErrors):
 *  1. Thêm pattern stack trace cụ thể theo ngôn ngữ
 *  2. Phát hiện verbose error trong status 200 (masked error)
 *  3. Phát hiện internal path / class name bị lộ
 *  4. Phát hiện database query trong error message
 */

// Pattern stack trace / verbose error theo ngôn ngữ
const STACK_TRACE_PATTERNS = [
  // Java
  { re: /at\s+[\w.$]+\([\w]+\.java:\d+\)/,
    label: 'Java stack trace (at ClassName.method(File.java:line))',    lang: 'Java' },
  { re: /Exception in thread|Caused by:\s+\w+Exception/i,
    label: 'Java "Exception in thread" hoặc "Caused by" error chain',  lang: 'Java' },
  // .NET
  { re: /at\s+[\w.]+\s+in\s+\w:[\\/].*\.cs:line\s+\d+/i,
    label: '.NET stack trace với file path và line number',             lang: '.NET' },
  { re: /System\.\w+Exception:|Microsoft\.\w+\.\w+Exception:/i,
    label: '.NET Exception class name trong response',                  lang: '.NET' },
  // Python
  { re: /Traceback\s+\(most recent call last\)/i,
    label: 'Python Traceback trong response',                           lang: 'Python' },
  { re: /File\s+"[^"]+\.py",\s+line\s+\d+/i,
    label: 'Python file path và line number trong response',            lang: 'Python' },
  // PHP
  { re: /(?:Fatal error|Parse error|Warning):\s+\w+.*in\s+\/.*\.php on line/i,
    label: 'PHP fatal/parse error với file path',                       lang: 'PHP' },
  { re: /Stack trace:\s*\n#\d+\s+[\w/]+\.php\(\d+\)/i,
    label: 'PHP stack trace',                                           lang: 'PHP' },
  // Node.js
  { re: /at\s+(?:Object\.|Function\.)?[\w.<>]+\s+\((?:\/[\w/.-]+\.js|\w+\.js):\d+:\d+\)/,
    label: 'Node.js stack trace với file path',                        lang: 'Node.js' },
  { re: /Error:\s+\w.*\n\s+at\s+/i,
    label: 'Node.js/JavaScript Error object với stack',                 lang: 'Node.js' },
  // Ruby
  { re: /\((?:RuntimeError|NoMethodError|ArgumentError)\)\n.*\.rb:\d+/i,
    label: 'Ruby exception với file path',                              lang: 'Ruby' },
  // Go
  { re: /goroutine\s+\d+\s+\[running\]|panic:\s+runtime error/i,
    label: 'Go panic / goroutine dump',                                 lang: 'Go' },
];

// Pattern internal path lộ trong error
const INTERNAL_PATH_PATTERNS = [
  { re: /[CD]:\\[\w\\.-]+\.(cs|java|php|py|js|ts)\b/i,  label: 'Windows absolute path trong error' },
  { re: /\/(?:home|usr|var|opt|srv|app|workspace)\/[\w/.-]+\.\w+/i, label: 'Linux absolute path trong error' },
  { re: /\/(?:WEB-INF|META-INF|classes|lib)\/[\w/.-]+/i, label: 'Java WAR internal path (WEB-INF)' },
];

// Pattern DB query lộ trong error
const DB_QUERY_IN_ERROR = [
  { re: /SELECT\s+.+\s+FROM\s+\w+.*WHERE/i,  label: 'SQL SELECT query trong error response' },
  { re: /INSERT\s+INTO\s+\w+\s*\(/i,          label: 'SQL INSERT query trong error response' },
  { re: /UPDATE\s+\w+\s+SET\s+/i,             label: 'SQL UPDATE query trong error response' },
  { re: /column\s+['"`]?\w+['"`]?\s+of\s+relation/i, label: 'PostgreSQL column error (schema leak)' },
];

function runExceptionLeakage(context) {
  const findings = [];
  const text   = context.text   || '';
  const status = context.status || 0;

  // ── 1. Từ missingPathProbe (bản gốc, giữ lại) ────────────────────────────
  if (context.missingPathProbe?.hasVerboseErrors) {
    findings.push(normalizeFinding({
      ruleId: 'A10-EX-001',
      owaspCategory: 'A10',
      title: 'Có dấu hiệu lộ exception/stack trace khi gặp tình huống bất thường',
      severity: 'high',
      confidence: 'high',
      target: context.missingPathProbe.url,
      location: 'error response',
      evidence: ['Response lỗi chứa chuỗi giống stack trace hoặc exception.'],
      remediation:
        'Ẩn chi tiết lỗi với client, log nội bộ đầy đủ, dùng fail-safe response nhất quán.',
      references: [
        'https://owasp.org/Top10/2025/A10_2025-Server_Side_Request_Forgery/',
        'https://cwe.mitre.org/data/definitions/209.html',
      ],
      collector: 'blackbox',
    }));
  }

  // ── 2. Stack trace patterns trong response ────────────────────────────────
  const stackMatches = STACK_TRACE_PATTERNS.filter(({ re }) => re.test(text));
  if (stackMatches.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A10-EX-002',
      owaspCategory: 'A10',
      title: 'Stack trace / verbose error bị lộ trong HTTP response',
      severity: 'high',
      confidence: 'high',
      target: context.finalUrl,
      location: `response body (HTTP ${status})`,
      evidence: stackMatches.map(m => `[${m.lang}] ${m.label}`),
      remediation:
        'Implement global error handler: trả về generic message cho client, log chi tiết nội bộ. ' +
        'Express: `app.use((err, req, res, next) => res.status(500).json({error: "Internal Server Error"}))`. ' +
        'Spring Boot: `@ControllerAdvice` + `server.error.include-stacktrace=never`. ' +
        'Django: `DEBUG=False` trong production.',
      references: [
        'https://cwe.mitre.org/data/definitions/209.html',
        'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
  }

  // ── 3. Internal path lộ ───────────────────────────────────────────────────
  const pathMatches = INTERNAL_PATH_PATTERNS.filter(({ re }) => re.test(text));
  if (pathMatches.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A10-EX-003',
      owaspCategory: 'A10',
      title: 'Internal file path bị lộ trong response — information disclosure',
      severity: 'medium',
      confidence: 'high',
      target: context.finalUrl,
      location: 'response body',
      evidence: pathMatches.map(m => m.label),
      remediation:
        'Ẩn internal path khỏi error message. ' +
        'Log path nội bộ, trả về generic message cho client.',
      references: [
        'https://cwe.mitre.org/data/definitions/209.html',
        'https://owasp.org/Top10/2025/A10_2025-Server_Side_Request_Forgery/',
      ],
      collector: 'blackbox',
    }));
  }

  // ── 4. DB query lộ trong error ────────────────────────────────────────────
  const dbMatches = DB_QUERY_IN_ERROR.filter(({ re }) => re.test(text));
  if (dbMatches.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A10-EX-004',
      owaspCategory: 'A10',
      title: 'Database query bị lộ trong error response — schema và data structure exposure',
      severity: 'high',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'error response body',
      evidence: dbMatches.map(m => m.label),
      remediation:
        'Không expose SQL query trong error response. ' +
        'Catch database exceptions và trả về generic database error message. ' +
        'Dùng parameterized queries để tránh SQL injection.',
      references: [
        'https://cwe.mitre.org/data/definitions/209.html',
        'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
  }

  return findings;
}

module.exports = { runExceptionLeakage };

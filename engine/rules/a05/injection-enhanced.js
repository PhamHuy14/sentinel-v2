// engine/rules/a05/injection-enhanced.js
const { normalizeFinding } = require('../../models/finding');

/**
 * BUG FIX: Phiên bản cũ dùng `/\b49\b/` để detect SSTI (math eval 7*7=49).
 * Pattern này khớp bất kỳ trang nào chứa số 49 — gây FALSE POSITIVE rất cao:
 * "49 results found", "version 1.49", "$49.99", v.v. → tất cả bị báo là SSTI critical.
 *
 * FIX:
 * 1. Loại bỏ check regex `/\b49\b/` trong static heuristic (quá noisy).
 * 2. Chỉ giữ lại SSTI_PROBE_7777 marker (marker đặc trưng hơn).
 * 3. SSTI thực sự được detect chính xác hơn trong fuzzer.js qua `isSsti()` trong analyzer.js,
 *    kết hợp với payload cụ thể — không dùng static scan của hàm này.
 */
function runSstiHeuristic(context) {
  const text = context.text || '';

  // Chỉ check marker đặc trưng — không check số 49 chung chung
  if (/SSTI_PROBE_7777/i.test(text)) {
    return [normalizeFinding({
      ruleId: 'A05-SSTI-001',
      owaspCategory: 'A05',
      title: 'Có dấu hiệu Server-Side Template Injection (SSTI)',
      severity: 'critical',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'response body',
      evidence: ['SSTI probe marker "SSTI_PROBE_7777" được reflect/evaluate trong response — SSTI có thể dẫn đến Remote Code Execution.'],
      remediation: 'Không dùng user input trực tiếp trong template string. Dùng sandbox hoặc static template với data binding.',
      references: ['https://portswigger.net/web-security/server-side-template-injection'],
      collector: 'blackbox',
    })];
  }
  return [];
}

function runSqliEnhanced(context) {
  const text = context.text || '';
  const findings = [];
  const dbErrorPatterns = [
    { re: /sql syntax|you have an error in your sql syntax/i, db: 'MySQL', severity: 'high' },
    { re: /pg_query\(\)|postgres.*error|pgsql.*error/i, db: 'PostgreSQL', severity: 'high' },
    { re: /sqlite.*error|sqliteexception/i, db: 'SQLite', severity: 'high' },
    { re: /microsoft.*odbc.*sql|ole db.*provider.*sql/i, db: 'MSSQL', severity: 'high' },
    { re: /ora-\d{5}|oracle.*error/i, db: 'Oracle', severity: 'high' },
    { re: /unclosed quotation mark|quoted string not properly terminated/i, db: 'Generic SQL', severity: 'medium' },
    { re: /column.*doesn't exist|relation.*does not exist/i, db: 'PostgreSQL/Generic', severity: 'medium' },
  ];
  for (const pat of dbErrorPatterns) {
    if (pat.re.test(text)) {
      findings.push(normalizeFinding({
        ruleId: 'A05-SQLI-002',
        owaspCategory: 'A05',
        title: `Lỗi ${pat.db} database lộ trong response`,
        severity: pat.severity,
        confidence: 'high',
        target: context.finalUrl,
        location: 'response body',
        evidence: [`Phát hiện error message của ${pat.db} trong response HTTP`],
        remediation: 'Dùng parameterized queries/prepared statements. Ẩn database errors, log nội bộ.',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
        collector: 'blackbox',
      }));
      break;
    }
  }
  return findings;
}

function runNoSqliHeuristic(context) {
  const text = context.text || '';
  if (/\$where|Cannot read property|MongoError|BSONTypeError|E11000 duplicate/i.test(text)) {
    return [normalizeFinding({
      ruleId: 'A05-NOSQL-001',
      owaspCategory: 'A05',
      title: 'Có dấu hiệu NoSQL error exposure',
      severity: 'high',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'response body',
      evidence: ['Response chứa MongoDB/NoSQL error message'],
      remediation: 'Validate và sanitize input trước khi dùng trong MongoDB query.',
      references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection'],
      collector: 'blackbox',
    })];
  }
  return [];
}

function runXxeHeuristic(context) {
  const text = context.text || '';
  const contentType = (context.contentType || '').toLowerCase();
  if ((contentType.includes('xml') || text.trimStart().startsWith('<?xml')) &&
      /file:\/\/|\/etc\/passwd|localhost|127\.0\.0\.1/i.test(text)) {
    return [normalizeFinding({
      ruleId: 'A05-XXE-001',
      owaspCategory: 'A05',
      title: 'Có dấu hiệu XML External Entity (XXE) vulnerability',
      severity: 'high',
      confidence: 'low',
      target: context.finalUrl,
      location: 'XML response',
      evidence: ['XML response chứa dấu hiệu file system access hoặc SSRF'],
      remediation: 'Disable XML external entity processing. Dùng safe XML parser configuration.',
      references: ['https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing'],
      collector: 'blackbox',
    })];
  }
  return [];
}

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
      remediation: 'Sanitize JSON input, reject keys như __proto__, prototype, constructor.',
      references: ['https://portswigger.net/web-security/prototype-pollution'],
      collector: 'blackbox',
    })];
  }
  return [];
}

module.exports = { runSstiHeuristic, runSqliEnhanced, runNoSqliHeuristic, runXxeHeuristic, runPrototypePollutionHeuristic };

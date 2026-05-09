const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện SQL Error Leakage (basic scan, blackbox)
 * Tham chiếu OWASP WSTG: WSTG-INPV-05
 *
 * Nâng cấp so với bản gốc:
 *  1. Pattern cụ thể hơn, giảm false positive từ từ khóa chung như "sql" hay "database"
 *  2. Thêm pattern PostgreSQL, MSSQL đặc trưng
 *  3. Kết hợp với `runSqliEnhanced` trong injection-enhanced.js để tránh trùng lặp:
 *     - File này (A05-SQLI-001) là scan nhanh, pattern broad → confidence: low
 *     - injection-enhanced.js (A05-SQLI-002) là scan chi tiết → confidence: high
 *  4. Không báo nếu là trang documentation (path chứa /docs, /help)
 */

// Pattern ngắn gọn nhưng đặc trưng hơn để giảm false positive
const QUICK_SQLI_PATTERNS = [
  /sql syntax near|you have an error in your sql syntax/i,
  /Warning:\s*(mysql_|mysqli_|pg_)/i,
  /\bSQLite\b.*exception|\bSQLiteException\b/i,
  /ODBC\s+(Microsoft|SQL Server|Access)\s+(Driver|Error)/i,
  /\bORA-\d{4,5}\b/,                         // Oracle error code
  /Exception.*SQLException|SQLException.*line/i,
  /Uncaught.*PDOException|SQLSTATE\[\w+\]/i,
  /pg_exec\(\)|pg_query\(\).*error/i,
  /invalid input syntax for type.*postgres/i,
  /relation.*does not exist.*postgresql/i,
];

function runSqliErrorBased(context) {
  const text = context.text || '';
  const url = (context.finalUrl || '').toLowerCase();

  // Bỏ qua trang documentation để giảm false positive
  if (/\/(docs?|help|manual|tutorial|example|reference)(\/|$)/.test(url)) {
    return [];
  }

  const matched = QUICK_SQLI_PATTERNS.some(re => re.test(text));
  if (!matched) return [];

  return [normalizeFinding({
    ruleId: 'A05-SQLI-001',
    owaspCategory: 'A05',
    title: 'Có dấu hiệu lộ lỗi SQL / database error trong response',
    severity: 'high',
    confidence: 'medium',
    target: context.finalUrl,
    location: 'response body',
    evidence: [
      'Response chứa chuỗi đặc trưng của SQL error hoặc database error.',
      'Lộ lỗi SQL giúp attacker suy luận cấu trúc database và xây dựng payload injection.',
    ],
    remediation:
      'Ẩn lỗi chi tiết với người dùng cuối và rà soát query parameterization. ' +
      'Dùng prepared statements/parameterized queries. ' +
      'Implement global exception handler để trả về error message chung chung.',
    references: [
      'https://owasp.org/Top10/2025/A05_2025-Injection/',
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection',
      'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
    ],
    collector: 'blackbox',
  })];
}

module.exports = { runSqliErrorBased };

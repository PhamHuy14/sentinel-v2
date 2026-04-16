// engine/scanner/analyzer.js
// ── Bản nâng cao: XSS, SQLi (error + timing), Open Redirect, SSRF, Path Traversal, SSTI, Cmd Injection

/**
 * Reflected XSS — kiểm tra payload có bị phản xạ trong HTML response hay không
 */
function isReflectedXss(res, payload) {
  if (!res?.text || !res?.response) return false;
  const ct = (res.response.headers.get('content-type') || '').toLowerCase();
  if (!ct.includes('text/html')) return false;
  return res.text.includes(payload);
}

/**
 * SQL Injection — phát hiện kiểu error-based
 * So khớp các mẫu lỗi DB phổ biến của MySQL, MSSQL, PostgreSQL, Oracle, SQLite
 */
const SQL_ERROR_RE = /(You have an error in your SQL syntax|mysql_fetch|mysql_num_rows|ORA-\d{5}|PostgreSQL.*ERROR|pg_query\(\)|SQLite3?::Exception|Syntax error.*string|Unclosed quotation mark|Microsoft OLE DB Provider for SQL Server|Driver\[SQL Server\]|Incorrect syntax near|Warning.*mysql_|supplied argument is not a valid MySQL|Division by zero in|System\.Data\.SqlClient|ODBC SQL Server Driver)/i;

/**
 * SQL Injection — error-based detection.
 * Chỉ báo khi body thực sự chứa SQL error pattern.
 * KHÔNG báo chỉ vì HTTP 500 — quá nhiều false positive (rate limit, crash, v.v.)
 */
function isSqlError(res) {
  if (!res?.text || !res?.response) return false;
  return SQL_ERROR_RE.test(res.text);
}

/**
 * SQL Injection — phát hiện kiểu time-based
 * So sánh với thời gian phản hồi gốc để giảm false positive
 */
function isSqlTiming(res, sleepSecs = 3, baselineMs = 0) {
  if (!res || typeof res.timeMs !== 'number') return false;
  const thresholdMs = sleepSecs * 1000 * 0.85; // allow 15% tolerance
  // Phải chậm hơn baseline đủ rõ ràng mới coi là tín hiệu timing đáng tin
  return res.timeMs > thresholdMs && res.timeMs > (baselineMs + sleepSecs * 800);
}

/**
 * Open Redirect — kiểm tra xem URL cuối cùng có redirect sang domain do attacker kiểm soát hay không
 */
function isOpenRedirect(res, payload) {
  if (!res?.finalUrl || !payload) return false;
  const cleanPayload  = payload.replace(/\/+$/, '').toLowerCase();
  const cleanFinalUrl = res.finalUrl.replace(/\/+$/, '').toLowerCase();
  return cleanFinalUrl.startsWith(cleanPayload) || cleanFinalUrl.includes('evil.example.com');
}

/**
 * SSRF — phát hiện phản hồi làm rò rỉ metadata nội bộ / cloud
 * Kiểm tra các mẫu metadata cloud phổ biến trong response body
 */
const SSRF_SIGNATURES = [
  /ami-id|instance-id|instance-type|local-ipv4|public-ipv4/i,  // AWS EC2
  /computeMetadata|project-id|serviceAccounts/i,                // GCP
  /IMDS|WindowsAzure|MSI_ENDPOINT/i,                            // Azure
  /ECS_CONTAINER_METADATA_URI|AWS_CONTAINER/i,                  // ECS
  /"AccessKeyId"|"SecretAccessKey"|"Token"/,                     // Rò rỉ credential AWS
];

function isSsrfResponse(res) {
  if (!res?.text) return false;
  // Redirect tới IP nội bộ cũng được xem là tín hiệu dương tính
  try {
    const finalUrl = new URL(res.finalUrl || '');
    const h = finalUrl.hostname;
    if (h === '169.254.169.254' || h === '127.0.0.1' || h === 'localhost' || h === '::1' || h === '0.0.0.0') return true;
  } catch {}
  return SSRF_SIGNATURES.some(re => re.test(res.text));
}

/**
 * Path Traversal — phát hiện rò rỉ nội dung file hệ điều hành trong response
 */
const PATH_TRAVERSAL_RE = /root:x:0:0|daemon:x:|nobody:x:|^\[boot loader\]|\[fonts\]|for 16-bit app|\[extensions\]/im;

function isPathTraversal(res) {
  if (!res?.text) return false;
  return PATH_TRAVERSAL_RE.test(res.text);
}

/**
 * Server-Side Template Injection — kiểm tra math expression đã được evaluate chưa.
 *
 * THIẾT KẾ PAYLOAD (xem payload-engine.js):
 *   - SSTI_7x7     : payload chứa "7*7"      → expect result "49"     (quá phổ biến, false positive cao)
 *   - SSTI_CANARY  : payload chứa marker hiếm → expect canary trong response (chính xác hơn)
 *   - SSTI_JINJA2  : payload "7*'7'"          → expect "7777777"       (Jinja2 specific, đặc trưng)
 *
 * FIX (vấn đề C): "49" xuất hiện rất phổ biến trong HTML thực (pagination, price, version...).
 * Thay bằng payload marker hiếm `{{60481729}}` (= 7777*7777) và check kết quả đó.
 * Kết quả "60481729" gần như không bao giờ xuất hiện trong HTML thật → false positive gần như bằng 0.
 *
 * Fallback: vẫn giữ check Jinja2 "7777777" vì cũng rất đặc trưng.
 *
 * @param {object} res  - response object từ ScannerHttpClient
 * @param {string} payload - payload đã gửi đi
 */
function isSsti(res, payload) {
  if (!res?.text) return false;

  // Jinja2 / Twig: {{7*'7'}} → "7777777" — chuỗi lặp 7 lần, đặc trưng
  if (payload.includes("7*'7'") && res.text.includes('7777777')) return true;

  // Canary-based: payload dùng số hiếm 7777*7777=60481729
  // Xem PAYLOAD_DICTIONARY.template và .text trong payload-engine.js
  // Payload: "{{7777*7777}}", "${7777*7777}", "<%=7777*7777%>", "#{7777*7777}"
  if (
    (payload.includes('7777*7777') || payload.includes('7777 * 7777')) &&
    res.text.includes('60481729')
  ) return true;

  // Legacy: chỉ dùng khi payload chứa marker SNTL_SSTI_EVAL (không phải '7*7' chung chung)
  // để tránh false positive với HTML có số 49 bình thường
  if (payload.includes('SNTL_SSTI_EVAL') && res.text.includes('49')) return true;

  return false;
}

/**
 * Command Injection — phát hiện output lệnh hệ điều hành trong response
 */
const CMD_OUTPUT_RE = /root:.*:0:0|uid=\d+\(|total \d+\ndrwx|WINDOWS|Microsoft Windows|Volume Serial Number/i;

function isCommandInjection(res) {
  if (!res?.text) return false;
  return CMD_OUTPUT_RE.test(res.text);
}

module.exports = {
  isReflectedXss,
  isSqlError,
  isSqlTiming,
  isOpenRedirect,
  isSsrfResponse,
  isPathTraversal,
  isSsti,
  isCommandInjection,
};

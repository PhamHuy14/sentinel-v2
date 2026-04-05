// engine/scanner/analyzer.js
// ── Enhanced: XSS, SQLi (error + timing), Open Redirect, SSRF, Path Traversal, SSTI, Cmd Injection

/**
 * Reflected XSS — check payload echo in HTML response body
 */
function isReflectedXss(res, payload) {
  if (!res?.text || !res?.response) return false;
  const ct = (res.response.headers.get('content-type') || '').toLowerCase();
  if (!ct.includes('text/html')) return false;
  return res.text.includes(payload);
}

/**
 * SQL Injection — error-based detection
 * Matches common DB error signatures across MySQL, MSSQL, PostgreSQL, Oracle, SQLite
 */
const SQL_ERROR_RE = /(You have an error in your SQL syntax|mysql_fetch|mysql_num_rows|ORA-\d{5}|PostgreSQL.*ERROR|pg_query\(\)|SQLite3?::Exception|Syntax error.*string|Unclosed quotation mark|Microsoft OLE DB Provider for SQL Server|Driver\[SQL Server\]|Incorrect syntax near|Warning.*mysql_|supplied argument is not a valid MySQL|Division by zero in|System\.Data\.SqlClient|ODBC SQL Server Driver)/i;

function isSqlError(res) {
  if (!res?.text || !res?.response) return false;
  if (res.response.status === 500) return true;
  return SQL_ERROR_RE.test(res.text);
}

/**
 * SQL Injection — time-based detection
 * Compare against baseline response time to reduce false positives
 */
function isSqlTiming(res, sleepSecs = 3, baselineMs = 0) {
  if (!res || typeof res.timeMs !== 'number') return false;
  const thresholdMs = sleepSecs * 1000 * 0.85; // allow 15% tolerance
  // Must be significantly slower than baseline (at least sleepSecs - baseline)
  return res.timeMs > thresholdMs && res.timeMs > (baselineMs + sleepSecs * 800);
}

/**
 * Open Redirect — check if final URL redirected to attacker-controlled domain
 */
function isOpenRedirect(res, payload) {
  if (!res?.finalUrl || !payload) return false;
  const cleanPayload  = payload.replace(/\/+$/, '').toLowerCase();
  const cleanFinalUrl = res.finalUrl.replace(/\/+$/, '').toLowerCase();
  return cleanFinalUrl.startsWith(cleanPayload) || cleanFinalUrl.includes('evil.example.com');
}

/**
 * SSRF — detect response that leaks internal/cloud metadata
 * Checks for cloud metadata signatures in response body
 */
const SSRF_SIGNATURES = [
  /ami-id|instance-id|instance-type|local-ipv4|public-ipv4/i,  // AWS EC2
  /computeMetadata|project-id|serviceAccounts/i,                // GCP
  /IMDS|WindowsAzure|MSI_ENDPOINT/i,                            // Azure
  /ECS_CONTAINER_METADATA_URI|AWS_CONTAINER/i,                  // ECS
  /"AccessKeyId"|"SecretAccessKey"|"Token"/,                     // AWS credentials leak
];

function isSsrfResponse(res) {
  if (!res?.text) return false;
  // Redirect to internal IP is also a positive
  try {
    const finalUrl = new URL(res.finalUrl || '');
    const h = finalUrl.hostname;
    if (h === '169.254.169.254' || h === '127.0.0.1' || h === 'localhost' || h === '::1' || h === '0.0.0.0') return true;
  } catch {}
  return SSRF_SIGNATURES.some(re => re.test(res.text));
}

/**
 * Path Traversal — detect OS file content leak in response
 */
const PATH_TRAVERSAL_RE = /root:x:0:0|daemon:x:|nobody:x:|^\[boot loader\]|\[fonts\]|for 16-bit app|\[extensions\]/im;

function isPathTraversal(res) {
  if (!res?.text) return false;
  return PATH_TRAVERSAL_RE.test(res.text);
}

/**
 * Server-Side Template Injection — check if math expression was evaluated
 * A payload `{{7*7}}` should return 49 if SSTI exists
 */
function isSsti(res, payload) {
  if (!res?.text) return false;
  // Check for evaluated result of math expressions
  if (payload.includes('7*7') && res.text.includes('49')) return true;
  if (payload.includes('7*\'7\'') && res.text.includes('7777777')) return true; // Jinja2
  return false;
}

/**
 * Command Injection — detect OS command output in response
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

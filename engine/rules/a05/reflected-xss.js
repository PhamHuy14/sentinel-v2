const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện Reflected XSS và các dạng injection script
 * Tham chiếu OWASP WSTG: WSTG-INPV-01 (Reflected XSS)
 *
 * Nâng cấp so với bản gốc:
 *  1. Thêm nhiều XSS probe markers
 *  2. Phát hiện XSS payload phổ biến chưa encode trong response
 *  3. Phát hiện `javascript:` URL scheme trong href/src attributes
 *  4. Phát hiện event handler injection: onerror=, onload=
 *  5. Phát hiện DOM-based XSS indicator từ JS source
 *  6. Phân loại mức severity theo context (trong script tag vs HTML)
 */

// ─────────────────────────────────────────────────────────────────────────────
// 1. Probe-based detection (markers từ scanner)
// ─────────────────────────────────────────────────────────────────────────────

const XSS_PROBE_MARKERS = [
  '<script>alert(1337)</script>',
  'OWASP_XSS_PROBE_2025',
  '<script>alert(document.domain)</script>',
  '<img src=x onerror=alert(1)>',
  '"> <script>alert(1)</script>',
  "'> <script>alert(1)</script>",
];

function runReflectedXss(context) {
  const text = context.text || '';
  const findings = [];

  // Kiểm tra probe markers
  for (const marker of XSS_PROBE_MARKERS) {
    if (text.includes(marker)) {
      findings.push(normalizeFinding({
        ruleId: 'A05-XSS-001',
        owaspCategory: 'A05',
        title: 'Phát hiện XSS probe marker được phản chiếu trong response — Reflected XSS xác nhận',
        severity: 'high',
        confidence: 'high',
        target: context.finalUrl,
        location: 'response body',
        evidence: [
          `Marker "${marker.slice(0, 60)}" được phản chiếu nguyên vẹn trong response.`,
          'Input người dùng không được encode trước khi render vào HTML.',
        ],
        remediation:
          'Encode output theo đúng context: ' +
          'HTML encode cho nội dung HTML, JS escape cho script context, URL encode cho URL context. ' +
          'Implement Content Security Policy (CSP) header. ' +
          'Dùng framework có auto-escaping (React, Angular, Vue).',
        references: [
          'https://owasp.org/Top10/2025/A05_2025-Injection/',
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting',
          'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
        ],
        collector: 'blackbox',
      }));
      break; // Chỉ cần 1 finding per URL
    }
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Passive XSS heuristics (không cần probe, phân tích response tĩnh)
// ─────────────────────────────────────────────────────────────────────────────

const SCRIPT_INJECTION_PATTERNS = [
  // Script tag rõ ràng trong context không phải code block
  { re: /<script\b[^>]*>.*?alert\s*\(/is,    label: 'Gọi hàm alert() trong thẻ <script> của response' },
  { re: /<script\b[^>]*>.*?confirm\s*\(/is,  label: 'Gọi hàm confirm() trong thẻ <script> của response' },
  { re: /<script\b[^>]*>.*?prompt\s*\(/is,   label: 'Gọi hàm prompt() trong thẻ <script> của response' },
];

const EVENT_HANDLER_PATTERNS = [
  { re: /\bon(error|load|click|mouseover|focus|blur)\s*=\s*["']?(?:alert|confirm|prompt|eval|javascript)/i,
    label: 'Inline event handler với hàm thực thi JS (onerror=alert, onload=eval, ...)' },
];

const JAVASCRIPT_URL_PATTERNS = [
  { re: /href\s*=\s*["']?\s*javascript\s*:/i,
    label: 'URI `javascript:` trong thuộc tính href — dẫn đến XSS khi click' },
  { re: /src\s*=\s*["']?\s*javascript\s*:/i,
    label: 'URI `javascript:` trong thuộc tính src' },
  { re: /action\s*=\s*["']?\s*javascript\s*:/i,
    label: 'URI `javascript:` trong thuộc tính action của form' },
];

const DOM_XSS_INDICATORS = [
  // Các sink nguy hiểm nhận input trực tiếp
  { re: /document\.write\s*\(\s*(?:location|document\.URL|window\.location)/i,
    label: 'document.write() nhận URL/location — Sink DOM-based XSS' },
  { re: /innerHTML\s*=\s*(?:location|document\.URL|window\.location|decodeURIComponent)/i,
    label: 'Gán innerHTML từ URL/location — Sink DOM-based XSS' },
  { re: /eval\s*\(\s*(?:location|document\.URL|window\.location|decodeURIComponent)/i,
    label: 'eval() nhận URL/location — Sink DOM-based XSS' },
  { re: /\bpostMessage\b.*\*['"]$/im,
    label: 'postMessage với origin wildcard (*) — Vector DOM-based XSS' },
];

function runXssPassiveHeuristic(context) {
  const text = context.text || '';
  const contentType = (context.contentType || '').toLowerCase();
  const findings = [];

  // Chỉ check HTML/JS response
  if (!contentType.includes('html') && !contentType.includes('javascript') && !contentType.includes('text')) {
    return findings;
  }

  // Script injection patterns
  const scriptMatches = SCRIPT_INJECTION_PATTERNS.filter(({ re }) => re.test(text));
  if (scriptMatches.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A05-XSS-002',
      owaspCategory: 'A05',
      title: 'Có dấu hiệu script injection trong response HTML',
      severity: 'medium',
      confidence: 'low',
      target: context.finalUrl,
      location: 'response body (HTML)',
      evidence: scriptMatches.map(m => m.label),
      remediation:
        'Kiểm tra nguồn gốc script. Nếu là user-controlled input được reflect: encode output. ' +
        'Implement CSP để block inline scripts.',
      references: [
        'https://owasp.org/Top10/2025/A05_2025-Injection/',
        'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
  }

  // Event handler injection
  const eventMatches = EVENT_HANDLER_PATTERNS.filter(({ re }) => re.test(text));
  if (eventMatches.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A05-XSS-003',
      owaspCategory: 'A05',
      title: 'Có dấu hiệu inline event handler với script execution trong response',
      severity: 'medium',
      confidence: 'low',
      target: context.finalUrl,
      location: 'response body (HTML attributes)',
      evidence: eventMatches.map(m => m.label),
      remediation:
        'Không cho phép inline event handlers. ' +
        'Encode attribute context theo OWASP XSS cheatsheet. ' +
        'Dùng CSP `unsafe-inline` blocked.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'],
      collector: 'blackbox',
    }));
  }

  // javascript: URI
  const jsUriMatches = JAVASCRIPT_URL_PATTERNS.filter(({ re }) => re.test(text));
  if (jsUriMatches.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A05-XSS-004',
      owaspCategory: 'A05',
      title: 'Có `javascript:` URI scheme trong response — dẫn đến XSS',
      severity: 'high',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'response body (HTML attributes)',
      evidence: jsUriMatches.map(m => m.label),
      remediation:
        'Validate URL scheme khi build href/src. Chỉ cho phép http://, https://, / (relative). ' +
        'Dùng URL allowlist.',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#rule-5-url-escape-before-inserting-untrusted-data-into-html-url-parameter-values',
      ],
      collector: 'blackbox',
    }));
  }

  // DOM-based XSS sinks
  const domMatches = DOM_XSS_INDICATORS.filter(({ re }) => re.test(text));
  if (domMatches.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A05-XSS-005',
      owaspCategory: 'A05',
      title: 'Có dấu hiệu DOM-based XSS sink nhận URL/location trực tiếp',
      severity: 'high',
      confidence: 'low',
      target: context.finalUrl,
      location: 'response JavaScript',
      evidence: domMatches.map(m => m.label),
      remediation:
        'Không đưa data từ location/URL vào DOM sink (innerHTML, document.write, eval) chưa qua sanitization. ' +
        'Dùng DOMPurify hoặc trusted types.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-Side_Testing/01-Testing_for_DOM-Based_Cross_Site_Scripting',
        'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
  }

  return findings;
}

module.exports = { runReflectedXss, runXssPassiveHeuristic };

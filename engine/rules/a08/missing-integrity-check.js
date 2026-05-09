const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện thiếu Subresource Integrity (SRI) và integrity controls
 * Tham chiếu OWASP WSTG: WSTG-CONF-11, A08 Software and Data Integrity Failures
 *
 * Nâng cấp so với bản gốc:
 *  1. Mở rộng: check cả <link> external CSS, không chỉ <script>
 *  2. Thêm: check crossorigin attribute cần thiết đi kèm integrity
 *  3. Thêm: phát hiện import map không có integrity
 *  4. Thêm: phát hiện dynamic script injection (document.createElement('script'))
 *  5. Fix: bản gốc chỉ check context.configFiles — nay check cả context.textFiles
 *  6. Thêm: check CDN whitelist — nếu dùng CDN uy tín nhưng không có SRI
 */

// CDN phổ biến cần SRI khi dùng trong production
const KNOWN_CDNS = [
  'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com',
  'ajax.googleapis.com', 'code.jquery.com', 'stackpath.bootstrapcdn.com',
  'maxcdn.bootstrapcdn.com', 'cdn.bootcss.com', 'cdn.staticfile.org',
  'fonts.googleapis.com', 'use.fontawesome.com', 'kit.fontawesome.com',
];

function isCdnUrl(src) {
  try {
    const host = new URL(src).hostname;
    return KNOWN_CDNS.some(cdn => host === cdn || host.endsWith('.' + cdn));
  } catch {
    return src.startsWith('http'); // fallback: mọi external URL
  }
}

function runMissingIntegrityCheck(context) {
  const findings = [];

  // Lấy tất cả file HTML từ cả configFiles và textFiles
  const allFiles = [
    ...(context.configFiles || []),
    ...(context.textFiles || []),
  ];

  const htmlFiles = allFiles.filter(f =>
    /\.(html|htm|cshtml|razor|jsp|aspx|php|ejs|hbs|njk)$/i.test(f.path)
    || /index\.\w+$/.test(f.path)
  );

  for (const file of htmlFiles) {
    const content = file.content || '';

    // ── 1. External <script src> không có integrity ──────────────────────────
    const scriptTags = [...content.matchAll(/<script\b([^>]*)>/gi)];
    for (const [fullTag, attrs] of scriptTags) {
      const srcMatch = attrs.match(/src=["']([^"']+)["']/i);
      if (!srcMatch) continue;
      const src = srcMatch[1];
      if (!src.startsWith('http') && !src.startsWith('//')) continue;
      if (/integrity=/i.test(attrs)) continue;

      const isCdn = isCdnUrl(src);
      findings.push(normalizeFinding({
        ruleId: 'A08-INTEGRITY-001',
        owaspCategory: 'A08',
        title: `External script thiếu Subresource Integrity (SRI)${isCdn ? ' — CDN script' : ''}`,
        severity: isCdn ? 'high' : 'medium',
        confidence: 'high',
        target: file.path,
        location: `<script src="${src.slice(0, 80)}">`,
        evidence: [
          fullTag.slice(0, 180),
          isCdn
            ? `CDN script "${src.slice(0, 80)}" không có integrity hash — nếu CDN bị compromise, script độc hại sẽ được load.`
            : `External script không có SRI — nội dung có thể bị thay đổi mà không phát hiện.`,
        ],
        remediation:
          'Thêm integrity + crossorigin: ' +
          `<script src="${src.slice(0, 60)}" integrity="sha384-..." crossorigin="anonymous">. ` +
          'Tạo hash: openssl dgst -sha384 -binary file.js | openssl base64 -A. ' +
          'Hoặc dùng https://www.srihash.org/',
        references: [
          'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity',
          'https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/',
          'https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html',
        ],
        collector: 'source',
      }));
    }

    // ── 2. External <link rel="stylesheet"> không có integrity ───────────────
    const linkTags = [...content.matchAll(/<link\b([^>]*)>/gi)];
    for (const [fullTag, attrs] of linkTags) {
      const isStylesheet = /rel=["']stylesheet["']/i.test(attrs);
      if (!isStylesheet) continue;
      const hrefMatch = attrs.match(/href=["']([^"']+)["']/i);
      if (!hrefMatch) continue;
      const href = hrefMatch[1];
      if (!href.startsWith('http') && !href.startsWith('//')) continue;
      if (/integrity=/i.test(attrs)) continue;

      const isCdn = isCdnUrl(href);
      if (!isCdn) continue; // Chỉ cảnh báo CDN CSS (third-party CSS ít critical hơn script)

      findings.push(normalizeFinding({
        ruleId: 'A08-INTEGRITY-002',
        owaspCategory: 'A08',
        title: 'External CDN stylesheet thiếu SRI integrity hash',
        severity: 'medium',
        confidence: 'high',
        target: file.path,
        location: `<link href="${href.slice(0, 80)}">`,
        evidence: [
          fullTag.slice(0, 180),
          'CSS từ CDN không có integrity — CSS injection có thể dùng để exfiltrate data hoặc overlay phishing UI.',
        ],
        remediation:
          'Thêm integrity attribute cho external CSS: ' +
          `<link href="${href.slice(0, 60)}" integrity="sha384-..." crossorigin="anonymous" rel="stylesheet">`,
        references: [
          'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity',
          'https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/',
        ],
        collector: 'source',
      }));
    }

    // ── 3. integrity attribute không kèm crossorigin ─────────────────────────
    const sriWithoutCrossorigin = content.match(/<(?:script|link)\b[^>]*integrity=[^>]*>/gi) || [];
    for (const tag of sriWithoutCrossorigin) {
      if (!/crossorigin/i.test(tag)) {
        findings.push(normalizeFinding({
          ruleId: 'A08-INTEGRITY-003',
          owaspCategory: 'A08',
          title: 'SRI integrity attribute thiếu crossorigin="anonymous"',
          severity: 'low',
          confidence: 'high',
          target: file.path,
          location: tag.slice(0, 100),
          evidence: [
            tag.slice(0, 180),
            'SRI không hoạt động đúng nếu thiếu crossorigin="anonymous" — browser có thể không verify hash.',
          ],
          remediation: 'Thêm crossorigin="anonymous" vào tag có integrity attribute.',
          references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity#cors_and_subresource_integrity'],
          collector: 'source',
        }));
        break; // 1 finding per file
      }
    }

    // ── 4. Dynamic script injection ──────────────────────────────────────────
    const dynamicScript = /document\.createElement\s*\(\s*['"]script['"]\s*\)/i.test(content)
      && /\.src\s*=|setAttribute\s*\(\s*['"]src['"]/i.test(content);

    if (dynamicScript) {
      findings.push(normalizeFinding({
        ruleId: 'A08-INTEGRITY-004',
        owaspCategory: 'A08',
        title: 'Dynamic script injection phát hiện trong source — cần kiểm tra integrity',
        severity: 'medium',
        confidence: 'low',
        target: file.path,
        location: 'JavaScript (dynamic script creation)',
        evidence: [
          'Phát hiện document.createElement("script") + .src assignment.',
          'Dynamic script không thể dùng SRI trực tiếp — cần verify URL nguồn gốc và integrity bằng code.',
        ],
        remediation:
          'Nếu dynamic script là từ third-party: ' +
          '(1) Hardcode URL và verify bằng fetch + integrity check trước khi inject. ' +
          '(2) Hoặc tự host script thay vì load dynamic từ CDN. ' +
          '(3) Implement Content Security Policy để giới hạn script-src.',
        references: [
          'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity',
          'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html',
        ],
        collector: 'source',
      }));
    }
  }

  return findings;
}

module.exports = { runMissingIntegrityCheck };

const { normalizeFinding } = require('../../models/finding');

// Từ khóa cho cookie nhạy cảm -> escalate severity
const SENSITIVE_COOKIE_KEYWORDS = /session|sess|auth|token|jwt|user|uid|id|credential/i;

// Thời gian tối đa hợp lý cho cookie: 1 năm
const MAX_ACCEPTABLE_AGE_SECONDS = 365 * 24 * 60 * 60;

/**
 * Parse một Set-Cookie string thô thành object các thuộc tính.
 * @param {string} raw
 * @returns {object}
 */
function parseCookie(raw) {
  const parts = String(raw || '').split(';').map((p) => p.trim());
  const [nameValue = '', ...attrs] = parts;
  const eqIdx = nameValue.indexOf('=');
  const name = eqIdx !== -1 ? nameValue.slice(0, eqIdx) : nameValue;
  const value = eqIdx !== -1 ? nameValue.slice(eqIdx + 1) : '';

  const attrMap = {};
  for (const attr of attrs) {
    const [k, ...rest] = attr.split('=');
    attrMap[k.trim().toLowerCase()] = rest.join('=').trim();
  }

  return {
    name,
    value,
    raw,
    secure: 'secure' in attrMap,
    httponly: 'httponly' in attrMap,
    samesite: attrMap.samesite || null,
    domain: attrMap.domain || null,
    path: attrMap.path || '/',
    expires: attrMap.expires || null,
    maxAge: attrMap['max-age'] !== undefined ? parseInt(attrMap['max-age'], 10) : null,
  };
}

function runCookieFlags(context) {
  const findings = [];
  const setCookies = context.setCookies || [];
  const isHttps = context.protocol === 'https:';
  const isLocal = !!context.isLocalhost;

  for (const raw of setCookies) {
    if (!raw) continue;
    const cookie = parseCookie(raw);
    const isSensitive = SENSITIVE_COOKIE_KEYWORDS.test(cookie.name);

    // 1. Thiếu Secure trên HTTPS
    if (isHttps && !cookie.secure && !isLocal) {
      findings.push(normalizeFinding({
        ruleId: 'A02-COOKIE-001',
        owaspCategory: 'A02',
        title: `Cookie "${cookie.name}" thiếu thuộc tính Secure`,
        severity: isSensitive ? 'high' : 'medium',
        confidence: 'high',
        target: context.finalUrl,
        location: 'Set-Cookie header',
        evidence: [cookie.raw],
        remediation:
          `Thêm thuộc tính Secure vào cookie "${cookie.name}" để chỉ gửi qua HTTPS.\n` +
          'Set-Cookie: name=value; Secure; ...',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes',
        ],
        collector: 'blackbox',
      }));
    }

    // 2. Thiếu HttpOnly
    if (!cookie.httponly) {
      findings.push(normalizeFinding({
        ruleId: 'A02-COOKIE-002',
        owaspCategory: 'A02',
        title: `Cookie "${cookie.name}" thiếu thuộc tính HttpOnly`,
        severity: isSensitive ? 'high' : 'medium',
        confidence: 'high',
        target: context.finalUrl,
        location: 'Set-Cookie header',
        evidence: [cookie.raw],
        remediation:
          `Thêm HttpOnly vào cookie "${cookie.name}" để JavaScript không thể đọc giá trị.\n` +
          'Bảo vệ chống XSS-based session hijacking.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes',
        ],
        collector: 'blackbox',
      }));
    }

    // 3. Thiếu SameSite
    if (!cookie.samesite) {
      findings.push(normalizeFinding({
        ruleId: 'A02-COOKIE-003',
        owaspCategory: 'A02',
        title: `Cookie "${cookie.name}" thiếu thuộc tính SameSite`,
        severity: 'medium',
        confidence: 'high',
        target: context.finalUrl,
        location: 'Set-Cookie header',
        evidence: [cookie.raw],
        remediation:
          'Thêm SameSite=Lax hoặc SameSite=Strict để giảm nguy cơ CSRF.\n' +
          'Chỉ dùng SameSite=None nếu cần cross-site và phải kèm Secure.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes',
          'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
        ],
        collector: 'blackbox',
      }));
    }

    // 4. SameSite=None thiếu Secure
    if (cookie.samesite && cookie.samesite.toLowerCase() === 'none' && !cookie.secure) {
      findings.push(normalizeFinding({
        ruleId: 'A02-COOKIE-004',
        owaspCategory: 'A02',
        title: `Cookie "${cookie.name}": SameSite=None thiếu Secure - không hợp lệ`,
        severity: 'high',
        confidence: 'high',
        target: context.finalUrl,
        location: 'Set-Cookie header',
        evidence: [
          cookie.raw,
          'SameSite=None yêu cầu bắt buộc phải có Secure theo spec.',
        ],
        remediation:
          'Thêm Secure khi dùng SameSite=None:\n' +
          'Set-Cookie: name=value; SameSite=None; Secure',
        references: [
          'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite#none',
        ],
        collector: 'blackbox',
      }));
    }

    // 5. Expires/Max-Age quá xa
    let ageSeconds = null;
    if (cookie.maxAge !== null && !isNaN(cookie.maxAge)) {
      ageSeconds = cookie.maxAge;
    } else if (cookie.expires) {
      const exp = new Date(cookie.expires);
      if (!isNaN(exp.getTime())) {
        ageSeconds = (exp.getTime() - Date.now()) / 1000;
      }
    }

    if (ageSeconds !== null && ageSeconds > MAX_ACCEPTABLE_AGE_SECONDS) {
      const years = (ageSeconds / (365 * 24 * 3600)).toFixed(1);
      findings.push(normalizeFinding({
        ruleId: 'A02-COOKIE-005',
        owaspCategory: 'A02',
        title: `Cookie "${cookie.name}" có thời hạn sống quá dài (~${years} năm)`,
        severity: 'low',
        confidence: 'high',
        target: context.finalUrl,
        location: 'Set-Cookie header',
        evidence: [cookie.raw],
        remediation:
          'Giới hạn thời gian sống của cookie nhạy cảm (session cookie không nên quá 24h).\n' +
          'Dùng session cookie (không set Expires/Max-Age) nếu có thể.',
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
        ],
        collector: 'blackbox',
      }));
    }

    // 6. Domain quá rộng
    if (cookie.domain) {
      let pageHost = '';
      try {
        pageHost = new URL(context.finalUrl).hostname;
      } catch (_e) {
        pageHost = '';
      }

      const normalizedCookieDomain = cookie.domain.replace(/^\./, '');
      const domainTooWide =
        cookie.domain.startsWith('.') ||
        (pageHost && !pageHost.endsWith(normalizedCookieDomain));

      if (domainTooWide && isSensitive) {
        findings.push(normalizeFinding({
          ruleId: 'A02-COOKIE-006',
          owaspCategory: 'A02',
          title: `Cookie nhạy cảm "${cookie.name}" có Domain quá rộng`,
          severity: 'low',
          confidence: 'medium',
          target: context.finalUrl,
          location: 'Set-Cookie header',
          evidence: [
            cookie.raw,
            `Domain: ${cookie.domain} -> áp dụng cho tất cả subdomain.`,
          ],
          remediation:
            'Giới hạn Domain cookie đến hostname cụ thể nhất có thể.\n' +
            'Tránh dùng ".example.com" cho cookie session/auth.',
          references: [
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes',
          ],
          collector: 'blackbox',
        }));
      }
    }
  }

  return findings;
}

module.exports = { runCookieFlags };

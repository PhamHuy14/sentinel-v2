const { normalizeFinding } = require('../../models/finding');

const A04_REF = 'https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/';
const OTG_SESS_002 = 'https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes';

const SENSITIVE_COOKIE_RE = /(session|token|auth|jwt|sid|connect\.sid|phpsessid|jsessionid|aspsessionid|remember|refresh)/i;

function parseCookie(raw) {
  if (!raw) return null;

  if (typeof raw === 'object') {
    return {
      name: String(raw.name || ''),
      secure: !!raw.secure,
      httpOnly: !!(raw.httpOnly || raw.httponly),
      sameSite: String(raw.sameSite || raw.samesite || ''),
      domain: String(raw.domain || ''),
      path: String(raw.path || ''),
      raw: raw.raw || `${raw.name || 'cookie'}=<value>`,
    };
  }

  const text = String(raw);
  const parts = text.split(';').map((p) => p.trim()).filter(Boolean);
  if (!parts.length) return null;

  const [nameValue, ...attrs] = parts;
  const eqIdx = nameValue.indexOf('=');
  const name = eqIdx > -1 ? nameValue.slice(0, eqIdx) : nameValue;

  let secure = false;
  let httpOnly = false;
  let sameSite = '';
  let domain = '';
  let path = '';

  for (const a of attrs) {
    const lower = a.toLowerCase();
    if (lower === 'secure') secure = true;
    if (lower === 'httponly') httpOnly = true;
    if (lower.startsWith('samesite=')) sameSite = a.split('=')[1] || '';
    if (lower.startsWith('domain=')) domain = a.split('=')[1] || '';
    if (lower.startsWith('path=')) path = a.split('=')[1] || '';
  }

  return { name, secure, httpOnly, sameSite, domain, path, raw: text };
}

function runCookieSecurityA04(context) {
  const findings = [];
  try {
    if (context.protocol !== 'https:' || context.isLocalhost) return findings;

    const finalUrl = context.finalUrl || context.scannedUrl || '';
    const rawCookies = context.setCookies || [];
    const cookies = rawCookies.map(parseCookie).filter(Boolean);

    if (!cookies.length) return findings;

    const missingSecure = cookies.filter((c) => !c.secure).map((c) => c.name).slice(0, 5);
    if (missingSecure.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A04-COOKIE-001',
        owaspCategory: 'A04',
        title: 'Cookie trên HTTPS thiếu Secure flag',
        severity: 'medium',
        confidence: 'medium',
        target: finalUrl,
        location: 'Set-Cookie',
        evidence: missingSecure.map((n) => `${n}: thiếu Secure`),
        remediation: 'Thêm Secure cho mọi cookie khi ứng dụng chạy HTTPS.',
        references: [A04_REF, OTG_SESS_002],
        collector: 'blackbox'
      }));
    }

    const missingHttpOnly = cookies
      .filter((c) => SENSITIVE_COOKIE_RE.test(c.name) && !c.httpOnly)
      .map((c) => c.name)
      .slice(0, 5);
    if (missingHttpOnly.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A04-COOKIE-002',
        owaspCategory: 'A04',
        title: 'Cookie nhạy cảm thiếu HttpOnly',
        severity: 'medium',
        confidence: 'high',
        target: finalUrl,
        location: 'Set-Cookie',
        evidence: missingHttpOnly.map((n) => `${n}: thiếu HttpOnly`),
        remediation: 'Bật HttpOnly cho cookie phiên/xác thực để giảm nguy cơ đánh cắp qua XSS.',
        references: [A04_REF, OTG_SESS_002],
        collector: 'blackbox'
      }));
    }

    const missingSameSite = cookies
      .filter((c) => SENSITIVE_COOKIE_RE.test(c.name) && !String(c.sameSite).trim())
      .map((c) => c.name)
      .slice(0, 5);
    if (missingSameSite.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A04-COOKIE-003',
        owaspCategory: 'A04',
        title: 'Cookie nhạy cảm thiếu SameSite',
        severity: 'medium',
        confidence: 'high',
        target: finalUrl,
        location: 'Set-Cookie',
        evidence: missingSameSite.map((n) => `${n}: thiếu SameSite`),
        remediation: 'Đặt SameSite=Lax hoặc SameSite=Strict cho cookie nhạy cảm.',
        references: [A04_REF, OTG_SESS_002],
        collector: 'blackbox'
      }));
    }

    const noneWithoutSecure = cookies
      .filter((c) => String(c.sameSite).toLowerCase() === 'none' && !c.secure)
      .map((c) => c.name)
      .slice(0, 5);
    if (noneWithoutSecure.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A04-COOKIE-004',
        owaspCategory: 'A04',
        title: 'SameSite=None nhưng cookie không có Secure',
        severity: 'high',
        confidence: 'high',
        target: finalUrl,
        location: 'Set-Cookie',
        evidence: noneWithoutSecure.map((n) => `${n}: SameSite=None + thiếu Secure`),
        remediation: 'Bắt buộc thêm Secure khi dùng SameSite=None.',
        references: [A04_REF, OTG_SESS_002],
        collector: 'blackbox'
      }));
    }

    const wideScope = cookies
      .filter((c) => {
        if (!SENSITIVE_COOKIE_RE.test(c.name)) return false;
        const wideDomain = c.domain && c.domain.startsWith('.');
        const widePath = !c.path || c.path === '/';
        return wideDomain || widePath;
      })
      .map((c) => `${c.name}: domain=${c.domain || '(none)'}, path=${c.path || '/'}`)
      .slice(0, 5);
    if (wideScope.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A04-COOKIE-005',
        owaspCategory: 'A04',
        title: 'Cookie nhạy cảm có phạm vi domain/path quá rộng',
        severity: 'low',
        confidence: 'medium',
        target: finalUrl,
        location: 'Set-Cookie',
        evidence: wideScope,
        remediation: 'Thu hẹp domain/path cookie theo nguyên tắc tối thiểu cần thiết.',
        references: [A04_REF, OTG_SESS_002],
        collector: 'blackbox'
      }));
    }
  } catch {
    return findings;
  }

  return findings;
}

module.exports = { runCookieSecurityA04 };

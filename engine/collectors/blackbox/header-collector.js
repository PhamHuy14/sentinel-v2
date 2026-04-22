const SENSITIVE_COOKIE_RE = /(session|sess|auth|token|jwt|user|id)/i;

function parseCookie(rawCookie = '') {
  const parts = String(rawCookie).split(';').map((p) => p.trim()).filter(Boolean);
  const [first = '', ...attrs] = parts;
  const eq = first.indexOf('=');
  const cookieName = eq >= 0 ? first.slice(0, eq).trim() : first.trim();
  const cookieValue = eq >= 0 ? first.slice(eq + 1).trim() : '';

  const attrMap = {};
  for (const attr of attrs) {
    const idx = attr.indexOf('=');
    if (idx < 0) {
      attrMap[attr.toLowerCase()] = true;
      continue;
    }
    const key = attr.slice(0, idx).trim().toLowerCase();
    const value = attr.slice(idx + 1).trim();
    attrMap[key] = value;
  }

  return { cookieName, cookieValue, attrMap, rawCookie };
}

function parseExpiresTimestamp(attrMap) {
  const maxAgeRaw = attrMap['max-age'];
  if (maxAgeRaw !== undefined) {
    const maxAge = Number(maxAgeRaw);
    if (Number.isFinite(maxAge) && maxAge > 0) return Date.now() + (maxAge * 1000);
  }
  const expiresRaw = attrMap.expires;
  if (!expiresRaw) return null;
  const ts = Date.parse(expiresRaw);
  return Number.isFinite(ts) ? ts : null;
}

function makeIssue(cookieName, issue, rawValue, severity, issueText) {
  const findingIssue = {
    cookieName,
    issue,
    rawValue,
    severity,
    issueText,
    message: issueText,
    toString() {
      return this.issueText;
    },
  };
  return findingIssue;
}

function collectCookieIssues(setCookies = [], options = {}) {
  const host = String(options.host || '').toLowerCase();
  const isHttps = !!options.isHttps;
  const issues = [];

  for (const rawCookie of setCookies) {
    const { cookieName, attrMap } = parseCookie(rawCookie);
    if (!cookieName) continue;

    const lowerName = cookieName.toLowerCase();
    const isSensitive = SENSITIVE_COOKIE_RE.test(lowerName);
    const hasHttpOnly = !!attrMap.httponly;
    const hasSecure = !!attrMap.secure;
    const sameSiteRaw = String(attrMap.samesite || '').toLowerCase();
    const hasSameSite = !!sameSiteRaw;
    const domain = String(attrMap.domain || '').trim().toLowerCase();
    const path = String(attrMap.path || '').trim();
    const expiryTs = parseExpiresTimestamp(attrMap);

    if (!hasSecure) {
      const sev = (isSensitive && isHttps) ? 'high' : 'medium';
      issues.push(makeIssue(cookieName, 'missing-secure', rawCookie, sev, `${cookieName}: thiếu Secure`));
    }

    if (!hasHttpOnly) {
      const sev = isSensitive ? 'high' : 'medium';
      issues.push(makeIssue(cookieName, 'missing-httponly', rawCookie, sev, `${cookieName}: thiếu HttpOnly`));
    }

    if (!hasSameSite) {
      issues.push(makeIssue(cookieName, 'missing-samesite', rawCookie, 'medium', `${cookieName}: thiếu SameSite`));
    }

    if (sameSiteRaw === 'none' && !hasSecure) {
      issues.push(makeIssue(cookieName, 'samesite-none-without-secure', rawCookie, 'high', `${cookieName}: SameSite=None nhưng thiếu Secure`));
    }

    if (expiryTs && expiryTs - Date.now() > (365 * 24 * 60 * 60 * 1000)) {
      issues.push(makeIssue(cookieName, 'expires-too-far', rawCookie, 'low', `${cookieName}: thời gian sống cookie quá dài (> 1 năm)`));
    }

    if (domain) {
      const normalizedDomain = domain.startsWith('.') ? domain.slice(1) : domain;
      const broadDomain = domain.startsWith('.') || (host && normalizedDomain && normalizedDomain !== host && !host.endsWith(`.${normalizedDomain}`));
      if (broadDomain) {
        issues.push(makeIssue(cookieName, 'domain-too-broad', rawCookie, 'low', `${cookieName}: Domain cookie quá rộng (${domain})`));
      }
    }

    if (path === '/' && !hasHttpOnly) {
      issues.push(makeIssue(cookieName, 'wide-path-missing-httponly', rawCookie, 'medium', `${cookieName}: Path=/ quá rộng và thiếu HttpOnly`));
    } else if (path === '/') {
      issues.push(makeIssue(cookieName, 'wide-path', rawCookie, 'info', `${cookieName}: Path=/ phạm vi rộng`));
    }
  }

  return issues;
}

function collectServerInfo(headers) {
  const get = (k) => (headers?.get ? headers.get(k) : (headers?.[k] || headers?.[k.toLowerCase()] || '')) || '';
  return {
    server: get('server'),
    xPoweredBy: get('x-powered-by'),
    xGenerator: get('x-generator'),
    xAspNetVersion: get('x-aspnet-version'),
    xAspNetMvcVersion: get('x-aspnetmvc-version'),
  };
}

function collectCorsHeaders(headers) {
  const get = (k) => (headers?.get ? headers.get(k) : (headers?.[k] || headers?.[k.toLowerCase()] || '')) || '';
  return {
    allowOrigin: get('access-control-allow-origin'),
    allowCredentials: get('access-control-allow-credentials'),
    allowMethods: get('access-control-allow-methods'),
    allowHeaders: get('access-control-allow-headers'),
    exposeHeaders: get('access-control-expose-headers'),
    maxAge: get('access-control-max-age'),
    vary: get('vary'),
  };
}

function detectMixedContent(htmlText, pageUrl, maxBodyLength = 500 * 1024) {
  const url = String(pageUrl || '');
  if (!/^https:\/\//i.test(url)) return [];

  const html = String(htmlText || '').slice(0, maxBodyLength);
  const matches = html.match(/(?:src|href|action)=['"](http:\/\/[^'"\s>]+)['"]/gi) || [];
  return matches
    .map((m) => {
      const found = m.match(/['"](http:\/\/[^'"\s>]+)['"]/i);
      return found ? found[1] : null;
    })
    .filter(Boolean)
    .slice(0, 30);
}

function checkHstsStrength(hstsValue = '') {
  const raw = String(hstsValue || '');
  const maxAgeMatch = raw.match(/max-age\s*=\s*(\d+)/i);
  const maxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : 0;
  const includeSubDomains = /includesubdomains/i.test(raw);
  const preload = /preload/i.test(raw);
  return {
    maxAge,
    includeSubDomains,
    preload,
    isStrong: maxAge >= 31536000 && includeSubDomains,
  };
}

module.exports = {
  collectCookieIssues,
  collectServerInfo,
  collectCorsHeaders,
  detectMixedContent,
  checkHstsStrength,
};

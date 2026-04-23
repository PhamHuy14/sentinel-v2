// engine/rules/a02/a02-rules.test.js
// A02 – Security Misconfiguration
// Covers: cors-misconfig.js + missing-security-headers.js

import { describe, expect, it } from 'vitest';
import { runCorsMisconfig } from './cors-misconfig.js';
import { runMissingSecurityHeaders } from './missing-security-headers.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build Headers object from plain object (Node 20+ global Headers). */
function hdrs(obj = {}) {
  return new Headers(obj);
}

/** Minimal CORS context. */
function corsCtx(headersObj = {}, extra = {}) {
  return {
    headers: hdrs(headersObj),
    finalUrl: 'https://api.example.com/data',
    ...extra,
  };
}

/** Minimal security-headers context (HTTPS HTML page). */
function secCtx(headersObj = {}, extra = {}) {
  return {
    headers: hdrs(headersObj),
    finalUrl: 'https://example.com/',
    protocol: 'https:',
    contentType: 'text/html; charset=utf-8',
    isLocalhost: false,
    suppressInfo: true, // mặc định tắt low-info findings để test rõ ràng hơn
    ...extra,
  };
}

// ---------------------------------------------------------------------------
// 1. A02-CORS-001 – Wildcard origin (*)
// ---------------------------------------------------------------------------
describe('A02-CORS-001 – wildcard origin', () => {
  it('triggers khi Access-Control-Allow-Origin là "*"', () => {
    const ids = runCorsMisconfig(corsCtx({ 'access-control-allow-origin': '*' })).map(f => f.ruleId);
    expect(ids).toContain('A02-CORS-001');
  });

  it('không trigger khi không có CORS header nào', () => {
    const findings = runCorsMisconfig(corsCtx({}));
    expect(findings.length).toBe(0);
  });

  it('không trigger khi origin là domain cụ thể', () => {
    const ids = runCorsMisconfig(corsCtx({ 'access-control-allow-origin': 'https://trusted.example.com' })).map(f => f.ruleId);
    expect(ids).not.toContain('A02-CORS-001');
  });

  it('finding có severity "medium" và owaspCategory "A02"', () => {
    const f = runCorsMisconfig(corsCtx({ 'access-control-allow-origin': '*' })).find(x => x.ruleId === 'A02-CORS-001');
    expect(f).toBeDefined();
    expect(f.severity).toBe('medium');
    expect(f.owaspCategory).toBe('A02');
  });
});

// ---------------------------------------------------------------------------
// 2. A02-CORS-003 – Wildcard + Allow-Credentials (cấu hình nguy hiểm nhất)
// ---------------------------------------------------------------------------
describe('A02-CORS-003 – wildcard origin kết hợp Allow-Credentials', () => {
  it('triggers khi cả * lẫn Allow-Credentials: true cùng lúc', () => {
    const ids = runCorsMisconfig(corsCtx({
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true',
    })).map(f => f.ruleId);
    expect(ids).toContain('A02-CORS-003');
  });

  it('không trigger khi chỉ có wildcard không có credentials', () => {
    const ids = runCorsMisconfig(corsCtx({ 'access-control-allow-origin': '*' })).map(f => f.ruleId);
    expect(ids).not.toContain('A02-CORS-003');
  });

  it('finding có severity "high"', () => {
    const f = runCorsMisconfig(corsCtx({
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true',
    })).find(x => x.ruleId === 'A02-CORS-003');
    expect(f.severity).toBe('high');
  });
});

// ---------------------------------------------------------------------------
// 3. A02-CORS-002 – Origin reflection (server echo nguyên xi Origin)
// ---------------------------------------------------------------------------
describe('A02-CORS-002 – origin reflection', () => {
  it('triggers khi server echo nguyên xi requestOrigin', () => {
    const origin = 'https://attacker.example.com';
    const ids = runCorsMisconfig({
      headers: hdrs({ 'access-control-allow-origin': origin }),
      finalUrl: 'https://api.example.com/',
      requestOrigin: origin,
    }).map(f => f.ruleId);
    expect(ids).toContain('A02-CORS-002');
  });

  it('không trigger khi allowOrigin khác requestOrigin', () => {
    const ids = runCorsMisconfig({
      headers: hdrs({ 'access-control-allow-origin': 'https://trusted.example.com' }),
      finalUrl: 'https://api.example.com/',
      requestOrigin: 'https://attacker.example.com',
    }).map(f => f.ruleId);
    expect(ids).not.toContain('A02-CORS-002');
  });
});

// ---------------------------------------------------------------------------
// 4. A02-CORS-004 – Methods nguy hiểm (PUT/DELETE/PATCH)
// ---------------------------------------------------------------------------
describe('A02-CORS-004 – dangerous CORS methods', () => {
  it('triggers khi Allow-Methods chứa "PUT"', () => {
    const ids = runCorsMisconfig(corsCtx({
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET, POST, PUT',
    })).map(f => f.ruleId);
    expect(ids).toContain('A02-CORS-004');
  });

  it('triggers khi Allow-Methods chứa "DELETE"', () => {
    const ids = runCorsMisconfig(corsCtx({
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET, DELETE',
    })).map(f => f.ruleId);
    expect(ids).toContain('A02-CORS-004');
  });

  it('không trigger khi chỉ có GET, POST', () => {
    const ids = runCorsMisconfig(corsCtx({
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET, POST',
    })).map(f => f.ruleId);
    expect(ids).not.toContain('A02-CORS-004');
  });
});

// ---------------------------------------------------------------------------
// 5. A02-CORS-006 – Thiếu Vary: Origin khi dynamic origin
// ---------------------------------------------------------------------------
describe('A02-CORS-006 – thiếu Vary: Origin', () => {
  it('triggers khi origin dynamic nhưng không có Vary: Origin', () => {
    const origin = 'https://trusted.example.com';
    const ids = runCorsMisconfig({
      headers: hdrs({ 'access-control-allow-origin': origin }),
      finalUrl: 'https://api.example.com/',
      requestOrigin: 'https://other.example.com', // khác → không trigger CORS-002
    }).map(f => f.ruleId);
    expect(ids).toContain('A02-CORS-006');
  });

  it('không trigger khi có Vary: Origin', () => {
    const origin = 'https://trusted.example.com';
    const ids = runCorsMisconfig({
      headers: hdrs({ 'access-control-allow-origin': origin, vary: 'Origin' }),
      finalUrl: 'https://api.example.com/',
    }).map(f => f.ruleId);
    expect(ids).not.toContain('A02-CORS-006');
  });
});

// ---------------------------------------------------------------------------
// 6. A02-HDR-001 – Thiếu X-Content-Type-Options
// ---------------------------------------------------------------------------
describe('A02-HDR-001 – thiếu X-Content-Type-Options', () => {
  it('triggers khi không có X-Content-Type-Options', () => {
    const ids = runMissingSecurityHeaders(secCtx({})).map(f => f.ruleId);
    expect(ids).toContain('A02-HDR-001');
  });

  it('không trigger khi header có giá trị "nosniff"', () => {
    const ids = runMissingSecurityHeaders(secCtx({ 'x-content-type-options': 'nosniff' })).map(f => f.ruleId);
    expect(ids).not.toContain('A02-HDR-001');
  });
});

// ---------------------------------------------------------------------------
// 7. A02-HDR-002 – Thiếu HSTS trên HTTPS
// ---------------------------------------------------------------------------
describe('A02-HDR-002 – thiếu HSTS trên HTTPS', () => {
  it('triggers khi HTTPS response không có Strict-Transport-Security', () => {
    const ids = runMissingSecurityHeaders(secCtx({ 'x-content-type-options': 'nosniff' })).map(f => f.ruleId);
    expect(ids).toContain('A02-HDR-002');
  });

  it('không trigger khi HSTS header đầy đủ', () => {
    const ids = runMissingSecurityHeaders(secCtx({
      'x-content-type-options': 'nosniff',
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
    })).map(f => f.ruleId);
    expect(ids).not.toContain('A02-HDR-002');
  });

  it('không trigger cho HTTP (HSTS không áp dụng)', () => {
    const ids = runMissingSecurityHeaders(secCtx({}, { protocol: 'http:' })).map(f => f.ruleId);
    expect(ids).not.toContain('A02-HDR-002');
  });

  it('không trigger cho localhost kể cả khi thiếu HSTS', () => {
    const ids = runMissingSecurityHeaders(secCtx({}, { isLocalhost: true })).map(f => f.ruleId);
    expect(ids).not.toContain('A02-HDR-002');
  });
});

// ---------------------------------------------------------------------------
// 8. A02-HDR-004 – HSTS max-age quá ngắn
// ---------------------------------------------------------------------------
describe('A02-HDR-004 – HSTS max-age quá ngắn', () => {
  it('triggers khi max-age chỉ 3600 (< 31536000)', () => {
    const ids = runMissingSecurityHeaders(secCtx({
      'x-content-type-options': 'nosniff',
      'strict-transport-security': 'max-age=3600',
    })).map(f => f.ruleId);
    expect(ids).toContain('A02-HDR-004');
  });

  it('không trigger khi max-age = 31536000 (đúng 1 năm)', () => {
    const ids = runMissingSecurityHeaders(secCtx({
      'x-content-type-options': 'nosniff',
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
    })).map(f => f.ruleId);
    expect(ids).not.toContain('A02-HDR-004');
  });
});

// ---------------------------------------------------------------------------
// 9. A02-HDR-003 – Thiếu CSP trên HTML response
// ---------------------------------------------------------------------------
describe('A02-HDR-003 – thiếu Content-Security-Policy', () => {
  it('triggers khi HTML response không có CSP', () => {
    const ids = runMissingSecurityHeaders(secCtx({ 'x-content-type-options': 'nosniff' })).map(f => f.ruleId);
    expect(ids).toContain('A02-HDR-003');
  });

  it('không trigger khi CSP header tồn tại', () => {
    const ids = runMissingSecurityHeaders(secCtx({
      'x-content-type-options': 'nosniff',
      'content-security-policy': "default-src 'self'",
    })).map(f => f.ruleId);
    expect(ids).not.toContain('A02-HDR-003');
  });

  it('không trigger cho non-HTML content type', () => {
    const ids = runMissingSecurityHeaders(secCtx(
      { 'x-content-type-options': 'nosniff' },
      { contentType: 'application/json' }
    )).map(f => f.ruleId);
    expect(ids).not.toContain('A02-HDR-003');
  });
});

// ---------------------------------------------------------------------------
// 10. A02-HDR-006 – Thiếu bảo vệ chống Clickjacking
// ---------------------------------------------------------------------------
describe('A02-HDR-006 – thiếu bảo vệ chống Clickjacking', () => {
  it('triggers khi không có X-Frame-Options và không có frame-ancestors CSP', () => {
    const ids = runMissingSecurityHeaders(secCtx({ 'x-content-type-options': 'nosniff' })).map(f => f.ruleId);
    expect(ids).toContain('A02-HDR-006');
  });

  it('không trigger khi có X-Frame-Options: DENY', () => {
    const ids = runMissingSecurityHeaders(secCtx({
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
    })).map(f => f.ruleId);
    expect(ids).not.toContain('A02-HDR-006');
  });

  it("không trigger khi CSP có frame-ancestors 'none'", () => {
    const ids = runMissingSecurityHeaders(secCtx({
      'x-content-type-options': 'nosniff',
      "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    })).map(f => f.ruleId);
    expect(ids).not.toContain('A02-HDR-006');
  });
});

// ---------------------------------------------------------------------------
// 11. Integration – mọi finding đều có owaspCategory "A02"
// ---------------------------------------------------------------------------
describe('A02 integration', () => {
  it('mọi finding của runMissingSecurityHeaders đều có owaspCategory "A02"', () => {
    const findings = runMissingSecurityHeaders(secCtx({}, { suppressInfo: false }));
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) expect(f.owaspCategory).toBe('A02');
  });

  it('mọi finding của runCorsMisconfig đều có owaspCategory "A02"', () => {
    const findings = runCorsMisconfig(corsCtx({
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true',
      'access-control-allow-methods': 'GET, POST, DELETE',
    }));
    for (const f of findings) expect(f.owaspCategory).toBe('A02');
  });

  it('response hoàn toàn hợp lệ không sinh finding CORS', () => {
    const findings = runCorsMisconfig(corsCtx({}));
    expect(findings.length).toBe(0);
  });
});

// engine/rules/a04/a04-rules.test.js
// A04 – Cryptographic Failures: unit tests for all sub-rule modules.
// Uses vitest + ESM imports (same pattern as scan-engine.test.js).

import { describe, expect, it } from 'vitest';
import { runTransportSecurityA04 } from './transport-security.js';
import { runHstsAndWebsocketA04 } from './hsts-websocket.js';
import { runCookieSecurityA04 } from './cookie-security.js';
import { runSensitiveDataA04, luhnValid } from './sensitive-data.js';
import { runA04Rules } from './index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal HTTPS context with no issues. */
function httpsCtx(overrides = {}) {
  return {
    protocol: 'https:',
    isLocalhost: false,
    finalUrl: 'https://example.com/',
    scannedUrl: 'https://example.com/',
    text: '',
    contentType: 'text/html',
    responseHeaders: { 'strict-transport-security': 'max-age=31536000' },
    requestHeaders: {},
    setCookies: [],
    queryString: '',
    ...overrides,
  };
}

/** Minimal HTTP context. */
function httpCtx(overrides = {}) {
  return {
    protocol: 'http:',
    isLocalhost: false,
    finalUrl: 'http://example.com/',
    scannedUrl: 'http://example.com/',
    text: '',
    contentType: 'text/html',
    responseHeaders: {},
    requestHeaders: {},
    setCookies: [],
    queryString: '',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// 1. HTTP → trigger A04-TRANSPORT-001
// ---------------------------------------------------------------------------
describe('A04 Transport Security – HTTP plain-text', () => {
  it('triggers A04-TRANSPORT-001 when protocol is http: and not localhost', () => {
    const findings = runTransportSecurityA04(httpCtx());
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('A04-TRANSPORT-001');
  });

  it('does NOT trigger A04-TRANSPORT-001 for localhost http:', () => {
    const findings = runTransportSecurityA04(httpCtx({ isLocalhost: true }));
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).not.toContain('A04-TRANSPORT-001');
  });

  it('finding has severity "high" and category "A04"', () => {
    const findings = runTransportSecurityA04(httpCtx());
    const f = findings.find((x) => x.ruleId === 'A04-TRANSPORT-001');
    expect(f).toBeDefined();
    expect(f.severity).toBe('high');
    expect(f.owaspCategory).toBe('A04');
  });

  it('does NOT trigger A04-TRANSPORT-001 when already on HTTPS', () => {
    const findings = runTransportSecurityA04(httpsCtx());
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).not.toContain('A04-TRANSPORT-001');
  });
});

// ---------------------------------------------------------------------------
// 2. HTTPS missing HSTS → trigger A04-HSTS-001
// ---------------------------------------------------------------------------
describe('A04 HSTS – missing Strict-Transport-Security', () => {
  it('triggers A04-HSTS-001 when HTTPS response has no HSTS header', () => {
    const ctx = httpsCtx({ responseHeaders: {} }); // no STS header
    const findings = runHstsAndWebsocketA04(ctx);
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('A04-HSTS-001');
  });

  it('does NOT trigger A04-HSTS-001 when HSTS header is present', () => {
    const findings = runHstsAndWebsocketA04(httpsCtx());
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).not.toContain('A04-HSTS-001');
  });

  it('does NOT trigger A04-HSTS-001 for plain HTTP (HSTS is irrelevant)', () => {
    const findings = runHstsAndWebsocketA04(httpCtx());
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).not.toContain('A04-HSTS-001');
  });

  it('does NOT trigger A04-HSTS-001 for localhost even without HSTS', () => {
    const ctx = httpsCtx({ isLocalhost: true, responseHeaders: {} });
    const findings = runHstsAndWebsocketA04(ctx);
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).not.toContain('A04-HSTS-001');
  });
});

// ---------------------------------------------------------------------------
// 3. Mixed content in HTTPS HTML → trigger A04-TRANSPORT-003
// ---------------------------------------------------------------------------
describe('A04 Transport Security – mixed content on HTTPS page', () => {
  it('triggers A04-TRANSPORT-003 when HTTPS HTML loads an http:// image', () => {
    const ctx = httpsCtx({
      text: '<html><img src="http://cdn.example.com/logo.png"></html>',
    });
    const findings = runTransportSecurityA04(ctx);
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('A04-TRANSPORT-003');
  });

  it('captures the insecure URL in evidence', () => {
    const ctx = httpsCtx({
      text: '<html><script src="http://cdn.example.com/lib.js"></script></html>',
    });
    const findings = runTransportSecurityA04(ctx);
    const f = findings.find((x) => x.ruleId === 'A04-TRANSPORT-003');
    expect(f).toBeDefined();
    expect(f.evidence.some((e) => e.includes('http://'))).toBe(true);
  });

  it('does NOT trigger A04-TRANSPORT-003 when all resources are HTTPS', () => {
    const ctx = httpsCtx({
      text: '<html><img src="https://cdn.example.com/logo.png"></html>',
    });
    const findings = runTransportSecurityA04(ctx);
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).not.toContain('A04-TRANSPORT-003');
  });
});

// ---------------------------------------------------------------------------
// 4. Sensitive cookie missing Secure / HttpOnly / SameSite
// ---------------------------------------------------------------------------
describe('A04 Cookie Security – sensitive cookie attribute checks', () => {
  it('triggers A04-COOKIE-001 (missing Secure) for any cookie on HTTPS', () => {
    const ctx = httpsCtx({
      setCookies: ['sessionid=abc123; Path=/; HttpOnly'],
    });
    const findings = runCookieSecurityA04(ctx);
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('A04-COOKIE-001');
  });

  it('triggers A04-COOKIE-002 (missing HttpOnly) for a session cookie', () => {
    const ctx = httpsCtx({
      setCookies: ['session=abc123; Path=/; Secure'],
    });
    const findings = runCookieSecurityA04(ctx);
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('A04-COOKIE-002');
  });

  it('triggers A04-COOKIE-003 (missing SameSite) for a session cookie', () => {
    const ctx = httpsCtx({
      setCookies: ['session=abc123; Path=/; Secure; HttpOnly'],
    });
    const findings = runCookieSecurityA04(ctx);
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('A04-COOKIE-003');
  });

  it('no cookie findings when all attributes are correctly set', () => {
    const ctx = httpsCtx({
      setCookies: ['session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict'],
    });
    const findings = runCookieSecurityA04(ctx);
    // None of the security rules should fire for a correctly configured cookie
    const securityRuleIds = ['A04-COOKIE-001', 'A04-COOKIE-002', 'A04-COOKIE-003', 'A04-COOKIE-004'];
    const triggered = findings.map((f) => f.ruleId).filter((id) => securityRuleIds.includes(id));
    expect(triggered.length).toBe(0);
  });

  it('does NOT check cookies on HTTP (function guards on https: protocol)', () => {
    const ctx = httpCtx({
      setCookies: ['session=abc123; Path=/'],
    });
    const findings = runCookieSecurityA04(ctx);
    expect(findings.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// 5. 16-digit invalid-Luhn number must NOT be flagged as card leak
// ---------------------------------------------------------------------------
describe('A04 Sensitive Data – Luhn validation gate', () => {
  it('luhnValid returns false for a 16-digit string that fails the Luhn check', () => {
    // 1234567890123456 → digit sum mod 10 ≠ 0
    expect(luhnValid('1234567890123456')).toBe(false);
  });

  it('luhnValid returns true for a known-valid Visa test PAN', () => {
    // Standard Visa test card – passes Luhn
    expect(luhnValid('4532015112830366')).toBe(true);
  });

  it('does NOT trigger A04-SENS-001 when body contains invalid-Luhn 16-digit string', () => {
    const ctx = httpsCtx({
      text: 'card: 1234567890123456',
    });
    const findings = runSensitiveDataA04(ctx);
    const f = findings.find((x) => x.ruleId === 'A04-SENS-001');
    // Either no finding at all, or finding evidence must NOT mention card-like string
    if (f) {
      const evidenceStr = f.evidence.join(' ');
      expect(evidenceStr).not.toMatch(/chuỗi giống số thẻ/);
    } else {
      expect(f).toBeUndefined();
    }
  });

  it('DOES trigger A04-SENS-001 card evidence when body contains a valid-Luhn PAN', () => {
    const ctx = httpsCtx({
      text: 'Your card: 4532015112830366 was charged.',
    });
    const findings = runSensitiveDataA04(ctx);
    const f = findings.find((x) => x.ruleId === 'A04-SENS-001');
    expect(f).toBeDefined();
    const evidenceStr = f.evidence.join(' ');
    expect(evidenceStr).toMatch(/chuỗi giống số thẻ/);
  });
});

// ---------------------------------------------------------------------------
// 6. ws:// in HTTPS page → trigger A04-WS-001
// ---------------------------------------------------------------------------
describe('A04 HSTS/WebSocket – insecure WebSocket on HTTPS page', () => {
  it('triggers A04-WS-001 when HTTPS HTML contains ws:// connection', () => {
    const ctx = httpsCtx({
      text: '<html><script>var ws = new WebSocket("ws://chat.example.com/socket");</script></html>',
      responseHeaders: { 'strict-transport-security': 'max-age=31536000' },
    });
    const findings = runHstsAndWebsocketA04(ctx);
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('A04-WS-001');
  });

  it('captures the ws:// URL in finding evidence', () => {
    const wsUrl = 'ws://chat.example.com/socket';
    const ctx = httpsCtx({
      text: `<script>new WebSocket("${wsUrl}");</script>`,
      responseHeaders: { 'strict-transport-security': 'max-age=31536000' },
    });
    const findings = runHstsAndWebsocketA04(ctx);
    const f = findings.find((x) => x.ruleId === 'A04-WS-001');
    expect(f).toBeDefined();
    expect(f.evidence.some((e) => e.includes('ws://'))).toBe(true);
  });

  it('does NOT trigger A04-WS-001 when page uses wss:// only', () => {
    const ctx = httpsCtx({
      text: '<script>new WebSocket("wss://chat.example.com/socket");</script>',
      responseHeaders: { 'strict-transport-security': 'max-age=31536000' },
    });
    const findings = runHstsAndWebsocketA04(ctx);
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).not.toContain('A04-WS-001');
  });

  it('does NOT trigger A04-WS-001 on HTTP pages (guard: isHttps check)', () => {
    const ctx = httpCtx({
      text: '<script>new WebSocket("ws://chat.example.com/socket");</script>',
    });
    const findings = runHstsAndWebsocketA04(ctx);
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).not.toContain('A04-WS-001');
  });
});

// ---------------------------------------------------------------------------
// 7. runA04Rules integration – aggregate runner does not break other categories
// ---------------------------------------------------------------------------
describe('A04 runA04Rules – integration smoke test', () => {
  it('returns an array', () => {
    const findings = runA04Rules(httpsCtx());
    expect(Array.isArray(findings)).toBe(true);
  });

  it('all returned findings have owaspCategory "A04"', () => {
    const ctx = httpCtx(); // HTTP triggers transport finding
    const findings = runA04Rules(ctx);
    for (const f of findings) {
      expect(f.owaspCategory).toBe('A04');
    }
  });

  it('returns empty array for a fully-compliant clean context', () => {
    const ctx = httpsCtx({
      responseHeaders: { 'strict-transport-security': 'max-age=63072000; includeSubDomains; preload' },
      text: '<html><body>Hello</body></html>',
      setCookies: [],
    });
    const findings = runA04Rules(ctx);
    expect(findings.length).toBe(0);
  });

  it('returns multiple findings for a context with multiple issues', () => {
    const ctx = httpsCtx({
      responseHeaders: {}, // no HSTS
      text: '<html><img src="http://cdn.example.com/x.png"><script>new WebSocket("ws://api.example.com");</script></html>',
      setCookies: ['session=abc; Path=/'], // missing Secure, HttpOnly, SameSite
    });
    const findings = runA04Rules(ctx);
    expect(findings.length).toBeGreaterThan(2);
  });
});

import { describe, expect, it } from 'vitest';
import {
    runAllA10Rules,
    runExceptionLeakage,
    runMalformedInput,
    runSsrfHeuristic,
    runSsrfSource,
} from './index.js';

describe('A10 SSRF and Exceptional Conditions', () => {
  it('detects cloud metadata patterns in response (A10-SSRF-001)', () => {
    const findings = runSsrfHeuristic({
      text: '{"AccessKeyId":"AKIA1234567890ABCD12"}',
      finalUrl: 'https://example.com/fetch',
      responseHeaders: {},
    });
    expect(findings.some(f => f.ruleId === 'A10-SSRF-001')).toBe(true);
  });

  it('flags SSRF attack surface in URL parameter (A10-SSRF-003)', () => {
    const findings = runSsrfHeuristic({
      text: '',
      finalUrl: 'https://example.com/proxy?url=http://169.254.169.254/latest/meta-data/',
      responseHeaders: {},
    });
    expect(findings.some(f => f.ruleId === 'A10-SSRF-003')).toBe(true);
  });

  it('detects redirect to internal IP (A10-SSRF-004)', () => {
    const findings = runSsrfHeuristic({
      text: '',
      finalUrl: 'https://example.com/redirect',
      responseHeaders: { location: 'http://127.0.0.1/admin' },
    });
    expect(findings.some(f => f.ruleId === 'A10-SSRF-004')).toBe(true);
  });

  it('detects SSRF in source code with user-controlled fetch (A10-SSRF-SRC-001)', () => {
    const findings = runSsrfSource({
      codeFiles: [{ path: 'server.js', content: 'fetch(req.query.url);' }],
    });
    expect(findings.some(f => f.ruleId === 'A10-SSRF-SRC-001')).toBe(true);
  });

  it('detects weak URL validation (A10-SSRF-SRC-002)', () => {
    const findings = runSsrfSource({
      codeFiles: [{ path: 'server.js', content: 'if (url.startsWith("http://")) { return url; }' }],
    });
    expect(findings.some(f => f.ruleId === 'A10-SSRF-SRC-002')).toBe(true);
  });

  it('detects dangerous URL schemes (A10-SSRF-SRC-003)', () => {
    const findings = runSsrfSource({
      codeFiles: [{ path: 'server.js', content: 'axios("file://etc/passwd");' }],
    });
    expect(findings.some(f => f.ruleId === 'A10-SSRF-SRC-003')).toBe(true);
  });

  it('detects stack trace leakage (A10-EX-002)', () => {
    const findings = runExceptionLeakage({
      text: 'Traceback (most recent call last):\n  File "app.py", line 12, in main',
      status: 500,
      finalUrl: 'https://example.com',
    });
    expect(findings.some(f => f.ruleId === 'A10-EX-002')).toBe(true);
  });

  it('detects missing path probe verbose errors (A10-EX-001)', () => {
    const findings = runExceptionLeakage({
      missingPathProbe: { hasVerboseErrors: true, url: 'https://example.com/404' },
      text: 'stack trace',
      status: 404,
      finalUrl: 'https://example.com/404',
    });
    expect(findings.some(f => f.ruleId === 'A10-EX-001')).toBe(true);
  });

  it('flags malformed input with server error (A10-MAL-001)', () => {
    const findings = runMalformedInput({ status: 500, finalUrl: 'https://example.com/api' });
    expect(findings.some(f => f.ruleId === 'A10-MAL-001')).toBe(true);
  });

  it('runAllA10Rules aggregates findings', () => {
    const findings = runAllA10Rules({
      text: '{"AccessKeyId":"AKIA1234567890ABCD12"}',
      finalUrl: 'https://example.com/fetch?url=http://169.254.169.254/',
      responseHeaders: { location: 'http://127.0.0.1/admin' },
      status: 500,
      codeFiles: [{ path: 'server.js', content: 'fetch(req.query.url);' }],
    });
    expect(findings.length).toBeGreaterThan(0);
  });
});

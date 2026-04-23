// engine/rules/a01/a01-rules.test.js
// A01 – Broken Access Control
// Covers: auth-bypass, access-control-enhanced (JWT, PathTraversal, SensitiveEndpoint, MassAssignment), runAllA01Rules

import { describe, expect, it } from 'vitest';
import {
  runAllA01Rules,
  runAuthBypassHeuristic,
  runJwtWeakness,
  runPathTraversalHeuristic,
  runSensitiveEndpointExposure,
  runMassAssignmentHeuristic,
} from './index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal clean context (HTTPS, not localhost). */
function baseCtx(overrides = {}) {
  return {
    protocol: 'https:',
    isLocalhost: false,
    finalUrl: 'https://example.com/',
    origin: 'https://example.com',
    text: '',
    requestBody: '',
    requestHeaders: {},
    responseHeaders: {},
    method: 'GET',
    statusCode: 200,
    surfaceStatus: {},
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// 1. Auth Bypass – URL query parameters
// ---------------------------------------------------------------------------
describe('A01-AUTHBYP-002 – URL bypass params', () => {
  it('triggers khi URL chứa "?authenticated=true"', () => {
    const ctx = baseCtx({ finalUrl: 'https://example.com/admin?authenticated=true' });
    const ids = runAuthBypassHeuristic(ctx).map(f => f.ruleId);
    expect(ids).toContain('A01-AUTHBYP-002');
  });

  it('triggers khi URL chứa "?skip_auth=1"', () => {
    const ctx = baseCtx({ finalUrl: 'https://example.com/dashboard?skip_auth=1' });
    const ids = runAuthBypassHeuristic(ctx).map(f => f.ruleId);
    expect(ids).toContain('A01-AUTHBYP-002');
  });

  it('không trigger với URL bình thường', () => {
    const ctx = baseCtx({ finalUrl: 'https://example.com/home?page=1' });
    const ids = runAuthBypassHeuristic(ctx).map(f => f.ruleId);
    expect(ids).not.toContain('A01-AUTHBYP-002');
  });
});

// ---------------------------------------------------------------------------
// 2. Auth Bypass – Cookie manipulation
// ---------------------------------------------------------------------------
describe('A01-AUTHBYP-003 – cookie bypass', () => {
  it('triggers khi cookie chứa "is_admin=true"', () => {
    const ctx = baseCtx({ requestHeaders: { Cookie: 'is_admin=true; session=abc' } });
    const ids = runAuthBypassHeuristic(ctx).map(f => f.ruleId);
    expect(ids).toContain('A01-AUTHBYP-003');
  });

  it('triggers khi cookie chứa "role=admin"', () => {
    const ctx = baseCtx({ requestHeaders: { Cookie: 'role=admin' } });
    const ids = runAuthBypassHeuristic(ctx).map(f => f.ruleId);
    expect(ids).toContain('A01-AUTHBYP-003');
  });

  it('không trigger với cookie hợp lệ bình thường', () => {
    const ctx = baseCtx({ requestHeaders: { Cookie: 'theme=dark; lang=vi' } });
    const ids = runAuthBypassHeuristic(ctx).map(f => f.ruleId);
    expect(ids).not.toContain('A01-AUTHBYP-003');
  });

  it('finding có severity "high" khi không phải localhost', () => {
    const ctx = baseCtx({ requestHeaders: { Cookie: 'is_admin=true' } });
    const f = runAuthBypassHeuristic(ctx).find(x => x.ruleId === 'A01-AUTHBYP-003');
    expect(f.severity).toBe('high');
  });
});

// ---------------------------------------------------------------------------
// 3. Auth Bypass – Bypass attempt + success signal → A01-AUTHBYP-001
// ---------------------------------------------------------------------------
describe('A01-AUTHBYP-001 – bypass thành công (critical)', () => {
  it('triggers A01-AUTHBYP-001 khi có URL bypass và response có dấu hiệu xác thực thành công', () => {
    const ctx = baseCtx({
      finalUrl: 'https://example.com/admin?authenticated=true',
      text: 'Welcome admin! You are now authenticated.',
      statusCode: 200,
    });
    const ids = runAuthBypassHeuristic(ctx).map(f => f.ruleId);
    expect(ids).toContain('A01-AUTHBYP-001');
  });

  it('finding A01-AUTHBYP-001 có severity "critical" trên non-localhost', () => {
    const ctx = baseCtx({
      finalUrl: 'https://example.com/?skip_auth=1',
      text: '"authenticated": true',
      statusCode: 200,
    });
    const f = runAuthBypassHeuristic(ctx).find(x => x.ruleId === 'A01-AUTHBYP-001');
    expect(f).toBeDefined();
    expect(f.severity).toBe('critical');
  });

  it('không trigger A01-AUTHBYP-001 khi không có success signal dù URL đáng ngờ', () => {
    const ctx = baseCtx({
      finalUrl: 'https://example.com/admin?authenticated=true',
      text: 'Access denied. Please login.',
      statusCode: 403,
    });
    const ids = runAuthBypassHeuristic(ctx).map(f => f.ruleId);
    expect(ids).not.toContain('A01-AUTHBYP-001');
  });
});

// ---------------------------------------------------------------------------
// 4. JWT Weakness – alg:none
// ---------------------------------------------------------------------------
describe('A01-JWT-002 – JWT algorithm "none"', () => {
  it('triggers khi Bearer token có alg:none trong header', () => {
    // Build a fake JWT với header: {"alg":"none","typ":"JWT"}
    const headerB64 = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify({ sub: '1' })).toString('base64url');
    const fakeToken = `${headerB64}.${payloadB64}.`;
    const ctx = baseCtx({ requestHeaders: { Authorization: `Bearer ${fakeToken}` } });
    const ids = runJwtWeakness(ctx).map(f => f.ruleId);
    expect(ids).toContain('A01-JWT-002');
  });

  it('finding A01-JWT-002 có severity "critical"', () => {
    const headerB64 = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify({ sub: '1' })).toString('base64url');
    const fakeToken = `${headerB64}.${payloadB64}.`;
    const ctx = baseCtx({ requestHeaders: { Authorization: `Bearer ${fakeToken}` } });
    const f = runJwtWeakness(ctx).find(x => x.ruleId === 'A01-JWT-002');
    expect(f.severity).toBe('critical');
  });
});

// ---------------------------------------------------------------------------
// 5. JWT Weakness – HS256 (weak symmetric algorithm)
// ---------------------------------------------------------------------------
describe('A01-JWT-003 – JWT symmetric algorithm HS256', () => {
  it('triggers khi Bearer token dùng HS256', () => {
    const headerB64 = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify({ sub: '1' })).toString('base64url');
    const sigB64 = Buffer.from('fakesig').toString('base64url');
    const fakeToken = `${headerB64}.${payloadB64}.${sigB64}`;
    const ctx = baseCtx({ requestHeaders: { Authorization: `Bearer ${fakeToken}` } });
    const ids = runJwtWeakness(ctx).map(f => f.ruleId);
    expect(ids).toContain('A01-JWT-003');
  });
});

// ---------------------------------------------------------------------------
// 6. JWT in response body – A01-JWT-001
// ---------------------------------------------------------------------------
describe('A01-JWT-001 – JWT trong response body', () => {
  it('triggers khi response body chứa mẫu JWT token', () => {
    // Tạo chuỗi giống JWT (3 phần, dài > 10 ký tự mỗi phần)
    const fakeJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const ctx = baseCtx({ text: `{"token":"${fakeJwt}"}`, requestHeaders: {} });
    const ids = runJwtWeakness(ctx).map(f => f.ruleId);
    expect(ids).toContain('A01-JWT-001');
  });

  it('không trigger khi không có JWT pattern trong body', () => {
    const ctx = baseCtx({ text: '{"status":"ok"}' });
    const ids = runJwtWeakness(ctx).map(f => f.ruleId);
    expect(ids).not.toContain('A01-JWT-001');
  });
});

// ---------------------------------------------------------------------------
// 7. Path Traversal – dấu hiệu thành công trong response
// ---------------------------------------------------------------------------
describe('A01-PATH-001 – path traversal thành công', () => {
  it('triggers khi response chứa /etc/passwd content', () => {
    const ctx = baseCtx({ text: 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin' });
    const ids = runPathTraversalHeuristic(ctx).map(f => f.ruleId);
    expect(ids).toContain('A01-PATH-001');
  });

  it('triggers khi response chứa Windows boot.ini marker', () => {
    const ctx = baseCtx({ text: '[boot loader]\ntimeout=30\ndefault=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS' });
    const ids = runPathTraversalHeuristic(ctx).map(f => f.ruleId);
    expect(ids).toContain('A01-PATH-001');
  });

  it('finding A01-PATH-001 có severity "critical"', () => {
    const ctx = baseCtx({ text: 'root:x:0:0:root:/root:/bin/bash' });
    const f = runPathTraversalHeuristic(ctx).find(x => x.ruleId === 'A01-PATH-001');
    expect(f.severity).toBe('critical');
  });

  it('không trigger với response HTML bình thường', () => {
    const ctx = baseCtx({ text: '<html><body>Hello World</body></html>' });
    const ids = runPathTraversalHeuristic(ctx).map(f => f.ruleId);
    expect(ids).not.toContain('A01-PATH-001');
  });
});

// ---------------------------------------------------------------------------
// 8. Sensitive Endpoint Exposure
// ---------------------------------------------------------------------------
describe('A01-EXPOSED-001 – sensitive endpoint trả về 200', () => {
  it('triggers khi /admin trả về 200 không có redirect to login', () => {
    const ctx = baseCtx({
      surfaceStatus: { '/admin': { status: 200, redirectedToLogin: false } },
    });
    const ids = runSensitiveEndpointExposure(ctx).map(f => f.ruleId);
    expect(ids).toContain('A01-EXPOSED-001');
  });

  it('triggers khi /.git trả về 200 (critical endpoint)', () => {
    const ctx = baseCtx({
      surfaceStatus: { '/.git': { status: 200, redirectedToLogin: false } },
    });
    const ids = runSensitiveEndpointExposure(ctx).map(f => f.ruleId);
    expect(ids).toContain('A01-EXPOSED-001');
  });

  it('không trigger khi /admin trả về 200 nhưng redirectedToLogin = true', () => {
    const ctx = baseCtx({
      surfaceStatus: { '/admin': { status: 200, redirectedToLogin: true } },
    });
    const ids = runSensitiveEndpointExposure(ctx).map(f => f.ruleId);
    expect(ids).not.toContain('A01-EXPOSED-001');
  });

  it('tidak trigger khi không có sensitive endpoint nào được map', () => {
    const ctx = baseCtx({ surfaceStatus: {} });
    const ids = runSensitiveEndpointExposure(ctx).map(f => f.ruleId);
    expect(ids).length(0);
  });
});

describe('A01-EXPOSED-002 – sensitive endpoint trả về 403 (có thể bypass)', () => {
  it('triggers khi /actuator/env trả về 403', () => {
    const ctx = baseCtx({
      surfaceStatus: { '/actuator/env': { status: 403 } },
    });
    const ids = runSensitiveEndpointExposure(ctx).map(f => f.ruleId);
    expect(ids).toContain('A01-EXPOSED-002');
  });
});

describe('A01-EXPOSED-003 – server cho phép HTTP methods nguy hiểm', () => {
  it('triggers khi Allow header chứa "DELETE"', () => {
    const ctx = baseCtx({ responseHeaders: { Allow: 'GET, POST, DELETE, PUT' } });
    const ids = runSensitiveEndpointExposure(ctx).map(f => f.ruleId);
    expect(ids).toContain('A01-EXPOSED-003');
  });

  it('không trigger khi Allow header chỉ có GET, POST', () => {
    const ctx = baseCtx({ responseHeaders: { Allow: 'GET, POST' } });
    const ids = runSensitiveEndpointExposure(ctx).map(f => f.ruleId);
    expect(ids).not.toContain('A01-EXPOSED-003');
  });
});

// ---------------------------------------------------------------------------
// 9. Mass Assignment
// ---------------------------------------------------------------------------
describe('A01-MASS – mass assignment heuristic', () => {
  it('triggers A01-MASS-002 (high confidence) khi privilege field trong cả request lẫn response', () => {
    const ctx = baseCtx({
      method: 'POST',
      requestBody: '{"username":"alice","isAdmin":true}',
      text: '{"id":1,"username":"alice","isAdmin":true,"role":"admin"}',
    });
    const ids = runMassAssignmentHeuristic(ctx).map(f => f.ruleId);
    expect(ids).toContain('A01-MASS-002');
  });

  it('triggers A01-MASS-003 khi privilege field chỉ trong request body (PUT)', () => {
    const ctx = baseCtx({
      method: 'PUT',
      requestBody: '{"role":"superuser","name":"bob"}',
      text: '{"id":2,"name":"bob"}',
    });
    const ids = runMassAssignmentHeuristic(ctx).map(f => f.ruleId);
    expect(ids).toContain('A01-MASS-003');
  });

  it('triggers A01-MASS-001 khi privilege field chỉ trong response (thông tin)', () => {
    const ctx = baseCtx({
      method: 'GET',
      text: '{"id":3,"username":"carol","isAdmin":false}',
    });
    const ids = runMassAssignmentHeuristic(ctx).map(f => f.ruleId);
    expect(ids).toContain('A01-MASS-001');
  });

  it('không trigger khi không có privilege field nào', () => {
    const ctx = baseCtx({
      method: 'POST',
      requestBody: '{"username":"dave","email":"dave@example.com"}',
      text: '{"id":4,"username":"dave"}',
    });
    const ids = runMassAssignmentHeuristic(ctx).map(f => f.ruleId);
    const massRules = ['A01-MASS-001', 'A01-MASS-002', 'A01-MASS-003'];
    expect(ids.filter(id => massRules.includes(id))).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 10. runAllA01Rules – Integration
// ---------------------------------------------------------------------------
describe('A01 runAllA01Rules – integration smoke test', () => {
  it('trả về array', () => {
    expect(Array.isArray(runAllA01Rules(baseCtx()))).toBe(true);
  });

  it('mọi finding đều có owaspCategory "A01"', () => {
    const ctx = baseCtx({
      finalUrl: 'https://example.com/admin?authenticated=true',
      text: '"authenticated": true',
      statusCode: 200,
      requestHeaders: { Cookie: 'is_admin=true' },
    });
    const findings = runAllA01Rules(ctx);
    for (const f of findings) expect(f.owaspCategory).toBe('A01');
  });

  it('deduplicate: cùng ruleId + target chỉ xuất hiện một lần', () => {
    // Tạo context có thể trigger trùng
    const ctx = baseCtx({
      text: 'root:x:0:0:root:/root:/bin/bash',
      finalUrl: 'https://example.com/',
    });
    const findings = runAllA01Rules(ctx);
    const keys = findings.map(f => `${f.ruleId}::${f.target}`);
    const uniqueKeys = new Set(keys);
    expect(keys.length).toBe(uniqueKeys.size);
  });

  it('context sạch không sinh finding A01-PATH hoặc A01-AUTHBYP', () => {
    const ctx = baseCtx({
      finalUrl: 'https://example.com/products',
      text: '<html><body><h1>Products</h1></body></html>',
    });
    const findings = runAllA01Rules(ctx);
    const pathOrBypass = findings.filter(f =>
      f.ruleId.startsWith('A01-PATH') || f.ruleId.startsWith('A01-AUTHBYP')
    );
    expect(pathOrBypass).toHaveLength(0);
  });
});

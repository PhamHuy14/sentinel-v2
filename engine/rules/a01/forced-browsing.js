/**
 * Forced Browsing Heuristic
 * OWASP Reference: OTG-AUTHZ-002
 *
 * Changes from original:
 *   1. Removed paths already covered by runSensitiveEndpointExposure (dedup)
 *   2. Added 403 detection with verb-bypass hint
 *   3. Added 401 differentiation
 *   4. Extended path list for auth-protected pages (not just tooling)
 *   5. Added X-Forwarded-For bypass hint
 */

const { normalizeFinding } = require('../../models/finding');

// Paths specific to forced browsing / auth bypass testing.
// Note: tooling paths (admin, swagger, debug etc.) are handled by
// runSensitiveEndpointExposure in access-control-enhanced.js — not duplicated here.
const FORCED_BROWSING_PATHS = [
  // Protected pages that regular users should NOT reach without auth
  { path: '/dashboard', title: 'Dashboard', severity: 'medium' },
  { path: '/account', title: 'Trang tài khoản', severity: 'medium' },
  { path: '/profile', title: 'Trang profile', severity: 'medium' },
  { path: '/settings', title: 'Trang cài đặt', severity: 'medium' },
  { path: '/orders', title: 'Danh sách đơn hàng', severity: 'medium' },
  { path: '/invoices', title: 'Trang hóa đơn', severity: 'medium' },
  { path: '/users', title: 'Danh sách users', severity: 'high' },
  { path: '/user/list', title: 'User list endpoint', severity: 'high' },
  { path: '/admin/users', title: 'Admin user management', severity: 'critical' },
  { path: '/admin/dashboard', title: 'Admin dashboard', severity: 'critical' },
  { path: '/admin/settings', title: 'Admin settings', severity: 'critical' },
  { path: '/admin/logs', title: 'Admin logs', severity: 'high' },
  { path: '/admin/reports', title: 'Admin reports', severity: 'high' },
  // API protected endpoints
  { path: '/api/admin', title: 'Admin API', severity: 'critical' },
  { path: '/api/users', title: 'Users API', severity: 'high' },
  { path: '/api/v1/admin', title: 'Admin API v1', severity: 'critical' },
  { path: '/api/v2/admin', title: 'Admin API v2', severity: 'critical' },
  { path: '/internal', title: 'Internal endpoint', severity: 'high' },
  { path: '/internal/api', title: 'Internal API', severity: 'high' },
  // Private/restricted areas
  { path: '/private', title: 'Khu vực riêng tư', severity: 'medium' },
  { path: '/restricted', title: 'Khu vực hạn chế', severity: 'medium' },
  { path: '/secret', title: 'Endpoint bí mật', severity: 'high' },
  { path: '/hidden', title: 'Endpoint ẩn', severity: 'medium' },
  { path: '/backdoor', title: 'Backdoor endpoint', severity: 'critical' },
  { path: '/superadmin', title: 'Super admin endpoint', severity: 'critical' },
];

// Headers an attacker might add to bypass IP-based auth gates
const IP_BYPASS_HINTS = [
  'X-Forwarded-For: 127.0.0.1',
  'X-Real-IP: 127.0.0.1',
  'X-Originating-IP: 127.0.0.1',
  'X-Remote-IP: 127.0.0.1',
  'Client-IP: 127.0.0.1',
];

function runForcedBrowsing(context) {
  const findings = [];
  const surfaceStatus = context.surfaceStatus || {};

  for (const { path, title, severity } of FORCED_BROWSING_PATHS) {
    const info = surfaceStatus[path];
    if (!info || !info.status) continue;

    // ── 200: Directly accessible ───────────────────────────────────────────────
    if (info.status === 200 && !info.redirectedToLogin) {
      findings.push(normalizeFinding({
        ruleId: 'A01-FB-001',
        owaspCategory: 'A01',
        title: `${title} (${path}) truy cập được mà không cần xác thực`,
        severity: context.isLocalhost ? 'low' : severity,
        confidence: 'high',
        target: `${context.origin}${path}`,
        location: path,
        evidence: [
          `${path} trả về HTTP 200 không có redirect đến trang login.`,
          'Forced browsing thành công — access control không được enforce.',
        ],
        remediation:
          'Implement authentication check trên tất cả protected routes. ' +
          'Redirect về login page nếu chưa auth. ' +
          'Trả về 401 (unauthenticated) hoặc 403 (unauthorized), không trả về 200.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema',
        ],
        collector: 'blackbox',
      }));
      continue;
    }

    // ── 302 redirect to login — correct behavior but log it ───────────────────
    if (info.status === 302 && info.redirectedToLogin) {
      // This is correct behavior — skip
      continue;
    }

    // ── 403: Resource exists but access blocked ──────────────────────────────
    // Could be bypassable via: verb tampering, IP spoofing headers, path variation
    if (info.status === 403) {
      findings.push(normalizeFinding({
        ruleId: 'A01-FB-002',
        owaspCategory: 'A01',
        title: `${title} (${path}) tồn tại nhưng bị block 403 — cần test bypass techniques`,
        severity: 'low',
        confidence: 'low',
        target: `${context.origin}${path}`,
        location: path,
        evidence: [
          `${path} trả về HTTP 403 — resource tồn tại.`,
          'Thử các kỹ thuật bypass:',
          `  1. HTTP verb tampering: HEAD, POST, PUT đến ${path}`,
          `  2. Path variation: ${path}/ ${path}// ${path}%20 ${path}..;/`,
          `  3. IP bypass headers: ${IP_BYPASS_HINTS.slice(0, 2).join(', ')}`,
          `  4. Case variation: ${path.toUpperCase()} `,
        ],
        remediation:
          'Đảm bảo 403 không thể bị bypass. Test với tất cả HTTP methods và path variations. ' +
          'Không dùng client IP hoặc header làm sole auth mechanism.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema',
          'http://static.swpag.info/download/Bypassing_VBAAC_with_HTTP_Verb_Tampering.pdf',
        ],
        collector: 'blackbox',
      }));
    }

    // ── 401: Unauthenticated — correct but may have brute-force risk ──────────
    if (info.status === 401) {
      // 401 on admin paths hints at basic auth — worth noting
      if (path.includes('admin') || path.includes('internal')) {
        findings.push(normalizeFinding({
          ruleId: 'A01-FB-003',
          owaspCategory: 'A01',
          title: `${title} (${path}) yêu cầu xác thực (401) — kiểm tra cơ chế auth`,
          severity: 'info',
          confidence: 'high',
          target: `${context.origin}${path}`,
          location: path,
          evidence: [
            `${path} trả về HTTP 401.`,
            'Nếu dùng Basic Auth, credentials có thể bị brute-force.',
            'Kiểm tra có account lockout không.',
          ],
          remediation:
            'Nếu dùng Basic Auth, chuyển sang form-based auth với lockout mechanism. ' +
            'Implement rate limiting và account lockout.',
          references: [
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism',
          ],
          collector: 'blackbox',
        }));
      }
    }
  }

  return findings;
}

module.exports = { runForcedBrowsing };

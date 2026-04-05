const { normalizeFinding } = require('../../models/finding');

function runJwtWeakness(context) {
  const findings = [];
  const text = context.text || '';
  const jwtInBody = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/i.test(text);
  const authHeader = context.requestHeaders?.['Authorization'] || '';
  const hasJwtAuth = /^Bearer\s+eyJ/i.test(authHeader);
  if (jwtInBody && !hasJwtAuth) {
    findings.push(normalizeFinding({
      ruleId: 'A01-JWT-001',
      owaspCategory: 'A01',
      title: 'Có JWT token trong response — cần kiểm tra validation phía server',
      severity: 'low',
      confidence: 'low',
      target: context.finalUrl,
      location: 'response body',
      evidence: ['JWT token pattern được tìm thấy trong response. Cần verify server validate signature và algorithm.'],
      remediation: 'Đảm bảo server reject token có alg:none, RS256 → HS256 downgrade, và token với signature không hợp lệ.',
      references: ['https://portswigger.net/web-security/jwt'],
      collector: 'blackbox'
    }));
  }
  return findings;
}

function runPathTraversalHeuristic(context) {
  const text = context.text || '';
  if (/root:x:0:0:|\/etc\/passwd|boot\.ini|win\.ini/i.test(text)) {
    return [normalizeFinding({
      ruleId: 'A01-PATH-001',
      owaspCategory: 'A01',
      title: 'Có dấu hiệu path traversal thành công',
      severity: 'critical',
      confidence: 'high',
      target: context.finalUrl,
      location: 'response body',
      evidence: ['Response chứa nội dung giống file hệ thống nhạy cảm (/etc/passwd, win.ini)'],
      remediation: 'Validate và sanitize tất cả file path input. Dùng allowlist thư mục hợp lệ.',
      references: ['https://owasp.org/www-community/attacks/Path_Traversal'],
      collector: 'blackbox'
    })];
  }
  return [];
}

function runSensitiveEndpointExposure(context) {
  const findings = [];
  const surfaceStatus = context.surfaceStatus || {};
  const sensitiveEndpoints = {
    '/admin': { severity: 'high', title: 'Admin panel' },
    '/swagger': { severity: 'medium', title: 'Swagger/OpenAPI docs' },
    '/swagger-ui': { severity: 'medium', title: 'Swagger UI' },
    '/api-docs': { severity: 'medium', title: 'API documentation' },
    '/debug': { severity: 'high', title: 'Debug endpoint' },
    '/actuator': { severity: 'high', title: 'Spring Actuator' },
    '/metrics': { severity: 'medium', title: 'Metrics endpoint' },
    '/health': { severity: 'low', title: 'Health check (thông tin hệ thống)' },
    '/phpinfo.php': { severity: 'high', title: 'PHPInfo page' },
    '/.env': { severity: 'critical', title: 'Environment file' },
    '/config': { severity: 'high', title: 'Config endpoint' },
  };
  for (const [path, meta] of Object.entries(sensitiveEndpoints)) {
    const info = surfaceStatus[path];
    if (!info || !info.status) continue;
    if (info.status === 200 && !info.redirectedToLogin) {
      findings.push(normalizeFinding({
        ruleId: 'A01-EXPOSED-001',
        owaspCategory: 'A01',
        title: `${meta.title} accessible không cần auth`,
        severity: context.isLocalhost ? 'low' : meta.severity,
        confidence: 'high',
        target: `${context.origin}${path}`,
        location: path,
        evidence: [`${path} trả về HTTP 200 không có redirect/auth gate`],
        remediation: 'Giới hạn truy cập bằng authentication, IP allowlist, hoặc xóa endpoint nếu không cần thiết.',
        references: ['https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/'],
        collector: 'blackbox'
      }));
    }
  }
  return findings;
}

function runMassAssignmentHeuristic(context) {
  const text = context.text || '';
  if (/"(is_admin|isAdmin|role|permissions|privilege)"\s*:/i.test(text)) {
    return [normalizeFinding({
      ruleId: 'A01-MASS-001',
      owaspCategory: 'A01',
      title: 'Response chứa privilege fields — cần kiểm tra mass assignment',
      severity: 'low',
      confidence: 'low',
      target: context.finalUrl,
      location: 'response body (JSON)',
      evidence: ['Response JSON chứa field liên quan quyền hạn (isAdmin, role, privilege)'],
      remediation: 'Dùng allowlist (DTO/ViewModel) để chỉ bind các field được phép.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html'],
      collector: 'blackbox'
    })];
  }
  return [];
}

module.exports = { runJwtWeakness, runPathTraversalHeuristic, runSensitiveEndpointExposure, runMassAssignmentHeuristic };

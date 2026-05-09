'use strict';

const path = require('path');
const { normalizeFinding } = require('../../models/finding');

const A04_REF = 'https://owasp.org/Top10/2025/A04_2025-Insecure_Design/';

function getProjectText(context) {
  return [
    ...(context.codeFiles || []),
    ...(context.configFiles || []),
    ...(context.textFiles || []),
  ].map((file) => file?.content || '').join('\n');
}

function hasDesignArtifact(context) {
  const files = context.files || [];
  return files.some((file) => {
    const base = path.basename(String(file)).toLowerCase();
    const normalized = String(file).replace(/\\/g, '/').toLowerCase();
    return (
      /threat[-_ ]?model|security[-_ ]?design|risk[-_ ]?register|abuse[-_ ]?case/.test(base) ||
      normalized.includes('/docs/security') ||
      normalized.includes('/adr/')
    );
  });
}

function runInsecureDesignProjectChecks(context) {
  const findings = [];
  const source = getProjectText(context);
  if (!source) return findings;

  const hasSensitiveFlows = /login|signin|password.?reset|forgot.?password|otp|mfa|admin|payment|checkout|transfer|delete|destroy/i.test(source);
  const hasRateLimitDesign = /rate.?limit|throttle|lockout|captcha|backoff|abuse.?case|anti.?automation/i.test(source);
  const hasAuthorizationDesign = /authorize|authorization|permission|policy|guard|role|rbac|abac|acl|canActivate|requireAuth/i.test(source);

  if (hasSensitiveFlows && !hasDesignArtifact(context)) {
    findings.push(normalizeFinding({
      ruleId: 'A04-DESIGN-001',
      owaspCategory: 'A04',
      title: 'Chưa thấy artifact threat model/security design cho luồng nhạy cảm',
      severity: 'medium',
      confidence: 'low',
      target: context.folderPath || context.repoRoot || 'project',
      location: 'project documentation',
      evidence: ['Project có dấu hiệu luồng auth/admin/payment/destructive nhưng không thấy threat model, security design, ADR hoặc abuse-case doc.'],
      remediation: 'Bổ sung threat model và abuse cases cho các luồng nhạy cảm; ghi rõ trust boundary, actor, misuse case và control bắt buộc.',
      references: [A04_REF, 'https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html'],
      collector: 'source',
    }));
  }

  if (/login|signin|password.?reset|forgot.?password|otp|mfa/i.test(source) && !hasRateLimitDesign) {
    findings.push(normalizeFinding({
      ruleId: 'A04-DESIGN-002',
      owaspCategory: 'A04',
      title: 'Luồng xác thực nhạy cảm chưa thấy thiết kế chống abuse/rate limiting',
      severity: 'medium',
      confidence: 'low',
      target: context.folderPath || context.repoRoot || 'project',
      location: 'auth flow design',
      evidence: ['Có dấu hiệu login/reset/OTP/MFA nhưng không thấy rate-limit, throttling, lockout, CAPTCHA hoặc backoff trong source/config được quét.'],
      remediation: 'Thiết kế rate limiting theo user/IP/device, lockout mềm, cảnh báo bất thường và bảo vệ reset/OTP khỏi brute force.',
      references: [A04_REF, 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'],
      collector: 'source',
    }));
  }

  if (/delete|destroy|admin|role|permission|transfer|refund/i.test(source) && !hasAuthorizationDesign) {
    findings.push(normalizeFinding({
      ruleId: 'A04-DESIGN-003',
      owaspCategory: 'A04',
      title: 'Luồng đặc quyền/destructive thiếu dấu hiệu authorization-by-design',
      severity: 'high',
      confidence: 'low',
      target: context.folderPath || context.repoRoot || 'project',
      location: 'privileged flow design',
      evidence: ['Có dấu hiệu action admin/destructive/privileged nhưng không thấy policy/guard/permission/role check trong source được quét.'],
      remediation: 'Áp dụng deny-by-default, policy/guard tập trung, kiểm tra quyền phía server cho từng action và review thiết kế trước release.',
      references: [A04_REF, 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'],
      collector: 'source',
    }));
  }

  return findings;
}

function runInsecureDesignUrlChecks(context) {
  const findings = [];
  const attackSurface = context.attackSurface || {};
  if ((attackSurface.score || 0) >= 45) {
    findings.push(normalizeFinding({
      ruleId: 'A04-DESIGN-004',
      owaspCategory: 'A04',
      title: 'Attack surface lớn, cần security design review',
      severity: 'medium',
      confidence: 'low',
      target: context.origin || context.finalUrl || '',
      location: 'attack surface',
      evidence: [`Attack surface score: ${attackSurface.score}/100`],
      remediation: 'Rà lại threat model, auth boundary, exposure của admin/debug/API docs và kiểm soát truy cập mặc định.',
      references: [A04_REF],
      collector: 'blackbox',
    }));
  }

  return findings;
}

function runInsecureDesignChecks(context) {
  return [
    ...runInsecureDesignProjectChecks(context),
    ...runInsecureDesignUrlChecks(context),
  ];
}

module.exports = {
  runInsecureDesignChecks,
  runInsecureDesignProjectChecks,
  runInsecureDesignUrlChecks,
};

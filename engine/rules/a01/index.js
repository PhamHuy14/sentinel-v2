/**
 * Chỉ mục quy tắc A01.
 * Tập hợp toàn bộ quy tắc cho OWASP A01 - Broken Access Control.
 *
 * Cách dùng:
 * Require file này và gọi runAllA01Rules(context) để chạy toàn bộ,
 * hoặc require từng module riêng lẻ.
 */

'use strict';

const { runJwtWeakness, runPathTraversalHeuristic, runSensitiveEndpointExposure, runMassAssignmentHeuristic } = require('./access-control-enhanced');
const { runCsrfHeuristic } = require('./csrf-heuristic');
const { runForcedBrowsing } = require('./forced-browsing');
const { runIdorHeuristic } = require('./idor-heuristic');
const { runPrivilegeEscalationHeuristic } = require('./privilege-escalation');
const { runAuthBypassHeuristic } = require('./auth-bypass');
const { runHttpVerbTampering } = require('./http-verb-tampering');
const { runSessionManagementHeuristic } = require('./session-management');
const { runSecurityHeadersHeuristic } = require('./security-headers');

/**
 * Danh sách toàn bộ quy tắc theo thứ tự ưu tiên.
 * Mỗi phần tử: { fn, name, owasp }
 */
const ALL_A01_RULES = [
  // Nhóm mức critical hoặc độ tin cậy cao.
  { fn: runPathTraversalHeuristic,       name: 'PathTraversal',         owasp: 'OTG-AUTHZ-001' },
  { fn: runAuthBypassHeuristic,          name: 'AuthBypass',            owasp: 'OTG-AUTHN-004' },
  { fn: runPrivilegeEscalationHeuristic, name: 'PrivilegeEscalation',   owasp: 'OTG-AUTHZ-003' },
  { fn: runJwtWeakness,                  name: 'JwtWeakness',           owasp: 'OTG-AUTHN'     },

  // Nhóm bề mặt kiểm soát truy cập.
  { fn: runSensitiveEndpointExposure,    name: 'SensitiveEndpoint',     owasp: 'OTG-CONFIG-005' },
  { fn: runForcedBrowsing,               name: 'ForcedBrowsing',        owasp: 'OTG-AUTHZ-002' },
  { fn: runIdorHeuristic,                name: 'IDOR',                  owasp: 'OTG-AUTHZ-004' },
  { fn: runMassAssignmentHeuristic,      name: 'MassAssignment',        owasp: 'OTG-AUTHZ-003' },

  // Nhóm session và CSRF.
  { fn: runSessionManagementHeuristic,   name: 'SessionManagement',     owasp: 'OTG-SESS-001'  },
  { fn: runCsrfHeuristic,                name: 'CSRF',                  owasp: 'OTG-SESS-005'  },

  // Nhóm cấu hình HTTP.
  { fn: runHttpVerbTampering,            name: 'HttpVerbTampering',     owasp: 'OTG-CONFIG-006' },
  { fn: runSecurityHeadersHeuristic,     name: 'SecurityHeaders',       owasp: 'OTG-AUTHN-006' },
];

/**
 * Chạy toàn bộ quy tắc A01 và trả về mảng findings (đã làm phẳng, đã khử trùng lặp).
 * @param {object} context
 * @returns {Array} danh sách phát hiện
 */
function runAllA01Rules(context) {
  const allFindings = [];
  const seenEvidence = new Set();

  for (const { fn, name } of ALL_A01_RULES) {
    try {
      const results = fn(context) || [];
      for (const finding of results) {
        // Khử trùng lặp đơn giản: cùng ruleId + cùng target
        const key = `${finding.ruleId}::${finding.target}`;
        if (!seenEvidence.has(key)) {
          seenEvidence.add(key);
          allFindings.push(finding);
        }
      }
    } catch (err) {
      // Không để một quy tắc làm hỏng toàn bộ luồng xử lý
      if (process.env.DEBUG_RULES) {
        console.error(`[A01 Rules] Error in ${name}:`, err.message);
      }
    }
  }

  return allFindings;
}

module.exports = {
  runAllA01Rules,
  // Đồng thời export từng runner để dùng chọn lọc
  runJwtWeakness,
  runPathTraversalHeuristic,
  runSensitiveEndpointExposure,
  runMassAssignmentHeuristic,
  runCsrfHeuristic,
  runForcedBrowsing,
  runIdorHeuristic,
  runPrivilegeEscalationHeuristic,
  runAuthBypassHeuristic,
  runHttpVerbTampering,
  runSessionManagementHeuristic,
  runSecurityHeadersHeuristic,
};

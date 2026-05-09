const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện GraphQL Introspection và API Misconfiguration
 * Tham chiếu OWASP WSTG: WSTG-CONF-02, WSTG-APIT-01
 *
 * GraphQL introspection bị bật trong production cho phép attacker:
 *  1. Dump toàn bộ schema: mutations, queries, types, fields
 *  2. Tìm endpoint, type, field ẩn
 *  3. Xây dựng attack payload chính xác hơn
 *
 * API misconfiguration: debug endpoints, CORS wildcard, versioning lộ
 */

// ─────────────────────────────────────────────────────────────────────────────
// 1. GraphQL Introspection
// ─────────────────────────────────────────────────────────────────────────────

// Dấu hiệu introspection query thành công trong response
const GRAPHQL_INTROSPECTION_PATTERNS = [
  // Response chứa __schema object (kết quả introspection)
  {
    re: /"__schema"\s*:\s*\{/i,
    label: 'Đối tượng __schema trong response — truy vấn introspection thành công',
  },
  // __typename, __type response
  {
    re: /"__typename"\s*:\s*"Query"|"__typename"\s*:\s*"Mutation"/i,
    label: '__typename Query/Mutation trong response',
  },
  // queryType, mutationType, types array
  {
    re: /"queryType"\s*:\s*\{.*"mutationType"\s*:/is,
    label: 'queryType và mutationType trong schema dump',
  },
  // Danh sách types đầy đủ
  {
    re: /"types"\s*:\s*\[.*"kind"\s*:\s*"OBJECT".*"kind"\s*:\s*"SCALAR"/is,
    label: 'Danh sách GraphQL types (OBJECT, SCALAR) trong response — full schema dump',
  },
];

// Dấu hiệu GraphQL endpoint (chưa chắc introspection thành công)
const GRAPHQL_PRESENCE_PATTERNS = [
  { re: /"data"\s*:\s*\{.*"errors"\s*:\s*\[/is,   label: 'Định dạng response GraphQL (data + errors)' },
  { re: /Cannot query field.*did you mean/i,        label: 'Lỗi field GraphQL (GraphQL engine đang hoạt động)' },
  { re: /Syntax Error.*Expected Name.*found/i,      label: 'Thông báo lỗi cú pháp GraphQL' },
];

function runGraphqlIntrospectionCheck(context) {
  const text = context.text || '';
  const contentType = (context.contentType || '').toLowerCase();
  const findings = [];

  // Chỉ check JSON response
  if (!contentType.includes('json') && !contentType.includes('graphql')) {
    // Fallback: check by content shape
    if (!text.includes('"data"') && !text.includes('"errors"')) return findings;
  }

  // Kiểm tra introspection thành công
  const introspectionMatches = GRAPHQL_INTROSPECTION_PATTERNS.filter(({ re }) => re.test(text));
  if (introspectionMatches.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A06-GRAPHQL-001',
      owaspCategory: 'A06',
      title: 'GraphQL Introspection bị bật — attacker có thể dump toàn bộ schema',
      severity: 'medium',
      confidence: 'high',
      target: context.finalUrl,
      location: 'GraphQL response body',
      evidence: [
        ...introspectionMatches.map(m => m.label),
        'Introspection lộ toàn bộ types, queries, mutations, fields — dữ liệu vàng cho attacker.',
      ],
      remediation:
        'Tắt introspection trong production GraphQL server. ' +
        'Apollo Server: `introspection: false`. ' +
        'graphql-js: dùng `NoSchemaIntrospectionCustomRule`. ' +
        'Hasura: tắt trong console settings. ' +
        'Nếu cần introspection cho internal tools, giới hạn bằng IP allowlist hoặc auth.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL',
        'https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
    return findings;
  }

  // Kiểm tra GraphQL endpoint tồn tại (low severity — cần probe thêm)
  const presenceMatches = GRAPHQL_PRESENCE_PATTERNS.filter(({ re }) => re.test(text));
  if (presenceMatches.length >= 1) {
    findings.push(normalizeFinding({
      ruleId: 'A06-GRAPHQL-002',
      owaspCategory: 'A06',
      title: 'Phát hiện GraphQL endpoint — cần kiểm tra introspection và auth',
      severity: 'info',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'response body',
      evidence: [
        ...presenceMatches.map(m => m.label),
        'Cần thủ công kiểm tra: introspection, depth limiting, query complexity limits, auth.',
      ],
      remediation:
        'Kiểm tra: 1) Introspection có bật không. 2) Query depth limit. 3) Query complexity. ' +
        '4) Rate limiting. 5) Auth đúng trên mỗi field resolver.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html'],
      collector: 'blackbox',
    }));
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. REST API Misconfiguration
// ─────────────────────────────────────────────────────────────────────────────

function runApiMisconfigCheck(context) {
  const findings = [];
  const text = context.text || '';
  const headers = context.headers || {};
  const getHeader = (k) => (headers?.get ? headers.get(k) : (headers[k] || headers[k.toLowerCase()] || '')) || '';

  // Swagger/OpenAPI spec bị lộ (check trong response body — endpoint probe đã được handle bởi A01)
  if (/"swagger"\s*:\s*["']\d+\.?\d*["']|"openapi"\s*:\s*["']\d+\.\d+["']/i.test(text)) {
    const specMatch = text.match(/"(?:swagger|openapi)"\s*:\s*["']([^"']+)["']/i);
    findings.push(normalizeFinding({
      ruleId: 'A06-API-001',
      owaspCategory: 'A06',
      title: 'Swagger/OpenAPI specification bị lộ trong response',
      severity: 'medium',
      confidence: 'high',
      target: context.finalUrl,
      location: 'response body (JSON)',
      evidence: [
        `Phát hiện Swagger/OpenAPI spec${specMatch ? ` (version ${specMatch[1]})` : ''} trong response.`,
        'Spec lộ toàn bộ endpoint, parameter, auth scheme — giúp attacker enumerate API.',
      ],
      remediation:
        'Giới hạn truy cập Swagger UI bằng auth hoặc IP allowlist trong production. ' +
        'Cân nhắc disable hoàn toàn API docs trong production nếu không cần thiết.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces',
      ],
      collector: 'blackbox',
    }));
  }

  // Kiểm tra Server-Timing header (tiết lộ backend timing info)
  const serverTiming = getHeader('server-timing');
  if (serverTiming && /(?:db|sql|cache|redis|query|handler)=\d+/i.test(serverTiming)) {
    findings.push(normalizeFinding({
      ruleId: 'A06-API-002',
      owaspCategory: 'A06',
      title: 'Server-Timing header tiết lộ thông tin backend (DB, cache timing)',
      severity: 'low',
      confidence: 'high',
      target: context.finalUrl,
      location: 'Server-Timing response header',
      evidence: [
        `Server-Timing: ${serverTiming.slice(0, 150)}`,
        'Timing data có thể giúp attacker suy luận về database queries và cache behavior (timing side-channel).',
      ],
      remediation:
        'Giới hạn Server-Timing header: chỉ expose total time, không expose component names như db, sql, cache. ' +
        'Hoặc chỉ gửi Server-Timing cho internal monitoring.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing'],
      collector: 'blackbox',
    }));
  }

  return findings;
}

module.exports = { runGraphqlIntrospectionCheck, runApiMisconfigCheck };

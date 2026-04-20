/**
 * IDOR (Insecure Direct Object Reference) Heuristic
 * OWASP Reference: OTG-AUTHZ-004
 *
 * Changes from original:
 *   1. Thêm UUID/GUID pattern detection
 *   2. Thêm API path parameter detection (/api/users/123)
 *   3. Thêm JSON response field patterns
 *   4. Thêm nhiều object identifier names
 *   5. Cross-user access hint (context.alternativeUserId)
 *   6. Object enumeration concern for sequential IDs
 */

const { normalizeFinding } = require('../../models/finding');

// ── Pattern groups ────────────────────────────────────────────────────────────

// Query string parameters with numeric/identifier values
const QUERY_ID_PATTERN =
  /[?&](id|userId|user_id|orderId|order_id|productId|product_id|categoryId|category_id|accountId|account_id|documentId|document_id|fileId|file_id|reportId|report_id|ticketId|ticket_id|invoiceId|invoice_id|messageId|message_id|postId|post_id|commentId|comment_id|itemId|item_id|customerId|customer_id|employeeId|employee_id|projectId|project_id)=([a-zA-Z0-9_-]{1,64})/gi;

// API path patterns like /api/users/123 or /v1/orders/abc-123
const API_PATH_PATTERN =
  /\/(?:api\/)?(?:v\d+\/)?(users?|accounts?|orders?|products?|documents?|files?|reports?|tickets?|invoices?|messages?|posts?|comments?|customers?|employees?|projects?|items?|subscriptions?|payments?)\/([a-zA-Z0-9_-]{1,64})/gi;

// UUID pattern in URL or response
const UUID_PATTERN =
  /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;

// JSON response fields with numeric IDs
const JSON_ID_FIELD_PATTERN =
  /"(?:id|user_?id|account_?id|order_?id|product_?id|document_?id|file_?id|report_?id|ticket_?id|invoice_?id|owner_?id|author_?id|created_?by)"\s*:\s*(\d+)/gi;

// Sequential numeric IDs (high IDOR risk)
const SEQUENTIAL_ID_PATTERN = /[?&/](\d{1,8})(?:[?&/]|$)/g;

function extractPatternMatches(text, pattern, maxResults = 8) {
  const matches = [];
  let match;
  const regex = new RegExp(pattern.source, pattern.flags);
  while ((match = regex.exec(text)) !== null && matches.length < maxResults) {
    matches.push(match[0]);
  }
  return [...new Set(matches)];
}

function runIdorHeuristic(context) {
  const findings = [];
  const url = context.finalUrl || '';
  const responseText = context.text || '';
  const combined = `${url}\n${responseText}`;

  // ── 1. Query string ID params ─────────────────────────────────────────────
  const queryMatches = extractPatternMatches(combined, QUERY_ID_PATTERN);

  // ── 2. API path params ────────────────────────────────────────────────────
  const apiPathMatches = extractPatternMatches(combined, API_PATH_PATTERN);

  // ── 3. UUIDs in URL or response ───────────────────────────────────────────
  const uuidMatches = extractPatternMatches(url, UUID_PATTERN, 4);

  // ── 4. JSON ID fields in response ────────────────────────────────────────
  const jsonIdMatches = extractPatternMatches(responseText, JSON_ID_FIELD_PATTERN, 6);

  // ── 5. Sequential numeric IDs in URL ──────────────────────────────────────
  const sequentialMatches = extractPatternMatches(url, SEQUENTIAL_ID_PATTERN, 3);

  const allIdentifiers = [
    ...queryMatches,
    ...apiPathMatches,
    ...uuidMatches.slice(0, 2),
    ...jsonIdMatches.slice(0, 3),
  ].filter(Boolean);

  if (allIdentifiers.length === 0 && sequentialMatches.length === 0) {
    return [];
  }

  // ── Main IDOR heuristic finding ────────────────────────────────────────────
  if (allIdentifiers.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A01-IDOR-001',
      owaspCategory: 'A01',
      title: 'Có dấu hiệu endpoint/object identifier — cần review quyền truy cập',
      severity: 'medium',
      confidence: 'medium',
      target: context.finalUrl,
      location: allIdentifiers.length > 3 ? 'URL + response body' : 'URL',
      evidence: [
        `Các mẫu định danh tìm thấy: ${allIdentifiers.slice(0, 6).join(', ')}`,
        'Cần kiểm tra: user A có thể truy cập resource của user B không bằng cách đổi ID.',
        'Test: đăng nhập user B, lấy ID từ session của B, truy cập bằng session của A.',
      ],
      remediation:
        'Luôn kiểm tra ownership/authorization ở server-side trước khi trả về object theo ID. ' +
        'Không tin tưởng ID từ client — verify user có quyền với object đó không. ' +
        'Dùng indirect references (random UUID) thay vì sequential integer IDs.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References',
        'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
  }

  // ── Sequential ID specific risk ───────────────────────────────────────────
  if (sequentialMatches.length > 0 && queryMatches.length > 0) {
    // Check if the IDs look sequential (single small integer → easy to enumerate)
    const numericIds = queryMatches
      .map(m => {
        const numMatch = m.match(/=(\d+)$/);
        return numMatch ? parseInt(numMatch[1], 10) : null;
      })
      .filter(n => n !== null && n < 10000);

    if (numericIds.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A01-IDOR-002',
        owaspCategory: 'A01',
        title: 'Object IDs là số nguyên nhỏ — dễ bị enumerate',
        severity: context.isLocalhost ? 'low' : 'medium',
        confidence: 'medium',
        target: context.finalUrl,
        location: 'URL query parameters',
        evidence: [
          `Tìm thấy numeric IDs nhỏ: ${numericIds.slice(0, 4).join(', ')}`,
          'IDs tuần tự dễ bị enumerate bằng brute-force (1, 2, 3, ..., N).',
          'Attacker có thể lặp qua toàn bộ object trong database.',
        ],
        remediation:
          'Dùng UUID (v4) hoặc ULID thay vì sequential integer ID cho các object nhạy cảm. ' +
          'Đảm bảo authorization check phía server vẫn là biện pháp chính.',
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html',
        ],
        collector: 'blackbox',
      }));
    }
  }

  // ── Cross-user access test result (if context provides it) ────────────────
  // This requires the scanner to have actually tested cross-user access
  if (context.idorCrossUserResult) {
    const { testedId, ownerUserId, requestingUserId, accessGranted } = context.idorCrossUserResult;
    if (accessGranted) {
      findings.push(normalizeFinding({
        ruleId: 'A01-IDOR-003',
        owaspCategory: 'A01',
        title: 'IDOR xác nhận: user có thể truy cập object của user khác',
        severity: context.isLocalhost ? 'medium' : 'critical',
        confidence: 'high',
        target: context.finalUrl,
        location: 'cross-user access test',
        evidence: [
          `Object ID: ${testedId}`,
          `Owned by: user ${ownerUserId}`,
          `Accessed by: user ${requestingUserId}`,
          'Server trả về object mà không check ownership.',
        ],
        remediation:
          'Implement ownership check: query WHERE id=? AND owner_id=current_user_id. ' +
          'Hoặc dùng authorization framework (RBAC/ABAC) với object-level permission.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References',
        ],
        collector: 'blackbox',
      }));
    }
  }

  return findings;
}

module.exports = { runIdorHeuristic };

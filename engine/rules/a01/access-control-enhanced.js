/**
 * Bộ quy tắc kiểm soát truy cập nâng cao
 * Tham chiếu OWASP:
 *   - OTG-AUTHZ-001: Vượt đường dẫn / nhúng tệp
 *   - OTG-AUTHZ-003: Leo thang đặc quyền (mass assignment)
 *   - OTG-CONFIG-005: Lộ endpoint nhạy cảm
 *   - OTG-AUTHN (JWT): Phát hiện điểm yếu JWT
 *
 * Điểm thay đổi so với bản gốc:
 *   1. runJwtWeakness: Thêm giải mã tiêu đề để phát hiện alg:none và thuật toán yếu
 *   2. runPathTraversalHeuristic: Mở rộng mẫu nhận diện, thêm đường dẫn Windows
 *   3. runSensitiveEndpointExposure: Thêm đường dẫn con Git/SVN/backup/Spring actuator,
 *      phát hiện 403 kèm gợi ý giả mạo phương thức, kiểm tra phương thức HTTP từ Allow header
 *   4. runMassAssignmentHeuristic: Sửa logic, ưu tiên phát hiện trường trong phần thân yêu cầu
 */

const { normalizeFinding } = require('../../models/finding');

// ─────────────────────────────────────────────────────────────────────────────
// 1. Điểm yếu JWT (nâng cao)
// ─────────────────────────────────────────────────────────────────────────────

function decodeJwtHeader(token) {
  try {
    const headerB64 = token.split('.')[0];
    const decoded = Buffer.from(headerB64, 'base64').toString('utf8');
    return JSON.parse(decoded);
  } catch (_) {
    return null;
  }
}

function runJwtWeakness(context) {
  const findings = [];
  const text = context.text || '';
  const authHeader = context.requestHeaders?.['Authorization'] || '';
  const tokenMatch = authHeader.match(/Bearer\s+(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)/i);

  // ── Trường hợp A: Giải mã token đang được sử dụng ────────────────────────────
  if (tokenMatch) {
    const token = tokenMatch[1];
    const header = decodeJwtHeader(token);

    if (header) {
      // alg:none là mức nghiêm trọng cao
      if (!header.alg || header.alg.toLowerCase() === 'none') {
        findings.push(normalizeFinding({
          ruleId: 'A01-JWT-002',
          owaspCategory: 'A01',
          title: 'JWT token dùng algorithm "none" — không có chữ ký',
          severity: 'critical',
          confidence: 'high',
          target: context.finalUrl,
          location: 'Authorization header',
          evidence: [
            `JWT header: ${JSON.stringify(header)}`,
            'alg:none có nghĩa token không có chữ ký. Nếu server chấp nhận, bất kỳ ai cũng có thể forge token.',
          ],
          remediation:
            'Server phải từ chối bất kỳ token nào có alg=none. ' +
            'Dùng library JWT đã được kiểm định và configure allowedAlgorithms tường minh.',
          references: ['https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature'],
          collector: 'blackbox',
        }));
      }

      // Thuật toán đối xứng yếu
      if (['HS256', 'HS384', 'HS512'].includes(header.alg)) {
        findings.push(normalizeFinding({
          ruleId: 'A01-JWT-003',
          owaspCategory: 'A01',
          title: `JWT dùng symmetric algorithm ${header.alg} — nguy cơ weak secret`,
          severity: 'low',
          confidence: 'low',
          target: context.finalUrl,
          location: 'Authorization header JWT',
          evidence: [
            `Algorithm: ${header.alg}`,
            'HMAC-based JWT dùng shared secret. Nếu secret yếu, attacker có thể brute-force.',
            'Dễ bị tấn công RS256→HS256 confusion nếu server không validate algorithm.',
          ],
          remediation:
            'Dùng RS256/ES256 (asymmetric) cho production. ' +
            'Nếu dùng HS256, secret phải ít nhất 256-bit ngẫu nhiên.',
          references: ['https://portswigger.net/web-security/jwt'],
          collector: 'blackbox',
        }));
      }
    }
  }

  // ── Trường hợp B: JWT xuất hiện trong thân phản hồi (quy tắc thụ động) ───────
  const jwtInBody = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/i.test(text);
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
      evidence: ['Phát hiện mẫu JWT token trong response. Cần xác minh server kiểm tra signature và algorithm đúng cách.'],
      remediation:
        'Đảm bảo server từ chối token có alg:none, hạ cấp RS256 → HS256, và mọi token có chữ ký không hợp lệ.',
      references: ['https://portswigger.net/web-security/jwt'],
      collector: 'blackbox',
    }));
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Vượt đường dẫn (nâng cao)
// ─────────────────────────────────────────────────────────────────────────────

// Dấu hiệu vượt đường dẫn thành công trong phản hồi
const TRAVERSAL_SUCCESS_PATTERNS = [
  { pattern: /root:x:0:0:/, label: '/etc/passwd content (root entry)' },
  { pattern: /daemon:x:\d+:\d+/, label: '/etc/passwd content (daemon entry)' },
  { pattern: /nobody:x:\d+:\d+/, label: '/etc/passwd content (nobody entry)' },
  { pattern: /\[boot loader\]/i, label: 'Windows boot.ini content' },
  { pattern: /\[extensions\]/i, label: 'Windows win.ini content' },
  { pattern: /\[fonts\]/i, label: 'Windows win.ini [fonts] section' },
  { pattern: /shadow:[*!]/, label: '/etc/shadow content' },
  { pattern: /\[drivers\]/i, label: 'Windows system file content' },
  // Tệp hosts của Windows
  { pattern: /127\.0\.0\.1\s+localhost/i, label: 'hosts file content' },
  // Lộ mã nguồn qua traversal
  { pattern: /<\?php\s+/i, label: 'PHP source code in response (possible traversal to .php file)' },
  // Đường dẫn Windows nhạy cảm
  { pattern: /\[AutoRun\]/i, label: 'Windows autorun.inf content' },
];

function runPathTraversalHeuristic(context) {
  const text = context.text || '';

  const matches = TRAVERSAL_SUCCESS_PATTERNS.filter(({ pattern }) => pattern.test(text));

  if (matches.length === 0) return [];

  const evidenceList = matches.map(m => m.label);

  return [normalizeFinding({
    ruleId: 'A01-PATH-001',
    owaspCategory: 'A01',
    title: 'Có dấu hiệu path traversal thành công',
    severity: 'critical',
    confidence: 'high',
    target: context.finalUrl,
    location: 'response body',
    evidence: evidenceList,
    remediation:
      'Validate và sanitize tất cả file path input. ' +
      'Resolve absolute path và kiểm tra nằm trong allowed directory. ' +
      'Dùng allowlist thư mục hợp lệ thay vì blacklist ký tự.',
    references: [
      'https://owasp.org/www-community/attacks/Path_Traversal',
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include',
    ],
    collector: 'blackbox',
  })];
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Lộ endpoint nhạy cảm (nâng cao)
// ─────────────────────────────────────────────────────────────────────────────

const SENSITIVE_ENDPOINTS = {
  // Quản trị / vận hành
  '/admin': { severity: 'high', title: 'Bảng quản trị' },
  '/admin/': { severity: 'high', title: 'Bảng quản trị' },
  '/administrator': { severity: 'high', title: 'Bảng quản trị (administrator)' },
  '/console': { severity: 'high', title: 'Console endpoint' },
  '/manager': { severity: 'high', title: 'Manager interface' },
  '/management': { severity: 'medium', title: 'Management endpoint' },

  // Tài liệu API
  '/swagger': { severity: 'medium', title: 'Tài liệu Swagger/OpenAPI' },
  '/swagger-ui': { severity: 'medium', title: 'Swagger UI' },
  '/swagger-ui.html': { severity: 'medium', title: 'Swagger UI HTML' },
  '/swagger/index.html': { severity: 'medium', title: 'Swagger index' },
  '/api-docs': { severity: 'medium', title: 'Tài liệu API' },
  '/api/docs': { severity: 'medium', title: 'Tài liệu API' },
  '/openapi.json': { severity: 'medium', title: 'OpenAPI JSON spec' },
  '/openapi.yaml': { severity: 'medium', title: 'OpenAPI YAML spec' },
  '/v2/api-docs': { severity: 'medium', title: 'Swagger v2 API docs' },
  '/v3/api-docs': { severity: 'medium', title: 'Swagger v3 API docs' },

  // Gỡ lỗi / môi trường phát triển
  '/debug': { severity: 'high', title: 'Endpoint debug' },
  '/trace': { severity: 'medium', title: 'HTTP TRACE / trace endpoint' },
  '/phpinfo.php': { severity: 'high', title: 'Trang PHPInfo' },
  '/phpinfo': { severity: 'high', title: 'Trang PHPInfo' },
  '/info.php': { severity: 'high', title: 'PHP info page' },
  '/test.php': { severity: 'medium', title: 'PHP test page' },
  '/adminer.php': { severity: 'high', title: 'Adminer DB management tool' },
  '/adminer': { severity: 'high', title: 'Adminer DB management tool' },

  // Spring Boot Actuator
  '/actuator': { severity: 'high', title: 'Spring Actuator (index)' },
  '/actuator/env': { severity: 'critical', title: 'Spring Actuator — biến môi trường' },
  '/actuator/heapdump': { severity: 'critical', title: 'Spring Actuator — heap dump' },
  '/actuator/mappings': { severity: 'medium', title: 'Spring Actuator — route mappings' },
  '/actuator/beans': { severity: 'medium', title: 'Spring Actuator — Spring beans' },
  '/actuator/logfile': { severity: 'high', title: 'Spring Actuator — log file' },
  '/actuator/configprops': { severity: 'high', title: 'Spring Actuator — config properties' },
  '/actuator/threaddump': { severity: 'medium', title: 'Spring Actuator — thread dump' },
  '/jolokia': { severity: 'high', title: 'Jolokia JMX bridge' },

  // Giám sát
  '/metrics': { severity: 'medium', title: 'Endpoint metrics' },
  '/health': { severity: 'low', title: 'Health check (thông tin hệ thống)' },
  '/status': { severity: 'low', title: 'Status endpoint' },
  '/server-status': { severity: 'medium', title: 'Apache server status' },
  '/server-info': { severity: 'medium', title: 'Apache server info' },

  // Cấu hình / bí mật
  '/.env': { severity: 'critical', title: 'Tệp biến môi trường' },
  '/.env.local': { severity: 'critical', title: 'Tệp .env.local' },
  '/.env.production': { severity: 'critical', title: 'Tệp .env.production' },
  '/.env.development': { severity: 'high', title: 'Tệp .env.development' },
  '/config': { severity: 'high', title: 'Endpoint cấu hình' },
  '/config.json': { severity: 'critical', title: 'Config JSON file' },
  '/config.php': { severity: 'high', title: 'Config PHP file' },
  '/web.config': { severity: 'high', title: 'ASP.NET web.config' },
  '/app.yaml': { severity: 'high', title: 'App config YAML' },

  // Lộ hệ thống quản lý mã nguồn
  '/.git': { severity: 'critical', title: 'Git repository directory' },
  '/.git/config': { severity: 'critical', title: 'Git config (remote URL, credentials)' },
  '/.git/HEAD': { severity: 'high', title: 'Git HEAD file' },
  '/.git/COMMIT_EDITMSG': { severity: 'medium', title: 'Git commit message' },
  '/.svn': { severity: 'high', title: 'SVN repository directory' },
  '/.svn/entries': { severity: 'high', title: 'SVN entries file' },
  '/.hg': { severity: 'high', title: 'Mercurial repository' },
  '/Makefile': { severity: 'medium', title: 'Makefile (project structure)' },

  // Tệp sao lưu
  '/backup': { severity: 'high', title: 'Backup directory' },
  '/backup.zip': { severity: 'critical', title: 'Backup archive' },
  '/backup.tar.gz': { severity: 'critical', title: 'Backup archive' },
  '/db.sql': { severity: 'critical', title: 'Database SQL dump' },
  '/database.sql': { severity: 'critical', title: 'Database SQL dump' },
  '/dump.sql': { severity: 'critical', title: 'Database dump' },

  // Công cụ quản trị cơ sở dữ liệu
  '/phpmyadmin': { severity: 'high', title: 'phpMyAdmin' },
  '/phpMyAdmin': { severity: 'high', title: 'phpMyAdmin' },
  '/pma': { severity: 'high', title: 'phpMyAdmin (pma)' },

  // Đường dẫn mặc định của CMS
  '/wp-admin': { severity: 'medium', title: 'WordPress admin' },
  '/wp-admin/': { severity: 'medium', title: 'WordPress admin' },
  '/wp-login.php': { severity: 'medium', title: 'WordPress login' },
  '/wp-config.php': { severity: 'critical', title: 'WordPress config' },
};

function runSensitiveEndpointExposure(context) {
  const findings = [];
  const surfaceStatus = context.surfaceStatus || {};

  for (const [path, meta] of Object.entries(SENSITIVE_ENDPOINTS)) {
    const info = surfaceStatus[path];
    if (!info || !info.status) continue;

    // ── 200 OK và không chuyển hướng tới trang đăng nhập ─────────────────────
    if (info.status === 200 && !info.redirectedToLogin) {
      findings.push(normalizeFinding({
        ruleId: 'A01-EXPOSED-001',
        owaspCategory: 'A01',
        title: `${meta.title} có thể truy cập mà không cần xác thực`,
        severity: context.isLocalhost ? 'low' : meta.severity,
        confidence: 'high',
        target: `${context.origin}${path}`,
        location: path,
        evidence: [`${path} trả về HTTP 200 không có redirect/auth gate`],
        remediation:
          'Giới hạn truy cập bằng authentication, IP allowlist, hoặc xóa endpoint nếu không cần thiết.',
        references: ['https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/'],
        collector: 'blackbox',
      }));
    }

    // ── 403 Forbidden: tài nguyên tồn tại, có thể bị vượt qua ─────────────────
    if (info.status === 403) {
      findings.push(normalizeFinding({
        ruleId: 'A01-EXPOSED-002',
        owaspCategory: 'A01',
        title: `${meta.title} tồn tại nhưng bị block (403) — có thể bypass`,
        severity: 'low',
        confidence: 'medium',
        target: `${context.origin}${path}`,
        location: path,
        evidence: [
          `${path} trả về HTTP 403 — resource tồn tại nhưng bị từ chối.`,
          'Thử: HTTP verb tampering (HEAD/POST), thêm header X-Forwarded-For: 127.0.0.1, path variation.',
        ],
        remediation:
          'Kiểm tra access control không chỉ dựa vào HTTP method. ' +
          'Verify 403 là đúng và không bị bypass qua các kỹ thuật khác.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces',
        ],
        collector: 'blackbox',
      }));
    }
  }

  // ── Kiểm tra phương thức HTTP từ Allow header ───────────────────────────────
  const allowHeader =
    (context.responseHeaders?.['allow'] || context.responseHeaders?.['Allow'] || '').toUpperCase();
  if (allowHeader) {
    const dangerousMethods = ['PUT', 'DELETE', 'TRACE'].filter(m => allowHeader.includes(m));
    if (dangerousMethods.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A01-EXPOSED-003',
        owaspCategory: 'A01',
        title: `Server cho phép HTTP methods nguy hiểm: ${dangerousMethods.join(', ')}`,
        severity: context.isLocalhost ? 'low' : 'high',
        confidence: 'high',
        target: context.finalUrl,
        location: 'Allow header',
        evidence: [
          `Allow: ${allowHeader}`,
          `Dangerous methods: ${dangerousMethods.join(', ')}`,
        ],
        remediation:
          'Disable các HTTP methods không cần thiết trên web server. ' +
          'REST APIs cần PUT/DELETE phải có proper authentication.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
        ],
        collector: 'blackbox',
      }));
    }
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Mass Assignment (đã sửa logic)
// ─────────────────────────────────────────────────────────────────────────────

const SENSITIVE_FIELDS_PATTERN =
  /["'](is_admin|isAdmin|admin|role|roles|permissions|privilege|privileges|access_level|accessLevel|verified|confirmed|trusted|superuser)["']\s*:/i;

function runMassAssignmentHeuristic(context) {
  const findings = [];
  const responseText = context.text || '';
  const requestBody = context.requestBody || '';
  const method = (context.method || 'GET').toUpperCase();

  const inResponse = SENSITIVE_FIELDS_PATTERN.test(responseText);
  const inRequest = SENSITIVE_FIELDS_PATTERN.test(requestBody);

  // ── Trường hợp A: Trường gửi trong yêu cầu VÀ được phản chiếu/xác nhận trong phản hồi
  // Độ tin cậy cao hơn: máy chủ có khả năng đã ánh xạ trường này
  if (inRequest && inResponse && ['POST', 'PUT', 'PATCH'].includes(method)) {
    findings.push(normalizeFinding({
      ruleId: 'A01-MASS-002',
      owaspCategory: 'A01',
      title: 'Có dấu hiệu Mass Assignment: privilege field trong request được phản chiếu trong response',
      severity: context.isLocalhost ? 'medium' : 'high',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'request body + response body',
      evidence: [
        'Request body chứa privilege field (isAdmin, role, privilege...)',
        'Response body cũng chứa privilege field — server có thể đã bind và lưu giá trị từ request.',
        `HTTP Method: ${method}`,
      ],
      remediation:
        'Dùng allowlist (DTO/ViewModel) để chỉ bind các field được phép. ' +
        'Không bao giờ bind trực tiếp request JSON vào database model.',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html',
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation',
      ],
      collector: 'blackbox',
    }));
    return findings;
  }

  // ── Trường hợp B: Chỉ thấy trường trong yêu cầu (mức quan ngại trung bình)
  if (inRequest && ['POST', 'PUT', 'PATCH'].includes(method)) {
    findings.push(normalizeFinding({
      ruleId: 'A01-MASS-003',
      owaspCategory: 'A01',
      title: 'Request chứa privilege field — cần xác minh server có ignore không',
      severity: 'low',
      confidence: 'low',
      target: context.finalUrl,
      location: 'request body',
      evidence: [
        'Request body chứa field liên quan quyền hạn (isAdmin, role, privilege...)',
        'Cần kiểm tra server-side xem field này có bị bind vào model không.',
      ],
      remediation:
        'Dùng allowlist (DTO/ViewModel) để chỉ bind các field được phép. ' +
        'Log và alert khi nhận field không mong đợi.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html'],
      collector: 'blackbox',
    }));
    return findings;
  }

  // ── Trường hợp C: Chỉ thấy trường trong phản hồi (độ tin cậy thấp, mang tính thông tin)
  if (inResponse && !inRequest) {
    findings.push(normalizeFinding({
      ruleId: 'A01-MASS-001',
      owaspCategory: 'A01',
      title: 'Response chứa privilege fields — cần kiểm tra mass assignment',
      severity: 'low',
      confidence: 'low',
      target: context.finalUrl,
      location: 'response body (JSON)',
      evidence: [
        'Response JSON chứa field liên quan quyền hạn (isAdmin, role, privilege)',
        'Cần thử gửi field này trong PUT/POST request để kiểm tra mass assignment.',
      ],
      remediation:
        'Dùng allowlist (DTO/ViewModel) để chỉ bind các field được phép. ' +
        'Ẩn privilege fields khỏi response nếu client không cần.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html'],
      collector: 'blackbox',
    }));
  }

  return findings;
}

module.exports = {
  runJwtWeakness,
  runPathTraversalHeuristic,
  runSensitiveEndpointExposure,
  runMassAssignmentHeuristic,
};

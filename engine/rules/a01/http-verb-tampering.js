/**
 * HTTP Verb Tampering Heuristic
 * OWASP Reference: OTG-CONFIG-006
 * Detects dangerous HTTP methods enabled, and endpoints that block GET
 * but may allow bypass via HEAD/POST/arbitrary verbs.
 */

const { normalizeFinding } = require('../../models/finding');

// Methods that should not be enabled on a production web app
const DANGEROUS_METHODS = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'];

// Methods that might bypass auth checks (some frameworks treat HEAD as GET)
const BYPASS_CANDIDATE_METHODS = ['HEAD', 'OPTIONS'];

// WebDAV methods — usually unnecessary for web apps
const WEBDAV_METHODS = ['PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK'];

/**
 * Parse the Allow header from an OPTIONS response.
 * Returns array of method strings, uppercased.
 */
function parseAllowHeader(allowHeaderValue) {
  if (!allowHeaderValue) return [];
  return allowHeaderValue
    .split(',')
    .map(m => m.trim().toUpperCase())
    .filter(Boolean);
}

function runHttpVerbTampering(context) {
  const findings = [];
  const surfaceStatus = context.surfaceStatus || {};
  const responseHeaders = context.responseHeaders || {};

  // ----------------------------------------------------------------
  // 1. Check Allow header from OPTIONS response on current endpoint
  // ----------------------------------------------------------------
  const allowHeader =
    responseHeaders.allow ||
    responseHeaders.Allow ||
    responseHeaders['ACCESS-CONTROL-ALLOW-METHODS'] ||
    '';

  const enabledMethods = parseAllowHeader(allowHeader);

  if (enabledMethods.length > 0) {
    const foundDangerous = enabledMethods.filter(m => DANGEROUS_METHODS.includes(m));
    const foundWebDav = enabledMethods.filter(m => WEBDAV_METHODS.includes(m));
    const traceEnabled = enabledMethods.includes('TRACE');

    if (traceEnabled) {
      findings.push(normalizeFinding({
        ruleId: 'A01-VERB-001',
        owaspCategory: 'A01',
        title: 'HTTP TRACE method được bật — nguy cơ Cross-Site Tracing (XST)',
        severity: context.isLocalhost ? 'low' : 'medium',
        confidence: 'high',
        target: context.finalUrl,
        location: 'HTTP Allow header',
        evidence: [
          `Allow header: ${allowHeader}`,
          'TRACE method cho phép attacker đọc HTTP headers (bao gồm cookie HttpOnly) qua XSS.',
        ],
        remediation: 'Disable HTTP TRACE method trên web server. Apache: TraceEnable Off. Nginx: không enable trace.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
          'https://www.cgisecurity.com/whitehat-mirror/WH-WhitePaper_XST_ebook.pdf',
        ],
        collector: 'blackbox',
      }));
    }

    if (foundDangerous.filter(m => m !== 'TRACE').length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A01-VERB-002',
        owaspCategory: 'A01',
        title: `HTTP methods nguy hiểm được bật: ${foundDangerous.join(', ')}`,
        severity: context.isLocalhost ? 'low' : 'high',
        confidence: 'high',
        target: context.finalUrl,
        location: 'HTTP Allow header',
        evidence: [
          `Allow header: ${allowHeader}`,
          `Methods nguy hiểm: ${foundDangerous.join(', ')}`,
          'PUT/DELETE không được phép trừ REST API có authentication đúng cách.',
        ],
        remediation:
          'Disable các HTTP methods không cần thiết. ' +
          'Nếu là REST API cần PUT/DELETE, đảm bảo có authentication và authorization đúng.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
        ],
        collector: 'blackbox',
      }));
    }

    if (foundWebDav.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A01-VERB-003',
        owaspCategory: 'A01',
        title: `WebDAV methods được bật: ${foundWebDav.join(', ')}`,
        severity: context.isLocalhost ? 'info' : 'medium',
        confidence: 'high',
        target: context.finalUrl,
        location: 'HTTP Allow header',
        evidence: [
          `Allow header: ${allowHeader}`,
          `WebDAV methods: ${foundWebDav.join(', ')}`,
          'WebDAV mở rộng attack surface đáng kể nếu không được bảo vệ.',
        ],
        remediation: 'Disable WebDAV nếu không cần thiết.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
        ],
        collector: 'blackbox',
      }));
    }
  }

  // ----------------------------------------------------------------
  // 2. Detect 403 endpoints in surfaceStatus → candidates for verb bypass
  // ----------------------------------------------------------------
  const blockedPaths = [];
  for (const [path, info] of Object.entries(surfaceStatus)) {
    if (!info || !info.status) continue;
    // 403 = resource exists but GET is forbidden → test other verbs
    if (info.status === 403) {
      blockedPaths.push(path);
    }
  }

  if (blockedPaths.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A01-VERB-004',
      owaspCategory: 'A01',
      title: `${blockedPaths.length} endpoint trả về 403 — cần test HTTP verb bypass`,
      severity: 'low',
      confidence: 'low',
      target: context.origin,
      location: blockedPaths.slice(0, 5).join(', '),
      evidence: [
        `Endpoints trả về 403: ${blockedPaths.slice(0, 8).join(', ')}`,
        'Một số framework/server cho phép HEAD hoặc POST khi GET bị chặn.',
        'Test: gửi HEAD/POST đến các path này và kiểm tra response.',
      ],
      remediation:
        'Đảm bảo access control kiểm tra method-agnostic (dựa trên resource, không dựa trên HTTP method). ' +
        'Test tất cả methods cho mỗi protected endpoint.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
        'http://static.swpag.info/download/Bypassing_VBAAC_with_HTTP_Verb_Tampering.pdf',
      ],
      collector: 'blackbox',
    }));
  }

  // ----------------------------------------------------------------
  // 3. Check current request method is non-standard (JEFF, CATS trick)
  // ----------------------------------------------------------------
  const currentMethod = (context.method || '').toUpperCase();
  const standardMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE'];
  if (currentMethod && !standardMethods.includes(currentMethod)) {
    const statusCode = context.statusCode || 0;
    if (statusCode === 200) {
      findings.push(normalizeFinding({
        ruleId: 'A01-VERB-005',
        owaspCategory: 'A01',
        title: `Server trả về 200 cho HTTP method không chuẩn: ${currentMethod}`,
        severity: context.isLocalhost ? 'low' : 'high',
        confidence: 'high',
        target: context.finalUrl,
        location: 'HTTP method',
        evidence: [
          `Method được dùng: ${currentMethod}`,
          'Server xử lý method không chuẩn như GET — có thể bypass method-level access control.',
        ],
        remediation: 'Server nên trả về 405 Method Not Allowed cho mọi method không được hỗ trợ.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
        ],
        collector: 'blackbox',
      }));
    }
  }

  return findings;
}

module.exports = { runHttpVerbTampering };

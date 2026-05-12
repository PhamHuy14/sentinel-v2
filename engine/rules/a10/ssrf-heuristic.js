const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện Server-Side Request Forgery (SSRF) — Blackbox
 * Tham chiếu: OWASP A10:2025, WSTG-INPV-19, CWE-918
 *
 * SSRF cho phép attacker buộc server thực hiện HTTP request đến:
 *  - Internal services (database, cache, admin panel)
 *  - Cloud metadata endpoints (AWS 169.254.169.254, GCP metadata.google.internal)
 *  - Localhost / loopback
 *  - Internal network (RFC1918)
 *
 * Rule này phát hiện qua response analysis (blackbox):
 *  1. Cloud metadata content trong response
 *  2. Internal IP / service content trong response
 *  3. URL parameters chứa full URL (attack surface)
 *  4. Redirect đến internal host
 */

// ─── 1. Cloud Metadata Service Content ───────────────────────────────────────

const AWS_METADATA_PATTERNS = [
  { re: /"AccessKeyId"\s*:\s*"(?:ASIA|AKIA)[A-Z0-9]{16}"/i,
    label: 'AWS IAM credentials (AccessKeyId) trong response — SSRF đến metadata endpoint thành công',
    severity: 'critical' },
  { re: /"SecretAccessKey"\s*:\s*"[A-Za-z0-9+/]{40}"/i,
    label: 'AWS SecretAccessKey trong response — credential leak qua SSRF',
    severity: 'critical' },
  { re: /"Token"\s*:\s*"[A-Za-z0-9+/=]{100,}"/i,
    label: 'AWS session token trong response',
    severity: 'critical' },
  { re: /ami-[0-9a-f]{8,17}/i,
    label: 'AWS AMI ID trong response (EC2 instance metadata)',
    severity: 'high' },
  { re: /"InstanceId"\s*:\s*"i-[0-9a-f]{8,17}"/i,
    label: 'AWS EC2 InstanceId trong response',
    severity: 'high' },
  { re: /169\.254\.169\.254/,
    label: 'AWS metadata IP (169.254.169.254) xuất hiện trong response',
    severity: 'medium' },
  { re: /latest\/meta-data\/iam\/security-credentials/i,
    label: 'AWS metadata credentials path trong response',
    severity: 'high' },
];

const GCP_METADATA_PATTERNS = [
  { re: /metadata\.google\.internal/i,
    label: 'GCP metadata endpoint domain trong response',
    severity: 'medium' },
  { re: /"computeMetadata\/v1/i,
    label: 'GCP Compute Metadata API path trong response',
    severity: 'high' },
  { re: /"serviceAccounts".*"token"/is,
    label: 'GCP service account token trong response',
    severity: 'critical' },
];

const AZURE_METADATA_PATTERNS = [
  { re: /169\.254\.169\.254.*metadata=true|metadata=true.*169\.254\.169\.254/i,
    label: 'Azure IMDS endpoint (169.254.169.254) với metadata header',
    severity: 'medium' },
  { re: /"subscriptionId"\s*:\s*"[0-9a-f-]{36}"/i,
    label: 'Azure subscription ID trong response (Azure IMDS leak)',
    severity: 'high' },
];

// ─── 2. Internal Service / Network Content ────────────────────────────────────

const INTERNAL_SERVICE_PATTERNS = [
  { re: /(?:redis_version|redis_mode|os:Linux.*redis)/i,
    label: 'Redis server info trong response — SSRF đến Redis port (6379)',
    severity: 'critical' },
  { re: /memcached.*version|STAT\s+version\s+\d/i,
    label: 'Memcached stats trong response — SSRF đến Memcached',
    severity: 'high' },
  { re: /Elastic(?:search)?\s+version|"cluster_name"\s*:\s*"/i,
    label: 'Elasticsearch cluster info trong response — internal service exposed',
    severity: 'high' },
  { re: /"kubernetes\.io|kube-system|kubectl|k8s\.io/i,
    label: 'Kubernetes internal resource trong response',
    severity: 'critical' },
  { re: /etcd.*cluster|"etcdserver"/i,
    label: 'etcd cluster data trong response — Kubernetes control plane',
    severity: 'critical' },
  { re: /Connection refused.*(?:127\.|localhost|10\.|192\.168\.)/i,
    label: 'Connection refused đến internal IP — SSRF probe indicator',
    severity: 'medium' },
  { re: /\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b/,
    label: 'RFC1918 private IP address trong response — internal network access',
    severity: 'high' },
];

// ─── 3. URL Parameters (attack surface — không phải confirmation) ─────────────

const SSRF_PARAM_PATTERNS = [
  'url', 'uri', 'link', 'src', 'source', 'dest', 'destination',
  'target', 'redirect', 'next', 'callback', 'return', 'returnUrl',
  'return_url', 'redirect_url', 'redirectUrl', 'fetch', 'load',
  'path', 'file', 'img', 'image', 'proxy', 'forward',
];

function runSsrfHeuristic(context) {
  const text    = context.text    || '';
  const url     = context.finalUrl || '';
  const findings = [];

  // ── 1. Cloud metadata content ──────────────────────────────────────────────
  const allCloudPatterns = [...AWS_METADATA_PATTERNS, ...GCP_METADATA_PATTERNS, ...AZURE_METADATA_PATTERNS];
  const cloudMatches = allCloudPatterns.filter(({ re }) => re.test(text));
  if (cloudMatches.length > 0) {
    const maxSeverity = cloudMatches.some(m => m.severity === 'critical') ? 'critical' : 'high';
    findings.push(normalizeFinding({
      ruleId: 'A10-SSRF-001',
      owaspCategory: 'A10',
      title: 'SSRF xác nhận — Cloud metadata service content bị lộ trong response',
      severity: maxSeverity,
      confidence: 'high',
      target: url,
      location: 'response body',
      evidence: cloudMatches.map(m => `[${m.severity.toUpperCase()}] ${m.label}`),
      remediation:
        'Implement URL allowlist: chỉ cho phép domain/IP được whitelist. ' +
        'Block outbound requests đến: 169.254.169.254, 100.64.0.0/10, 192.168.x.x, 10.x.x.x, 172.16-31.x.x. ' +
        'AWS: dùng IMDSv2 (yêu cầu PUT token trước GET). ' +
        'Không để server fetch URL do user cung cấp mà không validate.',
      references: [
        'https://owasp.org/Top10/2025/A10_2025-Server_Side_Request_Forgery/',
        'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery',
      ],
      collector: 'blackbox',
    }));
  }

  // ── 2. Internal service content ────────────────────────────────────────────
  if (cloudMatches.length === 0) {
    const internalMatches = INTERNAL_SERVICE_PATTERNS.filter(({ re }) => re.test(text));
    if (internalMatches.length > 0) {
      const maxSev = internalMatches.some(m => m.severity === 'critical') ? 'critical' : 'high';
      findings.push(normalizeFinding({
        ruleId: 'A10-SSRF-002',
        owaspCategory: 'A10',
        title: 'Có dấu hiệu SSRF — nội dung internal service trong response',
        severity: maxSev,
        confidence: 'medium',
        target: url,
        location: 'response body',
        evidence: internalMatches.map(m => `[${m.severity.toUpperCase()}] ${m.label}`),
        remediation:
          'Validate và whitelist URL trước khi thực hiện server-side request. ' +
          'Resolve DNS và verify IP không thuộc RFC1918 / loopback / metadata IP range. ' +
          'Chạy outbound request qua egress proxy với allowlist.',
        references: [
          'https://owasp.org/Top10/2025/A10_2025-Server_Side_Request_Forgery/',
          'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
        ],
        collector: 'blackbox',
      }));
    }
  }

  // ── 3. URL parameters là attack surface ───────────────────────────────────
  try {
    const parsed = new URL(url);
    const foundParams = SSRF_PARAM_PATTERNS.filter(p => {
      const v = parsed.searchParams.get(p) || '';
      // Chỉ cảnh báo khi value là URL đầy đủ (http/https/file)
      return /^(?:https?|file|ftp|dict|gopher|sftp):\/\//i.test(v);
    });

    if (foundParams.length > 0) {
      const paramValues = foundParams.map(p => {
        const v = parsed.searchParams.get(p) || '';
        return `?${p}=${v.slice(0, 50)}${v.length > 50 ? '...' : ''}`;
      });
      findings.push(normalizeFinding({
        ruleId: 'A10-SSRF-003',
        owaspCategory: 'A10',
        title: 'URL parameter chứa full URL — attack surface cho SSRF',
        severity: 'medium',
        confidence: 'medium',
        target: url,
        location: `URL parameter: ${foundParams.join(', ')}`,
        evidence: [
          ...paramValues,
          'Parameter nhận URL đầy đủ có thể bị attacker dùng để trỏ vào internal service.',
          'Cần verify: server có thực hiện HTTP request đến URL này không?',
        ],
        remediation:
          'Không nhận URL đầy đủ từ user nếu server sẽ fetch nó. ' +
          'Nếu cần: implement strict allowlist (scheme + hostname + path prefix). ' +
          'Reject: file://, gopher://, dict://, sftp://, internal IPs.',
        references: [
          'https://owasp.org/Top10/2025/A10_2025-Server_Side_Request_Forgery/',
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery',
        ],
        collector: 'blackbox',
      }));
    }
  } catch { /* URL parse failed */ }

  // ── 4. DNS rebinding indicator (request đến domain mà resolve ra internal IP) ──
  const locationHeader = (context.responseHeaders || {})['location'] || '';
  if (locationHeader && /^https?:\/\/(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.|0\.)/i.test(locationHeader)) {
    findings.push(normalizeFinding({
      ruleId: 'A10-SSRF-004',
      owaspCategory: 'A10',
      title: 'Redirect đến internal IP trong Location header — SSRF via open redirect',
      severity: 'high',
      confidence: 'high',
      target: url,
      location: `Location: ${locationHeader.slice(0, 100)}`,
      evidence: [
        `Server redirect đến internal IP: ${locationHeader.slice(0, 100)}`,
        'SSRF via open redirect: attacker dùng redirect để bypass URL validation.',
      ],
      remediation:
        'Validate redirect URL không trỏ đến internal IP sau khi resolve DNS. ' +
        'Block redirect đến RFC1918 và loopback addresses.',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
  }

  return findings;
}

module.exports = { runSsrfHeuristic };

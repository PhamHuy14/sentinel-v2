const { normalizeFinding } = require('../../models/finding');

const A04_REF = 'https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/';
const OTG_CRYPT_003 = 'https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels';

const MAX_BODY_SCAN = 500 * 1024;
const TOKEN_CONTEXT_RE = /(token|auth|authorization|bearer|jwt|session|access|refresh|id[_-]?token|api[_-]?key|secret|password|cookie)/i;
const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
const PAN_RE = /\b(?:\d[ -]*?){13,19}\b/g;

function luhnValid(numberText) {
  const digits = String(numberText || '').replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;

  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let n = parseInt(digits[i], 10);
    if (shouldDouble) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

function hasJwtWithContext(input) {
  const text = String(input || '');
  const match = text.match(JWT_RE);
  if (!match) return false;
  if (TOKEN_CONTEXT_RE.test(text)) return true;
  return /authorization\s*:\s*bearer/i.test(text);
}

function collectBodyLeaks(body) {
  const evidence = [];

  const leakPatterns = [
    { re: /["']password["']\s*:\s*["'][^"']{3,}/i, label: 'Password field xuất hiện trong response body' },
    { re: /["']secret["']\s*:\s*["'][^"']{6,}/i, label: 'Secret field xuất hiện trong response body' },
    { re: /["']api[_-]?key["']\s*:\s*["'][^"']{8,}/i, label: 'API key xuất hiện trong response body' },
    { re: /-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----/i, label: 'Private key marker xuất hiện trong response body' },
  ];

  for (const p of leakPatterns) {
    if (p.re.test(body)) evidence.push(p.label);
  }

  const panCandidates = body.match(PAN_RE) || [];
  const validCards = panCandidates.filter((p) => luhnValid(p));
  if (validCards.length > 0) {
    evidence.push(`Phát hiện ${validCards.length} chuỗi giống số thẻ hợp lệ Luhn`);
  }

  if (hasJwtWithContext(body)) {
    evidence.push('JWT token xuất hiện trong response body với ngữ cảnh xác thực');
  }

  return evidence;
}

function runSensitiveDataA04(context) {
  const findings = [];
  try {
    const finalUrl = context.finalUrl || context.scannedUrl || '';
    const body = String(context.text || '').slice(0, MAX_BODY_SCAN);
    const query = String(context.queryString || '');
    const reqHeaders = context.requestHeaders || {};

    const bodyEvidence = collectBodyLeaks(body);
    if (bodyEvidence.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A04-SENS-001',
        owaspCategory: 'A04',
        title: 'Có dấu hiệu dữ liệu nhạy cảm lộ trong response body',
        severity: 'high',
        confidence: 'high',
        target: finalUrl,
        location: 'response body',
        evidence: bodyEvidence.slice(0, 5),
        remediation: 'Không trả dữ liệu nhạy cảm về client. Mask/loại bỏ secret, token, PAN khỏi response.',
        references: [A04_REF, OTG_CRYPT_003],
        collector: 'blackbox'
      }));
    }

    const queryLeak = query && TOKEN_CONTEXT_RE.test(query) && /[=:%].{4,}/.test(query);
    if (queryLeak) {
      findings.push(normalizeFinding({
        ruleId: 'A04-SENS-002',
        owaspCategory: 'A04',
        title: 'Query string có dấu hiệu chứa dữ liệu nhạy cảm',
        severity: 'medium',
        confidence: 'medium',
        target: finalUrl,
        location: 'request URL query',
        evidence: [query.slice(0, 180)],
        remediation: 'Không truyền token/secret qua query string. Dùng Authorization header hoặc body bảo mật.',
        references: [A04_REF, OTG_CRYPT_003],
        collector: 'blackbox'
      }));
    }

    const headerEvidence = [];
    const authorization = String(reqHeaders.authorization || reqHeaders.Authorization || '');
    if (/^Bearer\s+\S+/i.test(authorization) || /^Basic\s+\S+/i.test(authorization)) {
      headerEvidence.push('Authorization header chứa credentials/token');
    }

    const cookieHeader = String(reqHeaders.cookie || reqHeaders.Cookie || '');
    if (cookieHeader && TOKEN_CONTEXT_RE.test(cookieHeader)) {
      headerEvidence.push('Cookie request chứa thông tin phiên/xác thực nhạy cảm');
    }

    if (headerEvidence.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A04-SENS-003',
        owaspCategory: 'A04',
        title: 'Request headers/cookies chứa dữ liệu nhạy cảm cần bảo vệ kênh truyền',
        severity: 'medium',
        confidence: 'medium',
        target: finalUrl,
        location: 'request headers',
        evidence: headerEvidence,
        remediation: 'Bắt buộc HTTPS end-to-end, hạn chế log headers chứa auth, và xoay vòng token định kỳ.',
        references: [A04_REF, OTG_CRYPT_003],
        collector: 'blackbox'
      }));
    }
  } catch {
    return findings;
  }

  return findings;
}

module.exports = { runSensitiveDataA04, luhnValid };

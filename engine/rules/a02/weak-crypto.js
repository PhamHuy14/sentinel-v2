'use strict';

const { normalizeFinding } = require('../../models/finding');

const A02_REF = 'https://owasp.org/Top10/2025/A02_2025-Cryptographic_Failures/';

function getSourceFiles(context) {
  return [
    ...(context.codeFiles || []),
    ...(context.configFiles || []),
    ...(context.textFiles || []),
  ].filter((file) => file && typeof file.content === 'string');
}

function runWeakCryptoUsage(context) {
  const findings = [];
  const files = getSourceFiles(context);

  const weakHashHits = [];
  const weakCipherHits = [];
  const weakJwtHits = [];
  const weakTlsHits = [];

  for (const file of files) {
    const content = file.content || '';
    const target = file.path || 'project source';

    if (/\b(md5|sha1)\b|createHash\s*\(\s*['"`](md5|sha1)['"`]\s*\)/i.test(content)) {
      weakHashHits.push(target);
    }

    if (/\b(des|3des|rc4|ecb)\b|createCipher(?:iv)?\s*\(\s*['"`](des|des-ede3|rc4|aes-\d+-ecb)/i.test(content)) {
      weakCipherHits.push(target);
    }

    if (/alg(?:orithm)?\s*[:=]\s*['"`](none|HS256)['"`]|jwt\.sign\s*\([^)]*algorithm\s*:\s*['"`]HS256/i.test(content)) {
      weakJwtHits.push(target);
    }

    if (/TLSv1(?:\.0|\.1)?\b|SSLv[23]\b|ssl_protocols[^;\n]*(TLSv1\s|TLSv1\.1|SSLv2|SSLv3)/i.test(content)) {
      weakTlsHits.push(target);
    }
  }

  if (weakHashHits.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A02-CRYPTO-001',
      owaspCategory: 'A02',
      title: 'Có dấu hiệu dùng hashing yếu (MD5/SHA1)',
      severity: 'medium',
      confidence: 'medium',
      target: weakHashHits[0],
      location: 'source/config',
      evidence: weakHashHits.slice(0, 3),
      remediation: 'Không dùng MD5/SHA1 cho mục đích bảo mật. Với password hãy dùng Argon2/bcrypt/scrypt; với integrity hãy dùng SHA-256 trở lên hoặc HMAC phù hợp.',
      references: [A02_REF, 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'],
      collector: 'source',
    }));
  }

  if (weakCipherHits.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A02-CRYPTO-002',
      owaspCategory: 'A02',
      title: 'Có dấu hiệu dùng cipher/mode yếu',
      severity: 'high',
      confidence: 'medium',
      target: weakCipherHits[0],
      location: 'source/config',
      evidence: weakCipherHits.slice(0, 3),
      remediation: 'Loại bỏ DES/3DES/RC4/ECB. Ưu tiên AES-GCM hoặc ChaCha20-Poly1305 với key management rõ ràng.',
      references: [A02_REF, 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'],
      collector: 'source',
    }));
  }

  if (weakJwtHits.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A02-JWT-001',
      owaspCategory: 'A02',
      title: 'JWT có dấu hiệu cấu hình thuật toán yếu',
      severity: 'high',
      confidence: 'medium',
      target: weakJwtHits[0],
      location: 'source/config',
      evidence: weakJwtHits.slice(0, 3),
      remediation: 'Không cho phép alg=none. Với HS256 cần secret đủ mạnh và quản lý rotation; ưu tiên allowlist thuật toán và verify issuer/audience/expiry.',
      references: [A02_REF, 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html'],
      collector: 'source',
    }));
  }

  if (weakTlsHits.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A02-TLS-005',
      owaspCategory: 'A02',
      title: 'Cấu hình cho phép TLS/SSL lỗi thời',
      severity: 'high',
      confidence: 'medium',
      target: weakTlsHits[0],
      location: 'source/config',
      evidence: weakTlsHits.slice(0, 3),
      remediation: 'Chỉ cho phép TLS 1.2/1.3. Tắt SSLv2/SSLv3/TLS 1.0/TLS 1.1 trong reverse proxy, server hoặc runtime config.',
      references: [A02_REF, 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'],
      collector: 'source',
    }));
  }

  return findings;
}

module.exports = { runWeakCryptoUsage };

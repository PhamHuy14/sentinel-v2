/**
 * Chỉ mục quy tắc A02 — Cryptographic Failures.
 *
 * FIX BUG 2a: runAllA02Rules thiếu logic deduplication → duplicate findings khi
 *   runLegacyCryptoA02Rules remap A04-COOKIE-00x → A02-COOKIE-00x trùng với
 *   ruleId đã có từ cookie-flags.js (A02-COOKIE-001..006).
 *
 * FIX BUG 2b: runLegacyCryptoA02Rules gọi runCookieSecurityA04 và runHstsAndWebsocketA04.
 *   Sau remap chúng sinh ra A02-COOKIE-00x và A02-TRANSPORT-00x TRÙNG với
 *   cookie-flags.js và transport-security.js đã chạy ở trên.
 *   Giải pháp: loại bỏ runCookieSecurityA04 + runHstsAndWebsocketA04 khỏi
 *   runLegacyCryptoA02Rules vì chức năng đã được bao phủ bởi các rule A02 native.
 *   Chỉ giữ runTransportSecurityA04 (phát hiện HTTP không mã hóa) và
 *   runSensitiveDataA04 (phát hiện PII/secrets trong response) vì hai rule này
 *   có ruleId A04-TRANSPORT-001 và A04-SENSITIVE-* không trùng với A02 native.
 */

'use strict';

const { runMissingSecurityHeaders } = require('./missing-security-headers');
const { runCookieFlags } = require('./cookie-flags');
const { runCorsMisconfig } = require('./cors-misconfig');
const { runDangerousMethods } = require('./dangerous-methods');
const { runDebugExposure } = require('./debug-exposure');
const { runServerHeaderExposure } = require('./server-header-exposure');
const { runTransportSecurity } = require('./transport-security');
const { runSensitiveFileExposure } = require('./sensitive-file-exposure');
const { runWeakCryptoUsage } = require('./weak-crypto');
const { remapFindings } = require('../remap-finding');
const { runTransportSecurityA04 } = require('../a04/transport-security');
// FIX: Bỏ runCookieSecurityA04 và runHstsAndWebsocketA04 khỏi legacy remap
// vì sau remap chúng tạo ruleId A02-COOKIE-00x và A02-HSTS-00x trùng với native rules.
// runSensitiveDataA04 được giữ lại — ruleId A04-SENSITIVE-* không trùng.
const { runSensitiveDataA04 } = require('../a04/sensitive-data');

const A02_REF = 'https://owasp.org/Top10/2025/A02_2025-Cryptographic_Failures/';

/**
 * Chỉ remap các rule A04 không bị trùng ruleId với A02 native:
 *  - runTransportSecurityA04: A04-TRANSPORT-001 → A02-TRANSPORT-001 (không trùng)
 *  - runSensitiveDataA04:     A04-SENSITIVE-*   → A02-SENSITIVE-*   (không trùng)
 *
 * ĐÃ LOẠI BỎ (gây trùng lặp):
 *  - runCookieSecurityA04:    A04-COOKIE-00x → A02-COOKIE-00x ← TRÙNG cookie-flags.js
 *  - runHstsAndWebsocketA04:  A04-HSTS-00x   → A02-HSTS-00x   ← TRÙNG missing-security-headers.js
 */
function runLegacyCryptoA02Rules(context) {
  const findings = [
    ...runTransportSecurityA04(context),
    ...runSensitiveDataA04(context),
  ];
  return remapFindings(findings, {
    fromCategory: 'A04',
    toCategory: 'A02',
    top10Url: A02_REF,
  });
}

/**
 * Chạy toàn bộ quy tắc A02 với deduplication.
 * FIX: Bổ bổ sung dedup theo key = ruleId::target (giống pattern của A01/A03/A05/A06/A07/A08/A09/A10).
 */
function runAllA02Rules(context) {
  const rawFindings = [
    ...runMissingSecurityHeaders(context),
    ...runCookieFlags(context),
    ...runCorsMisconfig(context),
    ...runDangerousMethods(context),
    ...runDebugExposure(context),
    ...runServerHeaderExposure(context),
    ...runTransportSecurity(context),
    ...runSensitiveFileExposure(context),
    ...runWeakCryptoUsage(context),
    ...runLegacyCryptoA02Rules(context),
  ];

  // Deduplication theo ruleId + target (nhất quán với tất cả các index khác)
  const seenKeys = new Set();
  const findings = [];
  for (const finding of rawFindings) {
    const key = `${finding.ruleId}::${finding.target}`;
    if (!seenKeys.has(key)) {
      seenKeys.add(key);
      findings.push(finding);
    }
  }

  return findings;
}

module.exports = {
  runAllA02Rules,
  runMissingSecurityHeaders,
  runCookieFlags,
  runCorsMisconfig,
  runDangerousMethods,
  runDebugExposure,
  runServerHeaderExposure,
  runTransportSecurity,
  runSensitiveFileExposure,
  runWeakCryptoUsage,
  runLegacyCryptoA02Rules,
};

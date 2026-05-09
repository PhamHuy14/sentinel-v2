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
const { runCookieSecurityA04 } = require('../a04/cookie-security');
const { runHstsAndWebsocketA04 } = require('../a04/hsts-websocket');
const { runSensitiveDataA04 } = require('../a04/sensitive-data');

const A02_REF = 'https://owasp.org/Top10/2025/A02_2025-Cryptographic_Failures/';

function runLegacyCryptoA02Rules(context) {
  const findings = [
    ...runTransportSecurityA04(context),
    ...runCookieSecurityA04(context),
    ...runHstsAndWebsocketA04(context),
    ...runSensitiveDataA04(context),
  ];
  return remapFindings(findings, {
    fromCategory: 'A04',
    toCategory: 'A02',
    top10Url: A02_REF,
  });
}

function runAllA02Rules(context) {
  const findings = [
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

/**
 * engine/rules/a04/crypto-failures.js
 *
 * Backward-compatibility shim for A04 – Cryptographic Failures.
 *
 * History:
 *   Before the A04 refactor, all cryptographic-failure checks lived in a
 *   single "crypto-failures" module exported as `runCryptoFailures(context)`.
 *   After the refactor the logic was split into four focused sub-modules:
 *     • transport-security.js  → runTransportSecurityA04
 *     • hsts-websocket.js      → runHstsAndWebsocketA04
 *     • cookie-security.js     → runCookieSecurityA04
 *     • sensitive-data.js      → runSensitiveDataA04
 *   and composed by index.js → runA04Rules.
 *
 * This file provides zero-duplication re-exports so that any existing caller
 * that imports from "crypto-failures" continues to work without modification.
 *
 * IMPORTANT: Do NOT add logic here – all business logic lives in the
 *            sub-modules above.
 */

'use strict';

const {
  runTransportSecurityA04,
} = require('./transport-security');

const {
  runHstsAndWebsocketA04,
} = require('./hsts-websocket');

const {
  runCookieSecurityA04,
} = require('./cookie-security');

const {
  runSensitiveDataA04,
  luhnValid,
} = require('./sensitive-data');

const {
  remapFindings,
} = require('../remap-finding');

const A02_REF = 'https://owasp.org/Top10/2025/A02_2025-Cryptographic_Failures/';

/**
 * Legacy entry-point alias.
 * Identical to runA04Rules – runs all A04 sub-rules against `context` and
 * returns a combined array of normalised findings.
 *
 * @param {object} context  Scan context (see engine/models/finding.js)
 * @returns {import('../../models/finding').NormalisedFinding[]}
 */
function runCryptoFailures(context) {
  const findings = [
    ...runTransportSecurityA04(context),
    ...runHstsAndWebsocketA04(context),
    ...runCookieSecurityA04(context),
    ...runSensitiveDataA04(context),
  ];

  return remapFindings(findings, {
    fromCategory: 'A04',
    toCategory: 'A02',
    top10Url: A02_REF,
  });
}

module.exports = {
  // ── Legacy name (backward-compat) ─────────────────────────────────────────
  runCryptoFailures,

  // ── Current public API (re-exported for consumers that want sub-runners) ──
  runTransportSecurityA04,
  runHstsAndWebsocketA04,
  runCookieSecurityA04,
  runSensitiveDataA04,

  // ── Utility helpers ────────────────────────────────────────────────────────
  luhnValid,
};

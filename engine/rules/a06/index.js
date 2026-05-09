/**
 * Chỉ mục quy tắc A06 — Vulnerable & Outdated Components.
 *
 * Lưu ý: các implementation dependency/outdated hiện vẫn nằm trong thư mục a03
 * để giữ tương thích import cũ. Index này remap output về đúng OWASP 2025 A06.
 */

'use strict';

const { runNpmDependencyRisk } = require('../a03/npm-dependency-risk');
const { runNugetDependencyRisk } = require('../a03/nuget-dependency-risk');
const { runDotnetFrameworkVersionRisk } = require('../a03/dotnet-framework-version-risk');
const { runNodeEngineVersionRisk } = require('../a03/node-engine-version-risk');
const { runSensitiveFileExposureRisk } = require('../a03/sensitive-file-exposure-risk');
const { runPackageLockConsistency, runTyposquattingRisk } = require('../source-enhanced/supply-chain-enhanced');
const { remapFindings } = require('../remap-finding');

const A06_REF = 'https://owasp.org/Top10/2025/A06_2025-Vulnerable_and_Outdated_Components/';

const ALL_A06_RULES = [
  { fn: runNpmDependencyRisk,            name: 'NpmDependencyRisk' },
  { fn: runNugetDependencyRisk,          name: 'NugetDependencyRisk' },
  { fn: runDotnetFrameworkVersionRisk,   name: 'DotnetFrameworkVersionRisk' },
  { fn: runNodeEngineVersionRisk,        name: 'NodeEngineVersionRisk' },
  { fn: runSensitiveFileExposureRisk,    name: 'SensitiveFileExposureRisk' },
  { fn: runPackageLockConsistency,       name: 'PackageLockConsistency' },
  { fn: runTyposquattingRisk,            name: 'TyposquattingRisk' },
];

function runAllA06Rules(context) {
  const allFindings = [];
  const seenKeys = new Set();

  for (const { fn, name } of ALL_A06_RULES) {
    try {
      const results = remapFindings(fn(context) || [], {
        fromCategory: 'A03',
        toCategory: 'A06',
        top10Url: A06_REF,
      });

      for (const finding of results) {
        const key = `${finding.ruleId}::${finding.target}`;
        if (!seenKeys.has(key)) {
          seenKeys.add(key);
          allFindings.push(finding);
        }
      }
    } catch (err) {
      if (process.env.DEBUG_RULES) {
        console.error(`[A06 Rules] Error in ${name}:`, err.message);
      }
    }
  }

  return allFindings;
}

module.exports = {
  runAllA06Rules,
  runNpmDependencyRisk,
  runNugetDependencyRisk,
  runDotnetFrameworkVersionRisk,
  runNodeEngineVersionRisk,
  runSensitiveFileExposureRisk,
  runPackageLockConsistency,
  runTyposquattingRisk,
};

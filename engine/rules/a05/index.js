/**
 * Chỉ mục quy tắc A05 — Security Misconfiguration.
 *
 * Lưu ý: các implementation misconfiguration hiện vẫn nằm trong thư mục a06
 * để giữ tương thích import cũ. Index này remap output về đúng OWASP 2025 A05.
 */

'use strict';

const { runDefaultPageCheck } = require('../a06/default-page-check');
const { runDirectoryListingCheck } = require('../a06/directory-listing-check');
const { runGraphqlIntrospectionCheck, runApiMisconfigCheck } = require('../a06/api-misconfig');
const { runFrameworkDisclosureCheck } = require('../a06/framework-version-disclosure');
const { remapFindings } = require('../remap-finding');

const A05_REF = 'https://owasp.org/Top10/2025/A05_2025-Security_Misconfiguration/';

const ALL_A05_RULES = [
  { fn: runDefaultPageCheck,          name: 'DefaultPage' },
  { fn: runDirectoryListingCheck,     name: 'DirectoryListing' },
  { fn: runGraphqlIntrospectionCheck, name: 'GraphQL-Introspection' },
  { fn: runApiMisconfigCheck,         name: 'API-Misconfig' },
  { fn: runFrameworkDisclosureCheck,  name: 'FrameworkDisclosure' },
];

function runAllA05Rules(context) {
  const allFindings = [];
  const seenKeys = new Set();

  for (const { fn, name } of ALL_A05_RULES) {
    try {
      const results = remapFindings(fn(context) || [], {
        fromCategory: 'A06',
        toCategory: 'A05',
        top10Url: A05_REF,
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
        console.error(`[A05 Rules] Error in ${name}:`, err.message);
      }
    }
  }

  return allFindings;
}

module.exports = {
  runAllA05Rules,
  runDefaultPageCheck,
  runDirectoryListingCheck,
  runGraphqlIntrospectionCheck,
  runApiMisconfigCheck,
  runFrameworkDisclosureCheck,
};

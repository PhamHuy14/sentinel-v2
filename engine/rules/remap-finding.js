'use strict';

function remapReferences(references, replacementTop10Url) {
  if (!Array.isArray(references)) return references;
  return references.map((ref) => {
    if (typeof ref === 'string' && /owasp\.org\/Top10\/2025\/A\d{2}_2025-/i.test(ref)) {
      return replacementTop10Url;
    }
    return ref;
  });
}

function remapFinding(finding, { fromCategory, toCategory, top10Url }) {
  if (!finding || !toCategory) return finding;

  const next = {
    ...finding,
    owaspCategory: toCategory,
  };

  if (fromCategory && typeof next.ruleId === 'string' && next.ruleId.startsWith(`${fromCategory}-`)) {
    next.ruleId = `${toCategory}-${next.ruleId.slice(fromCategory.length + 1)}`;
  }

  if (top10Url) {
    next.references = remapReferences(next.references, top10Url);
  }

  return next;
}

function remapFindings(findings, options) {
  return (findings || []).map((finding) => remapFinding(finding, options));
}

module.exports = {
  remapFinding,
  remapFindings,
};

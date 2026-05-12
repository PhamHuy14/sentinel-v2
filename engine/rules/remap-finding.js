'use strict';

/**
 * Tiện ích remap finding từ một OWASP category sang category khác.
 *
 * FIX BUG 4: Cập nhật regex trong remapReferences để nhận diện cả URL OWASP 2021
 *   lẫn 2025. Trước đây regex chỉ match:
 *     owasp.org/Top10/2025/A\d{2}_2025-
 *   → Các rule còn dùng URL OWASP 2021 (A\d{2}_2021-) sẽ không được thay thế
 *     khi remap, dẫn đến references trỏ sai category URL sau khi đổi owaspCategory.
 *
 *   Pattern mới match cả hai format:
 *     owasp.org/Top10/20xx/A\d{2}_20xx-
 */

function remapReferences(references, replacementTop10Url) {
  if (!Array.isArray(references)) return references;
  return references.map((ref) => {
    // FIX: Mở rộng regex để match OWASP 2021 lẫn 2025 (và các năm tương lai)
    if (typeof ref === 'string' && /owasp\.org\/Top10\/20\d{2}\/A\d{2}_20\d{2}-/i.test(ref)) {
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

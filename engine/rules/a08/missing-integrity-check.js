const { normalizeFinding } = require('../../models/finding');

function runMissingIntegrityCheck(context) {
  const findings = [];
  for (const file of context.configFiles || []) {
    if (/index\.html|\.cshtml|\.html$/i.test(file.path)) {
      const externalScripts = [...file.content.matchAll(/<script[^>]+src=["']https?:\/\/[^"']+["'][^>]*>/gi)];
      for (const script of externalScripts) {
        if (!/integrity=/i.test(script[0])) {
          findings.push(normalizeFinding({
            ruleId: 'A08-INTEGRITY-001',
            owaspCategory: 'A08',
            title: 'Script ngoài không có integrity attribute',
            severity: 'medium',
            confidence: 'medium',
            target: file.path,
            location: 'external script tag',
            evidence: [script[0].slice(0, 180)],
            remediation: 'Thêm Subresource Integrity hoặc tự host asset tin cậy.',
            references: ['https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/'],
            collector: 'source'
          }));
        }
      }
    }
  }
  return findings;
}

module.exports = { runMissingIntegrityCheck };

const { normalizeFinding } = require('../../models/finding');

function runUntrustedConfigData(context) {
  const findings = [];
  for (const file of context.textFiles || []) {
    if (/yaml|yml|json|env|config/i.test(file.path) && /eval\(|new Function\(|DynamicInvoke/i.test(file.content)) {
      findings.push(normalizeFinding({
        ruleId: 'A08-CONFIG-001',
        owaspCategory: 'A08',
        title: 'Có dấu hiệu thực thi dữ liệu/config không tin cậy',
        severity: 'high',
        confidence: 'low',
        target: file.path,
        location: 'file content',
        evidence: ['Tìm thấy chuỗi giống cơ chế thực thi động gần vùng config/data.'],
        remediation: 'Tránh thực thi dữ liệu cấu hình; xác thực và ràng buộc format dữ liệu rõ ràng.',
        references: ['https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/'],
        collector: 'source'
      }));
    }
  }
  return findings;
}

module.exports = { runUntrustedConfigData };

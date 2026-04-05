const { normalizeFinding } = require('../../models/finding');

function runAlertingCheck(context) {
  const corpus = (context.codeFiles || []).map((f) => `${f?.path || ''}\n${f?.content || ''}`).join('\n');
  const hasMonitoring = /serilog|splunk|elastic|opentelemetry|application insights|seq|sentry|pagerduty|alert/i.test(corpus);
  if (!hasMonitoring) {
    return [normalizeFinding({
      ruleId: 'A09-ALERT-001',
      owaspCategory: 'A09',
      title: 'Chưa thấy dấu hiệu tích hợp alerting/monitoring rõ ràng trong source mẫu',
      severity: 'low',
      confidence: 'low',
      target: 'project source',
      location: 'codebase/config',
      evidence: ['Không thấy pattern alerting/monitoring phổ biến trong tập file đã quét.'],
      remediation: 'Bổ sung monitoring và alerting cho sự kiện bảo mật quan trọng.',
      references: ['https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/'],
      collector: 'source'
    })];
  }
  return [];
}

module.exports = { runAlertingCheck };

function normalizeFinding(partial = {}) {
  return {
    ruleId: partial.ruleId || 'UNKNOWN',
    owaspCategory: partial.owaspCategory || 'A00',
    title: partial.title || 'Finding không xác định',
    severity: partial.severity || 'low',
    confidence: partial.confidence || 'medium',
    target: partial.target || '',
    location: partial.location || '',
    evidence: Array.isArray(partial.evidence) ? partial.evidence : [String(partial.evidence || '')].filter(Boolean),
    remediation: partial.remediation || '',
    remediationPlan: partial.remediationPlan && typeof partial.remediationPlan === 'object' ? partial.remediationPlan : null,
    references: Array.isArray(partial.references) ? partial.references : [partial.references].filter(Boolean),
    collector: partial.collector || 'không rõ'
  };
}

module.exports = { normalizeFinding };

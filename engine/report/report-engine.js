function summarizeFindings(findings = []) {
  const summary = { total: findings.length, byCategory: {}, bySeverity: {} };
  for (const finding of findings) {
    summary.byCategory[finding.owaspCategory] = (summary.byCategory[finding.owaspCategory] || 0) + 1;
    summary.bySeverity[finding.severity] = (summary.bySeverity[finding.severity] || 0) + 1;
  }
  return summary;
}

function escapeHtml(text) {
  return String(text ?? '')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}

function buildJsonReport(scanResult = {}) {
  return JSON.stringify(scanResult, null, 2);
}

function buildHtmlReport(scanResult = {}) {
  const findings = scanResult.findings || [];
  const summary = scanResult.metadata?.summary || summarizeFindings(findings);
  const authSummary = scanResult.metadata?.auth || null;
  const findingCards = findings.map((finding) => `
    <article class="finding sev-${escapeHtml(finding.severity)}">
      <div class="topline">${escapeHtml(finding.ruleId)} • ${escapeHtml(finding.owaspCategory)} • ${escapeHtml(finding.severity.toUpperCase())} • Confidence: ${escapeHtml(finding.confidence)}</div>
      <h3>${escapeHtml(finding.title)}</h3>
      <div class="meta">Target: ${escapeHtml(finding.target)}${finding.location ? ` • ${escapeHtml(finding.location)}` : ''} • Collector: ${escapeHtml(finding.collector)}</div>
      <ul>${(finding.evidence || []).map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>
      <p><strong>Khắc phục:</strong> ${escapeHtml(finding.remediation || '')}</p>
    </article>
  `).join('');

  return `<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SENTINEL — OWASP 2025 Report</title>
  <style>
    body { font-family: Inter, Segoe UI, Arial, sans-serif; margin: 0; background: #0b1020; color: #eef3ff; }
    .wrap { max-width: 1120px; margin: 0 auto; padding: 32px; }
    .hero, .panel, .finding { background: #121a31; border: 1px solid #253251; border-radius: 18px; padding: 20px; margin-bottom: 18px; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
    h1, h2, h3 { margin-top: 0; }
    .muted, .meta { color: #a6b1cc; }
    .topline { color: #7aa2ff; font-size: 12px; margin-bottom: 8px; }
    .sev-critical, .sev-high { border-left: 4px solid #ff9aa6; }
    .sev-medium { border-left: 4px solid #ffdd6e; }
    .sev-low { border-left: 4px solid #96f0b5; }
    code, pre { background: #0c1325; padding: 3px 6px; border-radius: 8px; }
    ul { line-height: 1.6; }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>SENTINEL — OWASP 2025 Report</h1>
      <p class="muted">Mode: ${escapeHtml(scanResult.mode || 'unknown')} • Generated: ${escapeHtml(new Date().toISOString())}</p>
      <p><strong>Target:</strong> ${escapeHtml(scanResult.scannedUrl || scanResult.target || '')}</p>
      ${scanResult.finalUrl ? `<p><strong>Final URL:</strong> ${escapeHtml(scanResult.finalUrl)}</p>` : ''}
      ${typeof scanResult.status !== 'undefined' ? `<p><strong>Status:</strong> ${escapeHtml(String(scanResult.status))}</p>` : ''}
      ${scanResult.title ? `<p><strong>Title:</strong> ${escapeHtml(scanResult.title)}</p>` : ''}
      ${authSummary ? `<p><strong>Auth used:</strong> cookie=${authSummary.hasCookie ? 'yes' : 'no'}, bearer=${authSummary.hasBearerToken ? 'yes' : 'no'}</p>` : ''}
    </section>
    <section class="grid">
      <div class="panel"><h2>Summary by Category</h2><pre>${escapeHtml(JSON.stringify(summary.byCategory, null, 2))}</pre></div>
      <div class="panel"><h2>Summary by Severity</h2><pre>${escapeHtml(JSON.stringify(summary.bySeverity, null, 2))}</pre></div>
    </section>
    <section class="panel"><h2>Metadata</h2><pre>${escapeHtml(JSON.stringify(scanResult.metadata || {}, null, 2))}</pre></section>
    <section>
      <h2>Findings (${findings.length})</h2>
      ${findingCards || '<div class="panel">Không có finding nào.</div>'}
    </section>
  </div>
</body>
</html>`;
}

function getSuggestedFilename(scanResult = {}, format = 'html') {
  const base = scanResult.mode === 'project-scan' ? 'owasp-project-scan' : 'owasp-url-scan';
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  return `${base}-${stamp}.${format}`;
}

module.exports = { summarizeFindings, buildJsonReport, buildHtmlReport, getSuggestedFilename };

import { useStore } from '../store/useStore';
import { ReportExportButton } from './ReportExportButton';
import { Finding } from '../types';

const severityColor = (sev: string) => {
  switch (sev) {
    case 'critical': return 'badge-critical';
    case 'high': return 'badge-high';
    case 'medium': return 'badge-medium';
    default: return 'badge-low';
  }
};

export const FindingsList: React.FC = () => {
  const { urlScanResult, projectScanResult, activeTab, error, isLoading } = useStore();
  const scanResult = activeTab === 'url' ? urlScanResult : projectScanResult;

  if (isLoading) {
    return (
      <div className="card findings-panel">
        <div className="loading-spinner"></div>
        <p>Scanning in progress...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card findings-panel error-panel">
        <h3>⚠️ Scan Error</h3>
        <p>{error}</p>
      </div>
    );
  }

  if (!scanResult) {
    return (
      <div className="card findings-panel empty-panel">
        <p>✨ No scan performed yet. Use the form above to start a security assessment.</p>
      </div>
    );
  }

  const { findings, metadata, mode, target } = scanResult;
  const summary = metadata.summary;

  return (
    <div className="card findings-panel">
      <div className="findings-header">
        <h3>🔎 Scan Results</h3>
        <ReportExportButton />
      </div>
      <div className="scan-info">
        <p><strong>Mode:</strong> {mode === 'url-scan' ? 'URL Scan' : 'Project Scan'}</p>
        <p><strong>Target:</strong> {target || scanResult.scannedUrl}</p>
        {scanResult.finalUrl && <p><strong>Final URL:</strong> {scanResult.finalUrl}</p>}
        {scanResult.status && <p><strong>HTTP Status:</strong> {scanResult.status}</p>}
        {scanResult.title && <p><strong>Page Title:</strong> {scanResult.title}</p>}
      </div>

      <div className="summary-stats">
        <div className="stat">Total Findings: <strong>{summary.total}</strong></div>
        <div className="stat-categories">
          {Object.entries(summary.bySeverity).map(([sev, count]) => (
            <span key={sev} className={`stat-badge ${severityColor(sev)}`}>
              {sev}: {count}
            </span>
          ))}
        </div>
      </div>

      {findings.length === 0 ? (
        <p className="no-findings">✅ No security issues detected (based on heuristics).</p>
      ) : (
        <div className="findings-list">
          {findings.map((finding: Finding, idx: number) => (
            <div key={idx} className={`finding-item ${severityColor(finding.severity)}`}>
              <div className="finding-title">
                <span className={`severity-dot ${severityColor(finding.severity)}`}></span>
                <strong>{finding.title}</strong>
                <span className="rule-id">{finding.ruleId}</span>
              </div>
              <div className="finding-meta">
                <span>OWASP: {finding.owaspCategory}</span>
                <span>Confidence: {finding.confidence}</span>
                <span>Collector: {finding.collector}</span>
              </div>
              <div className="finding-location">📍 {finding.location || finding.target}</div>
              {finding.evidence.length > 0 && (
                <div className="finding-evidence">
                  <strong>Evidence:</strong>
                  <ul>
                    {finding.evidence.slice(0, 3).map((e: string, i: number) => <li key={i}>{e}</li>)}
                  </ul>
                </div>
              )}
              <div className="finding-remediation">
                <strong>Remediation:</strong> {finding.remediation}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

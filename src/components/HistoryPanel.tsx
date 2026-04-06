import React from 'react';
import { useStore } from '../store/useStore';

function timeAgo(ts: number): string {
  const m = Math.floor((Date.now() - ts) / 60000);
  if (m < 1)  return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function riskScoreColor(score?: number): string {
  if (!score) return 'var(--text-3)';
  if (score >= 70) return 'var(--crit)';
  if (score >= 40) return 'var(--high)';
  if (score >= 15) return 'var(--med)';
  return 'var(--low)';
}

export const HistoryPanel: React.FC = () => {
  const { history, restoreFromHistory, clearHistory, setShowHistoryDropdown } = useStore();

  return (
    <>
      {/* Click-away backdrop */}
      <div className="hist-backdrop" onClick={() => setShowHistoryDropdown(false)} />

      <div className="hist-dropdown">
        <div className="hist-hdr">
          <span className="hist-hdr-title">Scan History</span>
          <div className="hist-hdr-actions" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {history.length > 0 && (
              <button
                className="btn-history-clear"
                onClick={() => { if (window.confirm('Xoá toàn bộ lịch sử scan?')) clearHistory(); }}
                title="Xoá toàn bộ lịch sử — không thể hoàn tác"
                aria-label="Clear all history"
              >
                <span className="btn-history-clear-icon">🗑</span>
                <span>Clear All</span>
              </button>
            )}
            <button
              className="btn-history-close"
              onClick={() => setShowHistoryDropdown(false)}
              title="Đóng panel lịch sử"
              aria-label="Close history panel"
            >
              ✕
            </button>
          </div>
        </div>

        {history.length === 0 ? (
          <div className="hist-empty">
            <div style={{ fontSize: 24, opacity: 0.3, marginBottom: 6 }}>🕐</div>
            <div>No scan history yet</div>
            <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 4 }}>
              Completed scans will appear here
            </div>
          </div>
        ) : (
          <div className="hist-list">
            {history.map((entry) => {
              const { bySeverity, total } = entry.summary;
              return (
                <button
                  key={entry.id}
                  className="hist-entry"
                  onClick={() => restoreFromHistory(entry.id)}
                  title={`Restore: ${entry.target}`}
                >
                  <div className="hist-entry-top">
                    <span className="hist-entry-mode" title={entry.mode === 'url-scan' ? 'URL Scan' : 'Project Scan'}>
                      {entry.mode === 'url-scan' ? '🌐' : '📁'}
                    </span>
                    <span className="hist-entry-target">{entry.target}</span>
                    <span className="hist-entry-time">{timeAgo(entry.ts)}</span>
                  </div>
                  <div className="hist-entry-bottom">
                    <div className="hist-entry-chips">
                      {(bySeverity.critical || 0) > 0 && <span className="sev-chip chip-crit">{bySeverity.critical} CRIT</span>}
                      {(bySeverity.high     || 0) > 0 && <span className="sev-chip chip-high">{bySeverity.high} HIGH</span>}
                      {(bySeverity.medium   || 0) > 0 && <span className="sev-chip chip-med">{bySeverity.medium} MED</span>}
                      {(bySeverity.low      || 0) > 0 && <span className="sev-chip chip-low">{bySeverity.low} LOW</span>}
                      {total === 0 && <span className="sev-chip chip-info">Clean ✓</span>}
                    </div>
                    {entry.riskScore !== undefined && (
                      <div
                        className="hist-risk-score"
                        style={{ color: riskScoreColor(entry.riskScore) }}
                        title={`Risk score: ${entry.riskScore}/100`}
                      >
                        Risk {entry.riskScore}
                      </div>
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        )}

        {history.length > 0 && (
          <div style={{
            padding: '8px 14px',
            borderTop: '1px solid var(--border-dim)',
            fontSize: 10,
            color: 'var(--text-3)',
            textAlign: 'center',
            fontFamily: 'var(--mono)',
          }}>
            {history.length}/10 entries · Click to restore
          </div>
        )}
      </div>
    </>
  );
};
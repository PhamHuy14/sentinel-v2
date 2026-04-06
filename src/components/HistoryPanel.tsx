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
          <div
            className="hist-hdr-actions"
            style={{ display: 'flex', gap: 8, alignItems: 'center' }}
          >
            {history.length > 0 && (
              <button
                className="btn-history-clear"
                onClick={clearHistory}
                title="Delete all history entries"
              >
                <span className="btn-history-clear-icon">🗑</span>
                <span>Clear All</span>
              </button>
            )}
            <button
              className="btn-history-close"
              onClick={() => setShowHistoryDropdown(false)}
              title="Close history panel"
              aria-label="Close"
            >
              ✕
            </button>
          </div>
        </div>

        {history.length === 0 ? (
          <div className="hist-empty">No scan history yet</div>
        ) : (
          <div className="hist-list">
            {history.map((entry) => {
              const { bySeverity, total } = entry.summary;
              return (
                <button key={entry.id} className="hist-entry" onClick={() => restoreFromHistory(entry.id)}>
                  <div className="hist-entry-top">
                    <span className="hist-entry-mode">{entry.mode === 'url-scan' ? '🌐' : '📁'}</span>
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

                    {/* Risk score trend indicator */}
                    {entry.riskScore !== undefined && (
                      <div className="hist-risk-score" style={{ color: riskScoreColor(entry.riskScore) }}>
                        Risk {entry.riskScore}
                      </div>
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </>
  );
};

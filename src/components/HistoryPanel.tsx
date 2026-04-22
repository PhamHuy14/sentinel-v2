import React, { useMemo, useState } from 'react';
import { useStore } from '../store/useStore';

function timeAgo(ts: number): string {
  const m = Math.floor((Date.now() - ts) / 60000);
  if (m < 1)  return 'vừa xong';
  if (m < 60) return `${m} phút trước`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} giờ trước`;
  return `${Math.floor(h / 24)} ngày trước`;
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
  const [query, setQuery] = useState('');
  const [modeFilter, setModeFilter] = useState<'all' | 'url-scan' | 'project-scan'>('all');

  const visibleHistory = useMemo(() => {
    return history.filter((entry) => {
      const byMode = modeFilter === 'all' || entry.mode === modeFilter;
      const byText =
        query.trim().length === 0 ||
        entry.target.toLowerCase().includes(query.toLowerCase()) ||
        entry.mode.toLowerCase().includes(query.toLowerCase());
      return byMode && byText;
    });
  }, [history, modeFilter, query]);

  return (
    <>
      {/* Lớp nền để đóng dropdown khi bấm ra ngoài */}
      <div className="hist-backdrop" onClick={() => setShowHistoryDropdown(false)} />

      <div className="hist-dropdown">
        <div className="hist-hdr">
          <span className="hist-hdr-title">Lịch sử quét</span>
          <div className="hist-hdr-actions" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {history.length > 0 && (
              <button
                className="btn-history-clear"
                onClick={() => { if (window.confirm('Xoá toàn bộ lịch sử scan?')) clearHistory(); }}
                title="Xoá toàn bộ lịch sử — không thể hoàn tác"
                aria-label="Xóa toàn bộ lịch sử"
              >
                <span className="btn-history-clear-icon">🗑</span>
                <span>Xóa tất cả</span>
              </button>
            )}
            <button
              className="btn-history-close"
              onClick={() => setShowHistoryDropdown(false)}
              title="Đóng panel lịch sử"
              aria-label="Đóng panel lịch sử"
            >
              ✕
            </button>
          </div>
        </div>

        <div className="hist-tools">
          <input
            className="hist-search"
            type="text"
            placeholder="Tìm mục tiêu scan..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <select
            className="hist-filter"
            value={modeFilter}
            onChange={(e) => setModeFilter(e.target.value as 'all' | 'url-scan' | 'project-scan')}
          >
            <option value="all">Tất cả</option>
            <option value="url-scan">URL Scan</option>
            <option value="project-scan">Project Scan</option>
          </select>
        </div>

        {history.length === 0 ? (
          <div className="hist-empty">
            <div style={{ fontSize: 24, opacity: 0.3, marginBottom: 6 }}>🕐</div>
            <div>Chưa có lịch sử quét</div>
            <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 4 }}>
              Các lần quét hoàn tất sẽ xuất hiện tại đây
            </div>
          </div>
        ) : (
          <div className="hist-list">
            {visibleHistory.map((entry) => {
              const { bySeverity, total } = entry.summary;
              return (
                <button
                  key={entry.id}
                  className="hist-entry"
                  onClick={() => restoreFromHistory(entry.id)}
                  title={`Khôi phục: ${entry.target}`}
                >
                  <div className="hist-entry-top">
                    <span className="hist-entry-mode" title={entry.mode === 'url-scan' ? 'Quét URL' : 'Quét dự án'}>
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
                      {total === 0 && <span className="sev-chip chip-info">Sạch ✓</span>}
                    </div>
                    {entry.riskScore !== undefined && (
                      <div
                        className="hist-risk-score"
                        style={{ color: riskScoreColor(entry.riskScore) }}
                        title={`Điểm rủi ro: ${entry.riskScore}/100`}
                      >
                        Rủi ro {entry.riskScore}
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
            {visibleHistory.length}/{history.length} mục · Nhấn để khôi phục
          </div>
        )}
      </div>
    </>
  );
};
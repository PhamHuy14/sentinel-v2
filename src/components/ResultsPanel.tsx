import React, { useEffect, useState } from 'react';
import { useAIStore } from '../store/useAIStore';
import { useStore } from '../store/useStore';
import { Finding } from '../types';
import { formatOwaspCategory } from '../utils/owasp';
import { ReportExportButton } from './ReportExportButton';
import { RiskDashboard } from './RiskDashboard';

const confClass = (c: string) => c === 'high' ? 'conf-high' : c === 'medium' ? 'conf-medium' : 'conf-low';

const SEV_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
type FindingStatus = 'new' | 'triaged' | 'in-progress' | 'mitigated';
const findingKey = (f: Finding): string => `${f.ruleId}::${f.target || f.location}::${f.title}`;

const STATUS_VI: Record<FindingStatus, string> = {
  new: 'Mới',
  triaged: 'Đã xem xét',
  'in-progress': 'Đang xử lý',
  mitigated: 'Đã khắc phục',
};

// ── Finding Drawer ────────────────────────────────────────────────────────────
const FindingDrawer: React.FC<{ finding: Finding | null; onClose: () => void }> = ({ finding, onClose }) => {
  const { setAIPendingFinding, setAIChatOpen } = useAIStore();
  if (!finding) return null;

  const isFuzzer = finding.collector === 'active-fuzzer';
  const payloadLine = finding.evidence.find((e) => e.startsWith('Payload:'));
  const evidenceLines = finding.evidence.filter((e) => !e.startsWith('Payload:'));

  return (
    <div className="finding-drawer-backdrop" onClick={onClose}>
      <aside className="finding-drawer" onClick={(e) => e.stopPropagation()}>

        {/* Head */}
        <div className="finding-drawer-head">
          <div className="finding-drawer-title-wrap">
            <span className={`sev-tag tag-${finding.severity}`}>{finding.severity}</span>
            <div className="finding-drawer-title">{finding.title}</div>
          </div>
          <button className="btn-secondary finding-drawer-close" onClick={onClose}>Đóng ✕</button>
        </div>

        {/* Meta row */}
        <div className="finding-drawer-meta">
          <span className="badge badge-cat">{formatOwaspCategory(finding.owaspCategory)}</span>
          {isFuzzer && <span className="badge badge-fuzzer">Fuzzer</span>}
          <span className={`conf-badge ${confClass(finding.confidence)}`}>
            Độ tin cậy: {finding.confidence}
          </span>
        </div>

        {/* Detail body */}
        <div className="finding-detail">
          <div>
            <div className="detail-label">Tìm thấy tại</div>
            <div className="detail-mono">{finding.target || finding.location}</div>
          </div>
          <div>
            <div className="detail-label">Mã lỗ hổng</div>
            <div className="detail-mono" style={{ color: 'var(--text-3)', fontSize: 11 }}>{finding.ruleId}</div>
          </div>
          {isFuzzer && payloadLine && (
            <div>
              <div className="detail-label">Payload kiểm tra</div>
              <div className="detail-payload">{payloadLine.replace('Payload: ', '')}</div>
            </div>
          )}
          {evidenceLines.length > 0 && (
            <div>
              <div className="detail-label">Dữ liệu phát hiện</div>
              {evidenceLines.map((e, i) => (
                <div key={i} className="detail-evidence" style={{ marginBottom: 3 }}>{e}</div>
              ))}
            </div>
          )}
          <div>
            <div className="detail-label">Cách khắc phục</div>
            <div className="detail-fix">{finding.remediation}</div>
          </div>
          <div style={{ paddingTop: 4 }}>
            <button
              className="btn-ask-ai"
              onClick={(e) => {
                e.stopPropagation();
                setAIPendingFinding(finding);
                setAIChatOpen(true);
              }}
            >
              Hỏi AI về lỗ hổng này
            </button>
          </div>
        </div>
      </aside>
    </div>
  );
};

// ── Findings Table ────────────────────────────────────────────────────────────
const FindingsTable: React.FC<{
  findings: Finding[];
  scopeKey: string;
  onOpen: (f: Finding) => void;
  getStatus: (sk: string, fk: string) => FindingStatus | undefined;
  onStatusChange: (sk: string, f: Finding, s: FindingStatus) => void;
}> = ({ findings, scopeKey, onOpen, getStatus, onStatusChange }) => (
  <div className="findings-table-wrap">
    <table className="findings-table">
      <thead>
        <tr>
          <th style={{ width: 88 }}>Mức độ</th>
          <th>Lỗ hổng</th>
          <th style={{ width: 210 }}>Danh mục</th>
          <th style={{ width: 190 }}>Vị trí</th>
          <th style={{ width: 128 }}>Trạng thái</th>
          <th style={{ width: 96 }}>Hành động</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f, idx) => {
          const key = findingKey(f);
          const rowStatus = getStatus(scopeKey, key) || 'new';
          return (
            <tr key={`${key}-${idx}`} className="finding-row">
              <td><span className={`sev-tag tag-${f.severity}`}>{f.severity}</span></td>
              <td>
                <div className="finding-rule">{f.ruleId}</div>
                <div className="finding-title-table">{f.title}</div>
              </td>
              <td><span className="badge badge-cat">{formatOwaspCategory(f.owaspCategory)}</span></td>
              <td className="finding-target" title={f.target || f.location}>
                {f.target || f.location || '—'}
              </td>
              <td>
                <select
                  className={`finding-status-select status-${rowStatus}`}
                  value={rowStatus}
                  onChange={(e) => onStatusChange(scopeKey, f, e.target.value as FindingStatus)}
                >
                  {(Object.keys(STATUS_VI) as FindingStatus[]).map((s) => (
                    <option key={s} value={s}>{STATUS_VI[s]}</option>
                  ))}
                </select>
              </td>
              <td>
                <button className="btn-secondary btn-open-finding" onClick={() => onOpen(f)}>
                  Chi tiết
                </button>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  </div>
);

// ── Results Panel ─────────────────────────────────────────────────────────────
export const ResultsPanel: React.FC = () => {
  const {
    urlScanResult, projectScanResult, error, isLoading, activeTab,
    resetUrlScanResult, resetProjectScanResult,
    setFindingStatus, getFindingStatus, clearFindingStatuses,
  } = useStore();

  const [sortBy, setSortBy]       = useState<'severity' | 'confidence'>('severity');
  const [filterSev, setFilterSev] = useState('all');
  const [searchQ, setSearchQ]     = useState('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [showOverview, setShowOverview]       = useState(true);

  const scanResult = activeTab === 'url' ? urlScanResult : projectScanResult;

  useEffect(() => {
    if (!scanResult) return;
    setShowOverview(scanResult.findings.length <= 5);
  }, [scanResult]);

  if (isLoading) return null;
  if (error) return <div className="error-bar">{error}</div>;

  // ── Empty state ──
  if (!scanResult) {
    return (
      <div className="rp-empty">
        <div className="rp-empty-steps">
          <div className="rp-empty-step">
            <div className="rp-empty-num">1</div>
            <div className="rp-empty-text">
              {activeTab === 'url'
                ? <><strong>Nhập URL</strong> website vào ô bên trái</>
                : <><strong>Chọn thư mục</strong> mã nguồn</>}
            </div>
          </div>
          <div className="rp-empty-arrow">→</div>
          <div className="rp-empty-step">
            <div className="rp-empty-num">2</div>
            <div className="rp-empty-text">
              {activeTab === 'url'
                ? <>Nhấn <strong>Bắt đầu quét URL</strong></>
                : <>Nhấn <strong>Bắt đầu phân tích</strong></>}
            </div>
          </div>
          <div className="rp-empty-arrow">→</div>
          <div className="rp-empty-step">
            <div className="rp-empty-num">3</div>
            <div className="rp-empty-text">Kết quả xuất hiện tại đây</div>
          </div>
        </div>
        <p className="rp-empty-hint">
          Cài đặt mặc định phù hợp cho hầu hết trường hợp — không cần thay đổi gì thêm.
        </p>
      </div>
    );
  }

  const { findings, metadata } = scanResult;
  const scanScopeKey = `${scanResult.mode}::${scanResult.target || scanResult.scannedUrl || 'unknown'}`.toLowerCase();
  const summary = metadata.summary;

  // ── Filter + sort ──
  const visible = findings
    .filter((f) => filterSev === 'all' || f.severity === filterSev)
    .filter((f) => !searchQ ||
      f.title.toLowerCase().includes(searchQ.toLowerCase()) ||
      f.ruleId.toLowerCase().includes(searchQ.toLowerCase()) ||
      formatOwaspCategory(f.owaspCategory).toLowerCase().includes(searchQ.toLowerCase()))
    .sort((a, b) =>
      sortBy === 'severity'
        ? SEV_ORDER[b.severity] - SEV_ORDER[a.severity]
        : (b.confidence === 'high' ? 3 : b.confidence === 'medium' ? 2 : 1) -
          (a.confidence === 'high' ? 3 : a.confidence === 'medium' ? 2 : 1)
    );

  const cnt = (sev: string) => summary.bySeverity?.[sev] || 0;
  const hasFilter = filterSev !== 'all' || searchQ !== '';
  const scopedStatusCount = findings.filter(f =>
    getFindingStatus(scanScopeKey, findingKey(f))
  ).length;

  return (
    <div className="results-shell density-comfort">

      {/* ── Overview toggle strip ── */}
      <div className="rp-guide">
        <div className="rp-guide-steps">
          <span className="rp-guide-pill rp-guide-pill--1">
            <span className="rp-guide-num">1</span> Xem lỗi Critical &amp; High trước
          </span>
          <span className="rp-guide-sep">→</span>
          <span className="rp-guide-pill">
            <span className="rp-guide-num">2</span> Nhấn &quot;Chi tiết&quot; để xem cách sửa
          </span>
          <span className="rp-guide-sep">→</span>
          <span className="rp-guide-pill">
            <span className="rp-guide-num">3</span> Cập nhật trạng thái xử lý
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <ReportExportButton />
          <button
            className="btn-secondary rp-overview-btn"
            onClick={() => setShowOverview((v) => !v)}
          >
            {showOverview ? 'Ẩn tổng quan' : 'Tổng quan'}
          </button>
        </div>
      </div>

      {/* ── Risk Dashboard ── */}
      {showOverview && (
        <div style={{ flexShrink: 0 }}>
          <RiskDashboard scanResult={scanResult} />
        </div>
      )}

      {/* ── Filter bar ── */}
      <div className="filter-bar-adv" style={{ flexShrink: 0 }}>
        <div className="filter-bar-main">
          {/* Severity chips */}
          <div className="sev-filter-chips">
            {(['all', 'critical', 'high', 'medium', 'low'] as const).map((s) => (
              <button
                key={s}
                className={`sev-filter-btn sev-filter-${s} ${filterSev === s ? 'active' : ''}`}
                onClick={() => setFilterSev(s)}
              >
                {s === 'all' ? 'Tất cả' : s.charAt(0).toUpperCase() + s.slice(1)}
                {s !== 'all' && cnt(s) > 0 && (
                  <span className="sev-filter-count">{cnt(s)}</span>
                )}
              </button>
            ))}
          </div>

          <input
            type="text"
            className="search-input"
            placeholder="Tìm lỗ hổng hoặc mã rule..."
            value={searchQ}
            onChange={(e) => setSearchQ(e.target.value)}
          />
        </div>

        <div className="filter-bar-right">
          <select
            className="filter-select filter-select-sort"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as 'severity' | 'confidence')}
          >
            <option value="severity">Sắp xếp: Mức độ</option>
            <option value="confidence">Sắp xếp: Độ tin cậy</option>
          </select>
          <span className="filter-count">{visible.length}/{findings.length}</span>

          {hasFilter && (
            <button className="btn-reset" onClick={() => { setFilterSev('all'); setSearchQ(''); }}>
              ↺ Xoá lọc
            </button>
          )}

          <button
            className="btn-reset btn-reset-status"
            disabled={scopedStatusCount === 0}
            onClick={() => clearFindingStatuses(scanScopeKey)}
            title="Đặt lại trạng thái xử lý"
          >
            ↺ Trạng thái
          </button>

          <button
            className="btn-reset btn-clear-results"
            onClick={() => {
              if (activeTab === 'url') resetUrlScanResult();
              else resetProjectScanResult();
              setSelectedFinding(null);
            }}
          >
            ✕ Xoá
          </button>
        </div>
      </div>

      {/* ── Table / empty results ── */}
      {visible.length === 0 ? (
        <div className="empty-state" style={{ minHeight: 160 }}>
          <div className="empty-icon">✓</div>
          <p>{hasFilter ? 'Không có lỗ hổng nào khớp bộ lọc.' : 'Không phát hiện vấn đề nào.'}</p>
        </div>
      ) : (
        <FindingsTable
          findings={visible}
          scopeKey={scanScopeKey}
          onOpen={setSelectedFinding}
          getStatus={getFindingStatus}
          onStatusChange={(sk, f, s) => setFindingStatus(sk, findingKey(f), s)}
        />
      )}

      <FindingDrawer finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
    </div>
  );
};

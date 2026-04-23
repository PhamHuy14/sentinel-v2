import React, { useEffect, useState } from 'react';
import { useAIStore } from '../store/useAIStore';
import { useStore } from '../store/useStore';
import { Finding } from '../types';
import { ReportExportButton } from './ReportExportButton';
import { RiskDashboard } from './RiskDashboard';

const httpColor = (code: number) => code >= 500 ? 'err' : code >= 400 ? 'warn' : code >= 300 ? 'warn' : 'ok';
const confClass = (c: string) => c === 'high' ? 'conf-high' : c === 'medium' ? 'conf-medium' : 'conf-low';

const SEV_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const CONF_ORDER: Record<string, number> = { high: 3, medium: 2, low: 1 };
type FindingStatus = 'new' | 'triaged' | 'in-progress' | 'mitigated';

const findingKey = (f: Finding): string => `${f.ruleId}::${f.target || f.location}::${f.title}`;

const statusLabel = (s: FindingStatus) => {
  if (s === 'new') return 'New';
  if (s === 'triaged') return 'Triaged';
  if (s === 'in-progress') return 'In Progress';
  return 'Mitigated';
};

const SeverityCell: React.FC<{ sev: Finding['severity'] }> = ({ sev }) => (
  <span className={`sev-tag tag-${sev}`}>{sev}</span>
);

const CollectorLabel: React.FC<{ collector: Finding['collector'] }> = ({ collector }) => {
  if (collector === 'active-fuzzer') return <span className="table-pill">Fuzzer</span>;
  if (collector === 'blackbox') return <span className="table-pill">Black-box</span>;
  return <span className="table-pill">Source</span>;
};

const FindingDrawer: React.FC<{
  finding: Finding | null;
  onClose: () => void;
}> = ({ finding, onClose }) => {
  const { setAIPendingFinding, setAIChatOpen } = useAIStore();

  if (!finding) return null;

  const isFuzzer = finding.collector === 'active-fuzzer';
  const payloadLine = finding.evidence.find((e) => e.startsWith('Payload:'));
  const evidenceLines = finding.evidence.filter((e) => !e.startsWith('Payload:'));

  const handleAskAI = (e: React.MouseEvent) => {
    e.stopPropagation();
    setAIPendingFinding(finding);
    setAIChatOpen(true);
  };

  return (
    <div className="finding-drawer-backdrop" onClick={onClose}>
      <aside className="finding-drawer" onClick={(e) => e.stopPropagation()}>
        <div className="finding-drawer-head">
          <div className="finding-drawer-title-wrap">
            <span className={`sev-tag tag-${finding.severity}`}>{finding.severity}</span>
            <div className="finding-drawer-title">{finding.title}</div>
          </div>
          <button className="btn-secondary finding-drawer-close" onClick={onClose}>Đóng</button>
        </div>

        <div className="finding-drawer-meta">
          <span className="badge badge-cat">{finding.owaspCategory}</span>
          {isFuzzer && <span className="badge badge-fuzzer">fuzzer</span>}
          <span className={`conf-badge ${confClass(finding.confidence)}`}>confidence: {finding.confidence}</span>
        </div>

        <div className="finding-detail">
          <div>
            <div className="detail-label">Vị trí</div>
            <div className="detail-mono">{finding.target || finding.location}</div>
          </div>
          <div>
            <div className="detail-label">Mã rule</div>
            <div className="detail-mono" style={{ color: 'var(--text-3)', fontSize: 11 }}>{finding.ruleId}</div>
          </div>
          {isFuzzer && payloadLine && (
            <div>
              <div className="detail-label">Payload</div>
              <div className="detail-payload">{payloadLine.replace('Payload: ', '')}</div>
            </div>
          )}
          {evidenceLines.length > 0 && (
            <div>
              <div className="detail-label">Bằng chứng</div>
              {evidenceLines.map((e, i) => <div key={i} className="detail-evidence" style={{ marginBottom: 3 }}>{e}</div>)}
            </div>
          )}
          <div>
            <div className="detail-label">Khuyến nghị khắc phục</div>
            <div className="detail-fix">{finding.remediation}</div>
          </div>

          <div style={{ paddingTop: 4 }}>
            <button className="btn-ask-ai btn-ask-ai--detail" onClick={handleAskAI}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
              Phân tích chi tiết bằng AI
            </button>
          </div>
        </div>
      </aside>
    </div>
  );
};

const FindingsTable: React.FC<{
  findings: Finding[];
  scopeKey: string;
  onOpen: (f: Finding) => void;
  getStatus: (scopeKey: string, findingKey: string) => FindingStatus | undefined;
  onStatusChange: (scopeKey: string, f: Finding, status: FindingStatus) => void;
}> = ({ findings, scopeKey, onOpen, getStatus, onStatusChange }) => {
  return (
    <div className="findings-table-wrap">
      <table className="findings-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Rule</th>
            <th>Category</th>
            <th>Target</th>
            <th>Collector</th>
            <th>Confidence</th>
            <th>Status</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, idx) => {
            const key = findingKey(f);
            const rowStatus = getStatus(scopeKey, key) || 'new';
            return (
              <tr key={`${key}-${idx}`} className="finding-row">
                <td><SeverityCell sev={f.severity} /></td>
                <td>
                  <div className="finding-rule">{f.ruleId}</div>
                  <div className="finding-title-table">{f.title}</div>
                </td>
                <td><span className="badge badge-cat">{f.owaspCategory}</span></td>
                <td className="finding-target" title={f.target || f.location}>{f.target || f.location || '—'}</td>
                <td><CollectorLabel collector={f.collector} /></td>
                <td><span className={`conf-badge ${confClass(f.confidence)}`}>{f.confidence}</span></td>
                <td>
                  <select
                    className={`finding-status-select status-${rowStatus}`}
                    value={rowStatus}
                    onChange={(e) => onStatusChange(scopeKey, f, e.target.value as FindingStatus)}
                    title="Trạng thái xử lý finding"
                  >
                    <option value="new">{statusLabel('new')}</option>
                    <option value="triaged">{statusLabel('triaged')}</option>
                    <option value="in-progress">{statusLabel('in-progress')}</option>
                    <option value="mitigated">{statusLabel('mitigated')}</option>
                  </select>
                </td>
                <td>
                  <button className="btn-secondary btn-open-finding" onClick={() => onOpen(f)}>Chi tiết</button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

export const ResultsPanel: React.FC = () => {
  const {
    urlScanResult,
    projectScanResult,
    error,
    isLoading,
    activeTab,
    resetUrlScanResult,
    resetProjectScanResult,
    setFindingStatus,
    getFindingStatus,
    clearFindingStatuses,
    resultsDensity,
    setResultsDensity,
  } = useStore();

  const [sortBy, setSortBy] = useState<'severity' | 'confidence' | 'collector'>('severity');
  const [filterSev, setFilterSev] = useState('all');
  const [filterCol, setFilterCol] = useState('all');
  const [searchQ, setSearchQ] = useState('');
  const [catFilter, setCatFilter] = useState('all');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [showOverview, setShowOverview] = useState(true);

  const onStatusChange = (scopeKey: string, finding: Finding, statusValue: FindingStatus) => {
    setFindingStatus(scopeKey, findingKey(finding), statusValue);
  };

  const scanResult = activeTab === 'url' ? urlScanResult : projectScanResult;

  useEffect(() => {
    if (!scanResult) return;
    // Với scan nhiều findings, mặc định thu gọn overview để ưu tiên vùng hiển thị lỗi.
    setShowOverview(scanResult.findings.length <= 3);
  }, [scanResult]);

  if (isLoading) return null;
  if (error) return <div className="error-bar">{error}</div>;

  if (!scanResult) {
    return (
      <div className="empty-state">
        <div className="empty-icon">◎</div>
        <p>Bắt đầu bằng cách chọn mục tiêu ở cột trái rồi nhấn <b>{activeTab === 'url' ? 'Bắt đầu quét' : 'Quét dự án'}</b>.</p>
        <p className="empty-state-tip">Nếu bạn mới làm quen bảo mật, hãy chạy profile mặc định trước để có kết quả dễ đọc và dễ xử lý.</p>
      </div>
    );
  }

  const { findings, metadata, scannedUrl, finalUrl, status, title } = scanResult;
  const scanScopeKey = `${scanResult.mode}::${scanResult.target || scannedUrl || 'unknown'}`.toLowerCase();
  const summary = metadata.summary;
  const cats = Array.from(new Set(findings.map((f) => f.owaspCategory))).sort();

  const visible = findings
    .filter((f) => catFilter === 'all' || f.owaspCategory === catFilter)
    .filter((f) => filterSev === 'all' || f.severity === filterSev)
    .filter((f) => filterCol === 'all' || f.collector === filterCol)
    .filter((f) => !searchQ || f.title.toLowerCase().includes(searchQ.toLowerCase()) || f.ruleId.toLowerCase().includes(searchQ.toLowerCase()))
    .sort((a, b) => {
      if (sortBy === 'severity') return SEV_ORDER[b.severity] - SEV_ORDER[a.severity];
      if (sortBy === 'confidence') return CONF_ORDER[b.confidence] - CONF_ORDER[a.confidence];
      return a.collector.localeCompare(b.collector);
    });

  const cnt = (sev: string) => summary.bySeverity?.[sev] || 0;
  const resetFilters = () => {
    setSortBy('severity');
    setFilterSev('all');
    setFilterCol('all');
    setSearchQ('');
    setCatFilter('all');
  };
  const hasFilter = catFilter !== 'all' || filterSev !== 'all' || filterCol !== 'all' || searchQ !== '';
  const scopedStatusCount = findings.reduce((acc, f) => {
    const statusValue = getFindingStatus(scanScopeKey, findingKey(f));
    return statusValue ? acc + 1 : acc;
  }, 0);

  return (
    <div className={`results-shell density-${resultsDensity}`}>
      <div className="beginner-guide-strip">
        <div className="beginner-guide-title">Lộ trình xử lý khuyến nghị</div>
        <div className="beginner-guide-steps">
          <span>1) Ưu tiên sửa CRITICAL/HIGH</span>
          <span>2) Chuyển trạng thái để theo dõi tiến độ</span>
          <span>3) Xác minh lại bằng scan nhanh</span>
        </div>
        <button className="btn-secondary btn-overview-toggle" onClick={() => setShowOverview((v) => !v)}>
          {showOverview ? 'Ẩn tổng quan' : 'Hiện tổng quan'}
        </button>
      </div>

      {showOverview && (
        <div style={{ flexShrink: 0 }}>
          <RiskDashboard scanResult={scanResult} />
        </div>
      )}

      {showOverview && (
      <div className="results-info-row">
        <div className="section results-info-meta">
          <div className="section-label">Thông tin scan</div>
          <div className="meta-table">
            <div className="meta-row">
              <span className="meta-key">Mục tiêu</span>
              <span className="meta-val" title={scanResult.target || scannedUrl}>
                {scanResult.target || scannedUrl || '—'}
              </span>
            </div>
            {scanResult.mode === 'url-scan' && (
              <>
                {finalUrl && finalUrl !== scannedUrl && (
                  <div className="meta-row"><span className="meta-key">URL cuối cùng</span><span className="meta-val">{finalUrl}</span></div>
                )}
                {status && (
                  <div className="meta-row">
                    <span className="meta-key">Trạng thái HTTP</span>
                    <span className={`meta-val ${httpColor(status)}`}>{status}</span>
                  </div>
                )}
                {title && <div className="meta-row"><span className="meta-key">Tiêu đề trang</span><span className="meta-val">{title}</span></div>}
                {metadata.crawledEndpointsCount !== undefined && (
                  <div className="meta-row"><span className="meta-key">URL đã crawl</span><span className="meta-val">{metadata.crawledEndpointsCount}</span></div>
                )}
                {metadata.formsDetected !== undefined && (
                  <div className="meta-row"><span className="meta-key">Biểu mẫu</span><span className="meta-val">{metadata.formsDetected}</span></div>
                )}
              </>
            )}
            {scanResult.mode === 'project-scan' && (
              <>
                {metadata.scannedFiles !== undefined && (
                  <div className="meta-row"><span className="meta-key">Số file đã quét</span><span className="meta-val">{metadata.scannedFiles}</span></div>
                )}
                {metadata.packageJsonFound !== undefined && (
                  <div className="meta-row">
                    <span className="meta-key">package.json</span>
                    <span className={`meta-val ${metadata.packageJsonFound ? 'ok' : 'warn'}`}>
                      {metadata.packageJsonFound ? 'Có' : 'Không có'}
                    </span>
                  </div>
                )}
                {metadata.configCount !== undefined && (
                  <div className="meta-row"><span className="meta-key">File cấu hình</span><span className="meta-val">{metadata.configCount}</span></div>
                )}
                {metadata.csprojCount !== undefined && metadata.csprojCount > 0 && (
                  <div className="meta-row"><span className="meta-key">File .csproj</span><span className="meta-val">{metadata.csprojCount}</span></div>
                )}
                {metadata.techStack && metadata.techStack.length > 0 && (
                  <div className="meta-row">
                    <span className="meta-key">Ngăn xếp công nghệ</span>
                    <span className="meta-val">{metadata.techStack.join(', ')}</span>
                  </div>
                )}
              </>
            )}
            <div className="meta-row">
              <span className="meta-key">Tổng số findings</span>
              <span className="meta-val">{metadata.summary.total}</span>
            </div>
          </div>
        </div>

        <div className="section results-info-summary">
          <div className="section-label">Tổng quan</div>
          <div className="results-count">{summary.total}</div>
          <div className="results-title">Tổng số findings</div>
          <div className="sev-chips">
            {cnt('critical') > 0 && <span className="sev-chip chip-crit">CRIT {cnt('critical')}</span>}
            {cnt('high') > 0 && <span className="sev-chip chip-high">HIGH {cnt('high')}</span>}
            {cnt('medium') > 0 && <span className="sev-chip chip-med">MED {cnt('medium')}</span>}
            {cnt('low') > 0 && <span className="sev-chip chip-low">LOW {cnt('low')}</span>}
          </div>
          <div style={{ marginTop: 'auto', paddingTop: 10 }}>
            <ReportExportButton />
          </div>
        </div>
      </div>
      )}

      <div className="filter-bar-adv" style={{ flexShrink: 0 }}>
        <div className="filter-bar-main">
          <input
            type="text"
            className="search-input"
            placeholder="🔍 Tìm findings…"
            value={searchQ}
            onChange={(e) => setSearchQ(e.target.value)}
          />
          <select className="filter-select filter-select-severity" value={filterSev} onChange={(e) => setFilterSev(e.target.value)}>
            <option value="all">Mức độ</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select className="filter-select filter-select-collector" value={filterCol} onChange={(e) => setFilterCol(e.target.value)}>
            <option value="all">Collector</option>
            <option value="blackbox">Black-box</option>
            <option value="active-fuzzer">Fuzzer</option>
            <option value="source">Mã nguồn</option>
          </select>
          {cats.length > 1 && (
            <select className="filter-select filter-select-category" value={catFilter} onChange={(e) => setCatFilter(e.target.value)}>
              <option value="all">Danh mục</option>
              {cats.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          )}
          <select className="filter-select filter-select-sort" value={sortBy} onChange={(e) => setSortBy(e.target.value as 'severity' | 'confidence' | 'collector')}>
            <option value="severity">Sort: Mức độ</option>
            <option value="confidence">Sort: Tin cậy</option>
            <option value="collector">Sort: Collector</option>
          </select>
        </div>
        <div className="filter-bar-right">
          <div className="density-switch" title="Chuyển mật độ hiển thị findings">
            <button
              className={`btn-reset ${resultsDensity === 'comfort' ? 'active' : ''}`}
              onClick={() => setResultsDensity('comfort')}
            >
              Comfort
            </button>
            <button
              className={`btn-reset ${resultsDensity === 'compact' ? 'active' : ''}`}
              onClick={() => setResultsDensity('compact')}
            >
              Compact
            </button>
          </div>
          <span className="filter-count">{visible.length}/{findings.length}</span>
          {hasFilter && (
            <button className="btn-reset" onClick={resetFilters} title="Đặt lại toàn bộ bộ lọc">
              <span className="btn-reset-icon">↺</span> Đặt lại
            </button>
          )}
          <button
            className="btn-reset btn-reset-status"
            title="Xóa trạng thái xử lý của scan hiện tại"
            disabled={scopedStatusCount === 0}
            onClick={() => {
              clearFindingStatuses(scanScopeKey);
            }}
          >
            ↺ Reset statuses
          </button>
          <button
            className="btn-reset btn-clear-results"
            title={`Xóa kết quả ${activeTab === 'url' ? 'quét URL' : 'quét dự án'} và bắt đầu lại`}
            onClick={() => {
              if (activeTab === 'url') resetUrlScanResult();
              else resetProjectScanResult();
              setSelectedFinding(null);
            }}
          >
            ✕ Xóa
          </button>
        </div>
      </div>

      {visible.length === 0 ? (
        <div className="empty-state" style={{ minHeight: 160 }}>
          <div className="empty-icon">✓</div>
          <p>{hasFilter ? 'Không có finding nào khớp với bộ lọc hiện tại.' : 'Không phát hiện vấn đề nào.'}</p>
        </div>
      ) : (
        <FindingsTable
          findings={visible}
          scopeKey={scanScopeKey}
          onOpen={setSelectedFinding}
          getStatus={getFindingStatus}
          onStatusChange={onStatusChange}
        />
      )}

      <FindingDrawer finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
    </div>
  );
};

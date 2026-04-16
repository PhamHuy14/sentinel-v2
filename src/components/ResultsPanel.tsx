import React, { useState } from 'react';
import { useStore } from '../store/useStore';
import { Finding } from '../types';
import { ReportExportButton } from './ReportExportButton';
import { RiskDashboard } from './RiskDashboard';
import { useAIStore } from '../store/useAIStore';

const sevClass  = (s: string) => `sev-${s}`;
const tagClass  = (s: string) => `tag-${s}`;
const confClass = (c: string) => c === 'high' ? 'conf-high' : c === 'medium' ? 'conf-medium' : 'conf-low';
const httpColor = (code: number) => code >= 500 ? 'err' : code >= 400 ? 'warn' : code >= 300 ? 'warn' : 'ok';

const SEV_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const CONF_ORDER: Record<string, number> = { high: 3, medium: 2, low: 1 };

const FindingCard: React.FC<{ f: Finding }> = ({ f }) => {
  const [open, setOpen] = useState(false);
  const { setAIPendingFinding, setAIChatOpen } = useAIStore();
  const isFuzzer   = f.collector === 'active-fuzzer';
  const payloadLine= f.evidence.find((e) => e.startsWith('Payload:'));
  const evidenceLines = f.evidence.filter((e) => !e.startsWith('Payload:'));

  const handleAskAI = (e: React.MouseEvent) => {
    e.stopPropagation(); // không trigger expand
    setAIPendingFinding(f);
    setAIChatOpen(true);
  };

  return (
    <div className={`finding-card ${sevClass(f.severity)}`}>
      <div className={`finding-header ${open ? 'open' : ''}`} onClick={() => setOpen((o) => !o)}>
        <span className={`sev-tag ${tagClass(f.severity)}`}>{f.severity}</span>
        <span className="finding-title">{f.title}</span>
        <div className="finding-badges">
          <span className="badge badge-cat">{f.owaspCategory}</span>
          {isFuzzer && <span className="badge badge-fuzzer">fuzzer</span>}
        </div>
        <button
          className="btn-ask-ai"
          onClick={handleAskAI}
          title="Phân tích finding này với AI"
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          Hỏi AI
        </button>
        <span className={`expand-caret ${open ? 'open' : ''}`}>▶</span>
      </div>

      {open && (
        <div className="finding-detail">
          <div style={{ display: 'flex', gap: 12 }}>
            <div style={{ flex: 1 }}>
              <div className="detail-label">Vị trí</div>
              <div className="detail-mono">{f.target || f.location}</div>
            </div>
            <div>
              <div className="detail-label">Độ tin cậy</div>
              <span className={`conf-badge ${confClass(f.confidence)}`}>{f.confidence}</span>
            </div>
          </div>
          <div>
            <div className="detail-label">Mã rule</div>
            <div className="detail-mono" style={{ color: 'var(--text-3)', fontSize: 11 }}>{f.ruleId}</div>
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
            <div className="detail-fix">{f.remediation}</div>
          </div>
          <div style={{ paddingTop: 4 }}>
            <button className="btn-ask-ai btn-ask-ai--detail" onClick={handleAskAI}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
              Phân tích chi tiết &amp; hướng dẫn khắc phục
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export const ResultsPanel: React.FC = () => {
  const { urlScanResult, projectScanResult, error, isLoading, activeTab, resetUrlScanResult, resetProjectScanResult } = useStore();

  // Trạng thái lọc / sắp xếp nâng cao
  const [sortBy,      setSortBy]      = useState<'severity' | 'confidence' | 'collector'>('severity');
  const [filterSev,   setFilterSev]   = useState('all');
  const [filterCol,   setFilterCol]   = useState('all');
  const [searchQ,     setSearchQ]     = useState('');
  const [catFilter,   setCatFilter]   = useState('all');

  if (isLoading) return null;
  if (error)     return <div className="error-bar">{error}</div>;

  const scanResult = activeTab === 'url' ? urlScanResult : projectScanResult;

  if (!scanResult) {
    return (
      <div className="empty-state">
        <div className="empty-icon">◎</div>
        <p>Vui lòng chọn mục tiêu và nhấn &quot;Bắt đầu quét&quot; để khởi động chế độ <b>{activeTab === 'url' ? 'Quét URL' : 'Quét dự án'}</b>.</p>
      </div>
    );
  }

  const { findings, metadata, scannedUrl, finalUrl, status, title } = scanResult;
  const summary = metadata.summary;
  const cats = Array.from(new Set(findings.map((f) => f.owaspCategory))).sort();

  // Tạo danh sách đã lọc và sắp xếp
  const visible = findings
    .filter((f) => catFilter   === 'all' || f.owaspCategory === catFilter)
    .filter((f) => filterSev   === 'all' || f.severity      === filterSev)
    .filter((f) => filterCol   === 'all' || f.collector     === filterCol)
    .filter((f) => !searchQ    || f.title.toLowerCase().includes(searchQ.toLowerCase())
                               || f.ruleId.toLowerCase().includes(searchQ.toLowerCase()))
    .sort((a, b) => {
      if (sortBy === 'severity')   return SEV_ORDER[b.severity]   - SEV_ORDER[a.severity];
      if (sortBy === 'confidence') return CONF_ORDER[b.confidence] - CONF_ORDER[a.confidence];
      return a.collector.localeCompare(b.collector);
    });

  const cnt = (sev: string) => summary.bySeverity?.[sev] || 0;

  const resetFilters = () => { setSortBy('severity'); setFilterSev('all'); setFilterCol('all'); setSearchQ(''); setCatFilter('all'); };
  const hasFilter = catFilter !== 'all' || filterSev !== 'all' || filterCol !== 'all' || searchQ !== '';

  return (
    <>
      {/* Bảng điều khiển rủi ro */}
      <div style={{ flexShrink: 0 }}>
        <RiskDashboard scanResult={scanResult} />
      </div>

      {/* Thông tin scan + tổng quan */}
      <div className="results-info-row">
        {/* Bên trái: metadata scan */}
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

        {/* Bên phải: tổng quan và xuất báo cáo */}
        <div className="section results-info-summary">
          <div className="section-label">Tổng quan</div>
          <div className="results-count">{summary.total}</div>
          <div className="results-title">Tổng số findings</div>
          <div className="sev-chips">
            {cnt('critical') > 0 && <span className="sev-chip chip-crit">CRIT {cnt('critical')}</span>}
            {cnt('high')     > 0 && <span className="sev-chip chip-high">HIGH {cnt('high')}</span>}
            {cnt('medium')   > 0 && <span className="sev-chip chip-med">MED {cnt('medium')}</span>}
            {cnt('low')      > 0 && <span className="sev-chip chip-low">LOW {cnt('low')}</span>}
          </div>
          <div style={{ marginTop: 'auto', paddingTop: 10 }}>
            <ReportExportButton />
          </div>
        </div>
      </div>

      {/* Thanh lọc nâng cao */}
      <div className="filter-bar-adv" style={{ flexShrink: 0 }}>
        <input
          type="text" className="search-input" placeholder="🔍 Tìm findings…"
          value={searchQ} onChange={(e) => setSearchQ(e.target.value)}
        />
        <select className="filter-select" value={filterSev} onChange={(e) => setFilterSev(e.target.value)}>
          <option value="all">Tất cả mức độ</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select className="filter-select" value={filterCol} onChange={(e) => setFilterCol(e.target.value)}>
          <option value="all">Tất cả collector</option>
          <option value="blackbox">Black-box</option>
          <option value="active-fuzzer">Fuzzer</option>
          <option value="source">Mã nguồn</option>
        </select>
        {cats.length > 1 && (
          <select className="filter-select" value={catFilter} onChange={(e) => setCatFilter(e.target.value)}>
            <option value="all">Tất cả danh mục</option>
            {cats.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        )}
        <select className="filter-select" value={sortBy} onChange={(e) => setSortBy(e.target.value as 'severity' | 'confidence' | 'collector')}>
          <option value="severity">Sắp xếp: Mức độ</option>
          <option value="confidence">Sắp xếp: Độ tin cậy</option>
          <option value="collector">Sắp xếp: Collector</option>
        </select>
        <div className="filter-bar-right">
          <span className="filter-count">{visible.length}/{findings.length}</span>
          {hasFilter && (
            <button className="btn-reset" onClick={resetFilters} title="Đặt lại toàn bộ bộ lọc">
              <span className="btn-reset-icon">↺</span> Đặt lại
            </button>
          )}
          <button
            className="btn-reset btn-clear-results"
            title={`Xóa kết quả ${activeTab === 'url' ? 'quét URL' : 'quét dự án'} và bắt đầu lại`}
            onClick={() => {
              if (activeTab === 'url') resetUrlScanResult();
              else resetProjectScanResult();
            }}
          >
            ✕ Xóa
          </button>
        </div>
      </div>

      {/* Danh sách findings */}
      {visible.length === 0 ? (
        <div className="empty-state" style={{ minHeight: 160 }}>
          <div className="empty-icon">✓</div>
          <p>{hasFilter ? 'Không có finding nào khớp với bộ lọc hiện tại.' : 'Không phát hiện vấn đề nào.'}</p>
        </div>
      ) : (
        <div className="findings-list">
          {visible.map((f, i) => <FindingCard key={i} f={f} />)}
        </div>
      )}
    </>
  );
};
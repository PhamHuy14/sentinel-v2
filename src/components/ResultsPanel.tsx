import React, { useState } from 'react';
import { useStore } from '../store/useStore';
import { Finding } from '../types';
import { ReportExportButton } from './ReportExportButton';
import { RiskDashboard } from './RiskDashboard';

const sevClass  = (s: string) => `sev-${s}`;
const tagClass  = (s: string) => `tag-${s}`;
const confClass = (c: string) => c === 'high' ? 'conf-high' : c === 'medium' ? 'conf-medium' : 'conf-low';
const httpColor = (code: number) => code >= 500 ? 'err' : code >= 400 ? 'warn' : code >= 300 ? 'warn' : 'ok';

const SEV_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const CONF_ORDER: Record<string, number> = { high: 3, medium: 2, low: 1 };

const FindingCard: React.FC<{ f: Finding }> = ({ f }) => {
  const [open, setOpen] = useState(false);
  const isFuzzer   = f.collector === 'active-fuzzer';
  const payloadLine= f.evidence.find((e) => e.startsWith('Payload:'));
  const evidenceLines = f.evidence.filter((e) => !e.startsWith('Payload:'));

  return (
    <div className={`finding-card ${sevClass(f.severity)}`}>
      <div className={`finding-header ${open ? 'open' : ''}`} onClick={() => setOpen((o) => !o)}>
        <span className={`sev-tag ${tagClass(f.severity)}`}>{f.severity}</span>
        <span className="finding-title">{f.title}</span>
        <div className="finding-badges">
          <span className="badge badge-cat">{f.owaspCategory}</span>
          {isFuzzer && <span className="badge badge-fuzzer">fuzzer</span>}
        </div>
        <span className={`expand-caret ${open ? 'open' : ''}`}>▶</span>
      </div>

      {open && (
        <div className="finding-detail">
          <div style={{ display: 'flex', gap: 12 }}>
            <div style={{ flex: 1 }}>
              <div className="detail-label">Location</div>
              <div className="detail-mono">{f.target || f.location}</div>
            </div>
            <div>
              <div className="detail-label">Confidence</div>
              <span className={`conf-badge ${confClass(f.confidence)}`}>{f.confidence}</span>
            </div>
          </div>
          <div>
            <div className="detail-label">Rule ID</div>
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
              <div className="detail-label">Evidence</div>
              {evidenceLines.map((e, i) => <div key={i} className="detail-evidence" style={{ marginBottom: 3 }}>{e}</div>)}
            </div>
          )}
          <div>
            <div className="detail-label">Remediation</div>
            <div className="detail-fix">{f.remediation}</div>
          </div>
        </div>
      )}
    </div>
  );
};

export const ResultsPanel: React.FC = () => {
  const { urlScanResult, projectScanResult, error, isLoading, activeTab, resetUrlScanResult, resetProjectScanResult } = useStore();

  // Advanced filter / sort state
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
        <p>Vui lòng chọn mục tiêu và nhấn &quot;Start Scan&quot; để bắt đầu ở chế độ <b>{activeTab === 'url' ? 'URL Scan' : 'Project Scan'}</b>.</p>
      </div>
    );
  }

  const { findings, metadata, scannedUrl, finalUrl, status, title } = scanResult;
  const summary = metadata.summary;
  const cats = Array.from(new Set(findings.map((f) => f.owaspCategory))).sort();

  // Build filtered + sorted list
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
      {/* Risk Dashboard */}
      <div style={{ flexShrink: 0 }}>
        <RiskDashboard scanResult={scanResult} />
      </div>

      {/* Scan Info + Summary side-by-side */}
      <div className="results-info-row">
        {/* Left: Scan meta */}
        <div className="section results-info-meta">
          <div className="section-label">Scan Info</div>
          <div className="meta-table">
            <div className="meta-row">
              <span className="meta-key">Target</span>
              <span className="meta-val" title={scanResult.target || scannedUrl}>
                {scanResult.target || scannedUrl || '—'}
              </span>
            </div>
            {scanResult.mode === 'url-scan' && (
              <>
                {finalUrl && finalUrl !== scannedUrl && (
                  <div className="meta-row"><span className="meta-key">Final URL</span><span className="meta-val">{finalUrl}</span></div>
                )}
                {status && (
                  <div className="meta-row">
                    <span className="meta-key">HTTP Status</span>
                    <span className={`meta-val ${httpColor(status)}`}>{status}</span>
                  </div>
                )}
                {title && <div className="meta-row"><span className="meta-key">Page Title</span><span className="meta-val">{title}</span></div>}
                {metadata.crawledEndpointsCount !== undefined && (
                  <div className="meta-row"><span className="meta-key">Crawled URLs</span><span className="meta-val">{metadata.crawledEndpointsCount}</span></div>
                )}
                {metadata.formsDetected !== undefined && (
                  <div className="meta-row"><span className="meta-key">Forms</span><span className="meta-val">{metadata.formsDetected}</span></div>
                )}
              </>
            )}
            {scanResult.mode === 'project-scan' && (
              <>
                {metadata.scannedFiles !== undefined && (
                  <div className="meta-row"><span className="meta-key">Files Scanned</span><span className="meta-val">{metadata.scannedFiles}</span></div>
                )}
                {metadata.packageJsonFound !== undefined && (
                  <div className="meta-row">
                    <span className="meta-key">package.json</span>
                    <span className={`meta-val ${metadata.packageJsonFound ? 'ok' : 'warn'}`}>
                      {metadata.packageJsonFound ? 'Found' : 'Not found'}
                    </span>
                  </div>
                )}
                {metadata.configCount !== undefined && (
                  <div className="meta-row"><span className="meta-key">Config Files</span><span className="meta-val">{metadata.configCount}</span></div>
                )}
                {metadata.csprojCount !== undefined && metadata.csprojCount > 0 && (
                  <div className="meta-row"><span className="meta-key">.csproj Files</span><span className="meta-val">{metadata.csprojCount}</span></div>
                )}
                {metadata.techStack && metadata.techStack.length > 0 && (
                  <div className="meta-row">
                    <span className="meta-key">Tech Stack</span>
                    <span className="meta-val">{metadata.techStack.join(', ')}</span>
                  </div>
                )}
              </>
            )}
            <div className="meta-row">
              <span className="meta-key">Total Findings</span>
              <span className="meta-val">{metadata.summary.total}</span>
            </div>
          </div>
        </div>

        {/* Right: Summary numbers + export */}
        <div className="section results-info-summary">
          <div className="section-label">Summary</div>
          <div className="results-count">{summary.total}</div>
          <div className="results-title">Total Findings</div>
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

      {/* Advanced filter bar */}
      <div className="filter-bar-adv" style={{ flexShrink: 0 }}>
        <input
          type="text" className="search-input" placeholder="🔍 Search findings…"
          value={searchQ} onChange={(e) => setSearchQ(e.target.value)}
        />
        <select className="filter-select" value={filterSev} onChange={(e) => setFilterSev(e.target.value)}>
          <option value="all">All severity</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select className="filter-select" value={filterCol} onChange={(e) => setFilterCol(e.target.value)}>
          <option value="all">All collectors</option>
          <option value="blackbox">Blackbox</option>
          <option value="active-fuzzer">Fuzzer</option>
          <option value="source">Source</option>
        </select>
        {cats.length > 1 && (
          <select className="filter-select" value={catFilter} onChange={(e) => setCatFilter(e.target.value)}>
            <option value="all">All categories</option>
            {cats.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        )}
        <select className="filter-select" value={sortBy} onChange={(e) => setSortBy(e.target.value as 'severity' | 'confidence' | 'collector')}>
          <option value="severity">Sort: Severity</option>
          <option value="confidence">Sort: Confidence</option>
          <option value="collector">Sort: Collector</option>
        </select>
        <div className="filter-bar-right">
          <span className="filter-count">{visible.length}/{findings.length}</span>
          {hasFilter && (
            <button className="btn-reset" onClick={resetFilters} title="Reset all filters">
              <span className="btn-reset-icon">↺</span> Reset
            </button>
          )}
          <button
            className="btn-reset btn-clear-results"
            title={`Clear ${activeTab === 'url' ? 'URL' : 'Project'} scan results and start over`}
            onClick={() => {
              if (activeTab === 'url') resetUrlScanResult();
              else resetProjectScanResult();
            }}
          >
            ✕ Clear
          </button>
        </div>
      </div>

      {/* Findings list */}
      {visible.length === 0 ? (
        <div className="empty-state" style={{ minHeight: 160 }}>
          <div className="empty-icon">✓</div>
          <p>{hasFilter ? 'No findings match current filters.' : 'No issues found.'}</p>
        </div>
      ) : (
        <div className="findings-list">
          {visible.map((f, i) => <FindingCard key={i} f={f} />)}
        </div>
      )}
    </>
  );
};
import { useStore } from './store/useStore';
import { UrlScanForm } from './components/UrlScanForm';
import { ProjectScanForm } from './components/ProjectScanForm';
import { ChecklistPanel } from './components/ChecklistPanel';
import { ScanProgress } from './components/ScanProgress';
import { ResultsPanel } from './components/ResultsPanel';
import { HistoryPanel } from './components/HistoryPanel';

function App() {
  const {
    activeTab, setActiveTab, isLoading,
    showHistoryDropdown, setShowHistoryDropdown, history,
  } = useStore();

  // Switch tab WITHOUT resetting scan results so data persists across tabs
  const switchTab = (tab: 'url' | 'project' | 'checklist') => {
    setActiveTab(tab);
    // NOTE: intentionally NOT calling resetScan() here so that:
    // 1. Checklist can read the latest project scan result
    // 2. Users can switch tabs and come back to their results
  };

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="app-logo">
          <div className="logo-icon">S</div>
          <div>
            <div className="logo-text">SENTINEL</div>
            <div className="logo-sub">OWASP 2025</div>
          </div>
        </div>

        <nav className="nav-tabs">
          <button className={`nav-tab ${activeTab === 'url'       ? 'active' : ''}`} onClick={() => switchTab('url')}>URL Scan</button>
          <button className={`nav-tab ${activeTab === 'project'   ? 'active' : ''}`} onClick={() => switchTab('project')}>Project Scan</button>
          <button className={`nav-tab ${activeTab === 'checklist' ? 'active' : ''}`} onClick={() => switchTab('checklist')}>Checklist</button>
        </nav>

        <div className="header-gap" />

        {/* History dropdown */}
        <div className="hist-btn-wrap">
          <button
            className={`btn-secondary hist-trigger ${showHistoryDropdown ? 'active' : ''}`}
            onClick={() => setShowHistoryDropdown(!showHistoryDropdown)}
            title="Scan History"
          >
            🕐 History {history.length > 0 && <span className="hist-badge">{history.length}</span>}
          </button>
          {showHistoryDropdown && <HistoryPanel />}
        </div>

        <div className="status-indicator">
          <div className={`status-dot ${isLoading ? 'active' : ''}`} />
          {isLoading ? 'Scanning' : 'Ready'}
        </div>
      </header>

      <div className="workspace">
        <aside className="left-panel">
          {activeTab === 'url'       && <UrlScanForm />}
          {activeTab === 'project'   && <ProjectScanForm />}
          {activeTab === 'checklist' && <ChecklistPanel />}
        </aside>

        <main className="right-panel">
          {isLoading ? (
            <ScanProgress />
          ) : activeTab === 'checklist' ? (
            <ChecklistResultsPanel />
          ) : (
            <ResultsPanel />
          )}
        </main>
      </div>
    </div>
  );
}

// Checklist right panel — shows project scan results summary if available
function ChecklistResultsPanel() {
  const { projectScanResult } = useStore();
  const projectScan = projectScanResult;

  if (!projectScan) {
    return (
      <div className="empty-state">
        <div className="empty-icon">☑</div>
        <p>Chạy <strong style={{ color: 'var(--accent)' }}>Project Scan</strong> để tự động điền checklist OWASP từ kết quả quét thực tế.</p>
      </div>
    );
  }

  // Show a summary of the project scan for reference on the right side
  const { findings, metadata } = projectScan;
  const bySev = metadata.summary.bySeverity;
  const byCat = metadata.summary.byCategory;
  const maxCat = Math.max(1, ...Object.values(byCat));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div className="section">
        <div className="section-label">Project Scan — Kết quả</div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
          {(['critical','high','medium','low'] as const).map(sev => {
            const n = bySev[sev] || 0;
            if (!n) return null;
            const colors: Record<string, string> = {
              critical: 'chip-crit', high: 'chip-high', medium: 'chip-med', low: 'chip-low'
            };
            return (
              <span key={sev} className={`sev-chip ${colors[sev]}`}>
                {sev.slice(0,4).toUpperCase()} {n}
              </span>
            );
          })}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
          <div className="rg-bars-hdr">Phân bổ theo OWASP Category</div>
          {Object.entries(byCat).sort((a,b) => b[1]-a[1]).map(([cat, count]) => (
            <div key={cat} className="rg-bar-row">
              <span className="rg-bar-cat">{cat}</span>
              <div className="rg-bar-track">
                <div className="rg-bar-fill" style={{ width: `${(count/maxCat)*100}%`, background: 'var(--accent)' }} />
              </div>
              <span className="rg-bar-n">{count}</span>
            </div>
          ))}
        </div>
      </div>

      {metadata.scannedFiles !== undefined && (
        <div className="section">
          <div className="section-label">Thống kê</div>
          <div className="meta-table">
            {metadata.scannedFiles !== undefined && (
              <div className="meta-row">
                <span className="meta-key">Files scanned</span>
                <span className="meta-val">{metadata.scannedFiles}</span>
              </div>
            )}
            {metadata.packageJsonFound !== undefined && (
              <div className="meta-row">
                <span className="meta-key">package.json found</span>
                <span className={`meta-val ${metadata.packageJsonFound ? 'ok' : ''}`}>
                  {metadata.packageJsonFound ? 'Yes' : 'No'}
                </span>
              </div>
            )}
            {metadata.configCount !== undefined && (
              <div className="meta-row">
                <span className="meta-key">Config files</span>
                <span className="meta-val">{metadata.configCount}</span>
              </div>
            )}
            <div className="meta-row">
              <span className="meta-key">Total findings</span>
              <span className="meta-val">{findings.length}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;

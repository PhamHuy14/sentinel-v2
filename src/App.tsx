import { useStore } from './store/useStore';
import { UrlScanForm } from './components/UrlScanForm';
import { ProjectScanForm } from './components/ProjectScanForm';
import { ChecklistPanel } from './components/ChecklistPanel';
import { ChecklistRightPanel } from './components/ChecklistRightPanel';
import { ScanProgress } from './components/ScanProgress';
import { ResultsPanel } from './components/ResultsPanel';
import { HistoryPanel } from './components/HistoryPanel';

function App() {
  const {
    activeTab, setActiveTab, isLoading,
    showHistoryDropdown, setShowHistoryDropdown, history,
  } = useStore();

  const switchTab = (tab: 'url' | 'project' | 'checklist') => {
    setActiveTab(tab);
  };

  const isChecklist = activeTab === 'checklist';

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

      {isChecklist ? (
        // Checklist tab: workspace-checklist dùng layout 3 cột
        // Col 1 (280px): scan source info + OWASP grid + Context checklist
        // Col 2+3 (1fr): Design Review + Scan summary — chiếm toàn bộ không gian còn lại
        <div className="workspace workspace-checklist">
          <aside className="left-panel">
            <ChecklistPanel />
          </aside>
          <main className="right-panel checklist-right-panel">
            {isLoading ? <ScanProgress /> : <ChecklistRightPanel />}
          </main>
        </div>
      ) : (
        // URL/Project tab: layout 2 cột gốc
        <div className="workspace">
          <aside className="left-panel">
            {activeTab === 'url'     && <UrlScanForm />}
            {activeTab === 'project' && <ProjectScanForm />}
          </aside>
          <main className="right-panel">
            {isLoading ? <ScanProgress /> : <ResultsPanel />}
          </main>
        </div>
      )}
    </div>
  );
}

export default App;
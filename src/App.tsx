import { useEffect, useState } from 'react';
import { AIChatWidget } from './components/AIChatWidget';
import { ChecklistPanel } from './components/ChecklistPanel';
import { ChecklistRightPanel } from './components/ChecklistRightPanel';
import { HistoryPanel } from './components/HistoryPanel';
import { ProjectScanForm } from './components/ProjectScanForm';
import { ResultsPanel } from './components/ResultsPanel';
import { ScanProgress } from './components/ScanProgress';
import { UrlScanForm } from './components/UrlScanForm';
import { useStore } from './store/useStore';

function App() {
  const {
    activeTab, setActiveTab, isLoading,
    showHistoryDropdown, setShowHistoryDropdown, history,
    themeMode, toggleThemeMode,
    performUrlScan, performProjectScan, exportReport,
  } = useStore();
  const [showShortcutHelp, setShowShortcutHelp] = useState(false);

  useEffect(() => {
    document.body.classList.remove('theme-dark', 'theme-light');
    document.body.classList.add(`theme-${themeMode}`);
  }, [themeMode]);

  useEffect(() => {
    const isEditable = (target: EventTarget | null) => {
      const el = target as HTMLElement | null;
      if (!el) return false;
      const tag = el.tagName.toLowerCase();
      return tag === 'input' || tag === 'textarea' || tag === 'select' || el.isContentEditable;
    };

    const onKeyDown = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (!mod) return;

      const key = e.key.toLowerCase();
      const editable = isEditable(e.target);

      if (key === '/') {
        e.preventDefault();
        setShowShortcutHelp((v) => !v);
        return;
      }

      if (editable) return;

      if (key === '1') {
        e.preventDefault();
        setActiveTab('url');
        return;
      }

      if (key === '5') {
        e.preventDefault();
        setActiveTab('checklist');
        return;
      }

      if (key === '6') {
        e.preventDefault();
        setShowHistoryDropdown(!showHistoryDropdown);
        return;
      }

      if (key === '7') {
        e.preventDefault();
        exportReport('html');
        return;
      }

      if (key === '8') {
        e.preventDefault();
        toggleThemeMode();
        return;
      }

      if (key === 'enter') {
        e.preventDefault();
        if (activeTab === 'url') void performUrlScan();
        if (activeTab === 'project') void performProjectScan();
      }
    };

    const onEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setShowShortcutHelp(false);
        setShowHistoryDropdown(false);
      }
    };

    window.addEventListener('keydown', onKeyDown);
    window.addEventListener('keydown', onEsc);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
      window.removeEventListener('keydown', onEsc);
    };
  }, [
    activeTab,
    exportReport,
    performProjectScan,
    performUrlScan,
    setActiveTab,
    setShowHistoryDropdown,
    showHistoryDropdown,
    toggleThemeMode,
  ]);

  const switchTab = (tab: 'url' | 'project' | 'checklist') => {
    setActiveTab(tab);
  };

  const isChecklist = activeTab === 'checklist';
  const isUrlScan = activeTab === 'url';

  const scanLayoutTitle = isUrlScan ? 'URL Scan' : 'Project Scan';
  const scanLayoutHint = isUrlScan
    ? 'Khu vực trái để cấu hình mục tiêu quét, khu vực phải để phân tích kết quả chi tiết.'
    : 'Khu vực trái để chọn dự án, khu vực phải để theo dõi rủi ro và findings.';

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

        <button
          className="btn-secondary theme-toggle"
          onClick={toggleThemeMode}
          title={themeMode === 'dark' ? 'Chuyển sang light mode (Ctrl/Cmd+8)' : 'Chuyển sang dark mode (Ctrl/Cmd+8)'}
        >
          {themeMode === 'dark' ? '☀ Light' : '🌙 Dark'}
        </button>

        <button
          className="btn-secondary shortcut-help-trigger"
          onClick={() => setShowShortcutHelp(true)}
          title="Xem phím tắt (Ctrl/Cmd+/)"
        >
          ⌨ Shortcuts
        </button>

        <div className="status-indicator">
          <div className={`status-dot ${isLoading ? 'active' : ''}`} />
          {isLoading ? 'Scanning' : 'Ready'}
        </div>
      </header>

      {isChecklist ? (
        <div className="workspace workspace-checklist-v2">
          <aside className="left-panel checklist-control-panel">
            <div className="layout-panel-head">
              <div className="layout-panel-title">Checklist Input</div>
              <div className="layout-panel-sub">Thu thập ngữ cảnh và danh mục OWASP làm nguồn cho vòng review.</div>
            </div>
            <ChecklistPanel />
          </aside>
          <main className="right-panel checklist-main-panel checklist-right-panel">
            {isLoading ? <ScanProgress /> : <ChecklistRightPanel />}
          </main>
        </div>
      ) : (
        <div className="workspace workspace-scan-v2">
          <aside className="left-panel scan-config-panel">
            <div className="layout-panel-head">
              <div className="layout-panel-title">{scanLayoutTitle}</div>
              <div className="layout-panel-sub">{scanLayoutHint}</div>
            </div>
            {activeTab === 'url'     && <UrlScanForm />}
            {activeTab === 'project' && <ProjectScanForm />}
          </aside>
          <main className="right-panel scan-results-panel">
            {isLoading ? <ScanProgress /> : <ResultsPanel />}
          </main>
        </div>
      )}

      {showShortcutHelp && (
        <div className="shortcut-overlay" onClick={() => setShowShortcutHelp(false)}>
          <div className="shortcut-modal" onClick={(e) => e.stopPropagation()}>
            <div className="shortcut-modal-head">
              <div className="shortcut-title">Phím tắt nhanh</div>
              <button className="btn-secondary" onClick={() => setShowShortcutHelp(false)}>Đóng</button>
            </div>
            <div className="shortcut-list">
              <div className="shortcut-row"><span>Chuyển URL Scan</span><kbd>Ctrl/Cmd + 1</kbd></div>
              <div className="shortcut-row"><span>Mở Checklist</span><kbd>Ctrl/Cmd + 5</kbd></div>
              <div className="shortcut-row"><span>Mở/đóng History</span><kbd>Ctrl/Cmd + 6</kbd></div>
              <div className="shortcut-row"><span>Xuất báo cáo HTML</span><kbd>Ctrl/Cmd + 7</kbd></div>
              <div className="shortcut-row"><span>Đổi Dark/Light mode</span><kbd>Ctrl/Cmd + 8</kbd></div>
              <div className="shortcut-row"><span>Bắt đầu scan tab hiện tại</span><kbd>Ctrl/Cmd + Enter</kbd></div>
              <div className="shortcut-row"><span>Hiện/ẩn bảng phím tắt</span><kbd>Ctrl/Cmd + /</kbd></div>
              <div className="shortcut-row"><span>Đóng panel/modal</span><kbd>Esc</kbd></div>
            </div>
          </div>
        </div>
      )}
      {/* AI Chat Widget — floating overlay, visible on all tabs */}
      <AIChatWidget />
    </div>
  );
}

export default App;
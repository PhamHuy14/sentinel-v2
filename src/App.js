import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useStore } from './store/useStore';
import { UrlScanForm } from './components/UrlScanForm';
import { ProjectScanForm } from './components/ProjectScanForm';
import { ChecklistPanel } from './components/ChecklistPanel';
import { ChecklistRightPanel } from './components/ChecklistRightPanel';
import { ScanProgress } from './components/ScanProgress';
import { ResultsPanel } from './components/ResultsPanel';
import { HistoryPanel } from './components/HistoryPanel';
function App() {
    const { activeTab, setActiveTab, isLoading, showHistoryDropdown, setShowHistoryDropdown, history, } = useStore();
    const switchTab = (tab) => {
        setActiveTab(tab);
    };
    const isChecklist = activeTab === 'checklist';
    return (_jsxs("div", { className: "app-shell", children: [_jsxs("header", { className: "app-header", children: [_jsxs("div", { className: "app-logo", children: [_jsx("div", { className: "logo-icon", children: "S" }), _jsxs("div", { children: [_jsx("div", { className: "logo-text", children: "SENTINEL" }), _jsx("div", { className: "logo-sub", children: "OWASP 2025" })] })] }), _jsxs("nav", { className: "nav-tabs", children: [_jsx("button", { className: `nav-tab ${activeTab === 'url' ? 'active' : ''}`, onClick: () => switchTab('url'), children: "URL Scan" }), _jsx("button", { className: `nav-tab ${activeTab === 'project' ? 'active' : ''}`, onClick: () => switchTab('project'), children: "Project Scan" }), _jsx("button", { className: `nav-tab ${activeTab === 'checklist' ? 'active' : ''}`, onClick: () => switchTab('checklist'), children: "Checklist" })] }), _jsx("div", { className: "header-gap" }), _jsxs("div", { className: "hist-btn-wrap", children: [_jsxs("button", { className: `btn-secondary hist-trigger ${showHistoryDropdown ? 'active' : ''}`, onClick: () => setShowHistoryDropdown(!showHistoryDropdown), title: "Scan History", children: ["\uD83D\uDD50 History ", history.length > 0 && _jsx("span", { className: "hist-badge", children: history.length })] }), showHistoryDropdown && _jsx(HistoryPanel, {})] }), _jsxs("div", { className: "status-indicator", children: [_jsx("div", { className: `status-dot ${isLoading ? 'active' : ''}` }), isLoading ? 'Scanning' : 'Ready'] })] }), isChecklist ? (
            // Checklist tab: workspace-checklist dùng layout 3 cột
            // Col 1 (280px): scan source info + OWASP grid + Context checklist
            // Col 2+3 (1fr): Design Review + Scan summary — chiếm toàn bộ không gian còn lại
            _jsxs("div", { className: "workspace workspace-checklist", children: [_jsx("aside", { className: "left-panel", children: _jsx(ChecklistPanel, {}) }), _jsx("main", { className: "right-panel checklist-right-panel", children: isLoading ? _jsx(ScanProgress, {}) : _jsx(ChecklistRightPanel, {}) })] })) : (
            // URL/Project tab: layout 2 cột gốc
            _jsxs("div", { className: "workspace", children: [_jsxs("aside", { className: "left-panel", children: [activeTab === 'url' && _jsx(UrlScanForm, {}), activeTab === 'project' && _jsx(ProjectScanForm, {})] }), _jsx("main", { className: "right-panel", children: isLoading ? _jsx(ScanProgress, {}) : _jsx(ResultsPanel, {}) })] }))] }));
}
export default App;

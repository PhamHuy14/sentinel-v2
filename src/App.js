import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useStore } from './store/useStore';
import { UrlScanForm } from './components/UrlScanForm';
import { ProjectScanForm } from './components/ProjectScanForm';
import { ChecklistPanel } from './components/ChecklistPanel';
import { ScanProgress } from './components/ScanProgress';
import { ResultsPanel } from './components/ResultsPanel';
import { HistoryPanel } from './components/HistoryPanel';
function App() {
    const { activeTab, setActiveTab, isLoading, showHistoryDropdown, setShowHistoryDropdown, history, } = useStore();
    // Switch tab WITHOUT resetting scan results so data persists across tabs
    const switchTab = (tab) => {
        setActiveTab(tab);
        // NOTE: intentionally NOT calling resetScan() here so that:
        // 1. Checklist can read the latest project scan result
        // 2. Users can switch tabs and come back to their results
    };
    return (_jsxs("div", { className: "app-shell", children: [_jsxs("header", { className: "app-header", children: [_jsxs("div", { className: "app-logo", children: [_jsx("div", { className: "logo-icon", children: "S" }), _jsxs("div", { children: [_jsx("div", { className: "logo-text", children: "SENTINEL" }), _jsx("div", { className: "logo-sub", children: "OWASP 2025" })] })] }), _jsxs("nav", { className: "nav-tabs", children: [_jsx("button", { className: `nav-tab ${activeTab === 'url' ? 'active' : ''}`, onClick: () => switchTab('url'), children: "URL Scan" }), _jsx("button", { className: `nav-tab ${activeTab === 'project' ? 'active' : ''}`, onClick: () => switchTab('project'), children: "Project Scan" }), _jsx("button", { className: `nav-tab ${activeTab === 'checklist' ? 'active' : ''}`, onClick: () => switchTab('checklist'), children: "Checklist" })] }), _jsx("div", { className: "header-gap" }), _jsxs("div", { className: "hist-btn-wrap", children: [_jsxs("button", { className: `btn-secondary hist-trigger ${showHistoryDropdown ? 'active' : ''}`, onClick: () => setShowHistoryDropdown(!showHistoryDropdown), title: "Scan History", children: ["\uD83D\uDD50 History ", history.length > 0 && _jsx("span", { className: "hist-badge", children: history.length })] }), showHistoryDropdown && _jsx(HistoryPanel, {})] }), _jsxs("div", { className: "status-indicator", children: [_jsx("div", { className: `status-dot ${isLoading ? 'active' : ''}` }), isLoading ? 'Scanning' : 'Ready'] })] }), _jsxs("div", { className: "workspace", children: [_jsxs("aside", { className: "left-panel", children: [activeTab === 'url' && _jsx(UrlScanForm, {}), activeTab === 'project' && _jsx(ProjectScanForm, {}), activeTab === 'checklist' && _jsx(ChecklistPanel, {})] }), _jsx("main", { className: "right-panel", children: isLoading ? (_jsx(ScanProgress, {})) : activeTab === 'checklist' ? (_jsx(ChecklistResultsPanel, {})) : (_jsx(ResultsPanel, {})) })] })] }));
}
// Checklist right panel — shows project scan results summary if available
function ChecklistResultsPanel() {
    const { scanResult } = useStore();
    const projectScan = scanResult?.mode === 'project-scan' ? scanResult : null;
    if (!projectScan) {
        return (_jsxs("div", { className: "empty-state", children: [_jsx("div", { className: "empty-icon", children: "\u2611" }), _jsxs("p", { children: ["Ch\u1EA1y ", _jsx("strong", { style: { color: 'var(--accent)' }, children: "Project Scan" }), " \u0111\u1EC3 t\u1EF1 \u0111\u1ED9ng \u0111i\u1EC1n checklist OWASP t\u1EEB k\u1EBFt qu\u1EA3 qu\u00E9t th\u1EF1c t\u1EBF."] })] }));
    }
    // Show a summary of the project scan for reference on the right side
    const { findings, metadata } = projectScan;
    const bySev = metadata.summary.bySeverity;
    const byCat = metadata.summary.byCategory;
    const maxCat = Math.max(1, ...Object.values(byCat));
    return (_jsxs("div", { style: { display: 'flex', flexDirection: 'column', gap: 14 }, children: [_jsxs("div", { className: "section", children: [_jsx("div", { className: "section-label", children: "Project Scan \u2014 K\u1EBFt qu\u1EA3" }), _jsx("div", { style: { display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }, children: ['critical', 'high', 'medium', 'low'].map(sev => {
                            const n = bySev[sev] || 0;
                            if (!n)
                                return null;
                            const colors = {
                                critical: 'chip-crit', high: 'chip-high', medium: 'chip-med', low: 'chip-low'
                            };
                            return (_jsxs("span", { className: `sev-chip ${colors[sev]}`, children: [sev.slice(0, 4).toUpperCase(), " ", n] }, sev));
                        }) }), _jsxs("div", { style: { display: 'flex', flexDirection: 'column', gap: 5 }, children: [_jsx("div", { className: "rg-bars-hdr", children: "Ph\u00E2n b\u1ED5 theo OWASP Category" }), Object.entries(byCat).sort((a, b) => b[1] - a[1]).map(([cat, count]) => (_jsxs("div", { className: "rg-bar-row", children: [_jsx("span", { className: "rg-bar-cat", children: cat }), _jsx("div", { className: "rg-bar-track", children: _jsx("div", { className: "rg-bar-fill", style: { width: `${(count / maxCat) * 100}%`, background: 'var(--accent)' } }) }), _jsx("span", { className: "rg-bar-n", children: count })] }, cat)))] })] }), metadata.scannedFiles !== undefined && (_jsxs("div", { className: "section", children: [_jsx("div", { className: "section-label", children: "Th\u1ED1ng k\u00EA" }), _jsxs("div", { className: "meta-table", children: [metadata.scannedFiles !== undefined && (_jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-key", children: "Files scanned" }), _jsx("span", { className: "meta-val", children: metadata.scannedFiles })] })), metadata.packageJsonFound !== undefined && (_jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-key", children: "package.json found" }), _jsx("span", { className: `meta-val ${metadata.packageJsonFound ? 'ok' : ''}`, children: metadata.packageJsonFound ? 'Yes' : 'No' })] })), metadata.configCount !== undefined && (_jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-key", children: "Config files" }), _jsx("span", { className: "meta-val", children: metadata.configCount })] })), _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-key", children: "Total findings" }), _jsx("span", { className: "meta-val", children: findings.length })] })] })] }))] }));
}
export default App;

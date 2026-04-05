import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useStore } from '../store/useStore';
function timeAgo(ts) {
    const m = Math.floor((Date.now() - ts) / 60000);
    if (m < 1)
        return 'just now';
    if (m < 60)
        return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24)
        return `${h}h ago`;
    return `${Math.floor(h / 24)}d ago`;
}
function riskScoreColor(score) {
    if (!score)
        return 'var(--text-3)';
    if (score >= 70)
        return 'var(--crit)';
    if (score >= 40)
        return 'var(--high)';
    if (score >= 15)
        return 'var(--med)';
    return 'var(--low)';
}
export const HistoryPanel = () => {
    const { history, restoreFromHistory, clearHistory, setShowHistoryDropdown } = useStore();
    return (_jsxs(_Fragment, { children: [_jsx("div", { className: "hist-backdrop", onClick: () => setShowHistoryDropdown(false) }), _jsxs("div", { className: "hist-dropdown", children: [_jsxs("div", { className: "hist-hdr", children: [_jsx("span", { className: "hist-hdr-title", children: "Scan History" }), _jsxs("div", { style: { display: 'flex', gap: 8, alignItems: 'center' }, children: [history.length > 0 && (_jsx("button", { className: "btn-link", style: { fontSize: 11, color: 'var(--text-3)' }, onClick: clearHistory, children: "Clear all" })), _jsx("button", { className: "btn-link", style: { fontSize: 16, lineHeight: 1 }, onClick: () => setShowHistoryDropdown(false), children: "\u00D7" })] })] }), history.length === 0 ? (_jsx("div", { className: "hist-empty", children: "No scan history yet" })) : (_jsx("div", { className: "hist-list", children: history.map((entry) => {
                            const { bySeverity, total } = entry.summary;
                            return (_jsxs("button", { className: "hist-entry", onClick: () => restoreFromHistory(entry.id), children: [_jsxs("div", { className: "hist-entry-top", children: [_jsx("span", { className: "hist-entry-mode", children: entry.mode === 'url-scan' ? '🌐' : '📁' }), _jsx("span", { className: "hist-entry-target", children: entry.target }), _jsx("span", { className: "hist-entry-time", children: timeAgo(entry.ts) })] }), _jsxs("div", { className: "hist-entry-bottom", children: [_jsxs("div", { className: "hist-entry-chips", children: [(bySeverity.critical || 0) > 0 && _jsxs("span", { className: "sev-chip chip-crit", children: [bySeverity.critical, " CRIT"] }), (bySeverity.high || 0) > 0 && _jsxs("span", { className: "sev-chip chip-high", children: [bySeverity.high, " HIGH"] }), (bySeverity.medium || 0) > 0 && _jsxs("span", { className: "sev-chip chip-med", children: [bySeverity.medium, " MED"] }), (bySeverity.low || 0) > 0 && _jsxs("span", { className: "sev-chip chip-low", children: [bySeverity.low, " LOW"] }), total === 0 && _jsx("span", { className: "sev-chip chip-info", children: "Clean \u2713" })] }), entry.riskScore !== undefined && (_jsxs("div", { className: "hist-risk-score", style: { color: riskScoreColor(entry.riskScore) }, children: ["Risk ", entry.riskScore] }))] })] }, entry.id));
                        }) }))] })] }));
};

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
    return (_jsxs(_Fragment, { children: [_jsx("div", { className: "hist-backdrop", onClick: () => setShowHistoryDropdown(false) }), _jsxs("div", { className: "hist-dropdown", children: [_jsxs("div", { className: "hist-hdr", children: [_jsx("span", { className: "hist-hdr-title", children: "Scan History" }), _jsxs("div", { className: "hist-hdr-actions", style: { display: 'flex', gap: 8, alignItems: 'center' }, children: [history.length > 0 && (_jsxs("button", { className: "btn-history-clear", onClick: () => { if (window.confirm('Xoá toàn bộ lịch sử scan?'))
                                            clearHistory(); }, title: "Xo\u00E1 to\u00E0n b\u1ED9 l\u1ECBch s\u1EED \u2014 kh\u00F4ng th\u1EC3 ho\u00E0n t\u00E1c", "aria-label": "Clear all history", children: [_jsx("span", { className: "btn-history-clear-icon", children: "\uD83D\uDDD1" }), _jsx("span", { children: "Clear All" })] })), _jsx("button", { className: "btn-history-close", onClick: () => setShowHistoryDropdown(false), title: "\u0110\u00F3ng panel l\u1ECBch s\u1EED", "aria-label": "Close history panel", children: "\u2715" })] })] }), history.length === 0 ? (_jsxs("div", { className: "hist-empty", children: [_jsx("div", { style: { fontSize: 24, opacity: 0.3, marginBottom: 6 }, children: "\uD83D\uDD50" }), _jsx("div", { children: "No scan history yet" }), _jsx("div", { style: { fontSize: 10, color: 'var(--text-3)', marginTop: 4 }, children: "Completed scans will appear here" })] })) : (_jsx("div", { className: "hist-list", children: history.map((entry) => {
                            const { bySeverity, total } = entry.summary;
                            return (_jsxs("button", { className: "hist-entry", onClick: () => restoreFromHistory(entry.id), title: `Restore: ${entry.target}`, children: [_jsxs("div", { className: "hist-entry-top", children: [_jsx("span", { className: "hist-entry-mode", title: entry.mode === 'url-scan' ? 'URL Scan' : 'Project Scan', children: entry.mode === 'url-scan' ? '🌐' : '📁' }), _jsx("span", { className: "hist-entry-target", children: entry.target }), _jsx("span", { className: "hist-entry-time", children: timeAgo(entry.ts) })] }), _jsxs("div", { className: "hist-entry-bottom", children: [_jsxs("div", { className: "hist-entry-chips", children: [(bySeverity.critical || 0) > 0 && _jsxs("span", { className: "sev-chip chip-crit", children: [bySeverity.critical, " CRIT"] }), (bySeverity.high || 0) > 0 && _jsxs("span", { className: "sev-chip chip-high", children: [bySeverity.high, " HIGH"] }), (bySeverity.medium || 0) > 0 && _jsxs("span", { className: "sev-chip chip-med", children: [bySeverity.medium, " MED"] }), (bySeverity.low || 0) > 0 && _jsxs("span", { className: "sev-chip chip-low", children: [bySeverity.low, " LOW"] }), total === 0 && _jsx("span", { className: "sev-chip chip-info", children: "Clean \u2713" })] }), entry.riskScore !== undefined && (_jsxs("div", { className: "hist-risk-score", style: { color: riskScoreColor(entry.riskScore) }, title: `Risk score: ${entry.riskScore}/100`, children: ["Risk ", entry.riskScore] }))] })] }, entry.id));
                        }) })), history.length > 0 && (_jsxs("div", { style: {
                            padding: '8px 14px',
                            borderTop: '1px solid var(--border-dim)',
                            fontSize: 10,
                            color: 'var(--text-3)',
                            textAlign: 'center',
                            fontFamily: 'var(--mono)',
                        }, children: [history.length, "/10 entries \u00B7 Click to restore"] }))] })] }));
};

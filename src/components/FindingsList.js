import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useStore } from '../store/useStore';
import { ReportExportButton } from './ReportExportButton';
const severityColor = (sev) => {
    switch (sev) {
        case 'critical': return 'badge-critical';
        case 'high': return 'badge-high';
        case 'medium': return 'badge-medium';
        default: return 'badge-low';
    }
};
export const FindingsList = () => {
    const { urlScanResult, projectScanResult, activeTab, error, isLoading } = useStore();
    const scanResult = activeTab === 'url' ? urlScanResult : projectScanResult;
    if (isLoading) {
        return (_jsxs("div", { className: "card findings-panel", children: [_jsx("div", { className: "loading-spinner" }), _jsx("p", { children: "Scanning in progress..." })] }));
    }
    if (error) {
        return (_jsxs("div", { className: "card findings-panel error-panel", children: [_jsx("h3", { children: "\u26A0\uFE0F Scan Error" }), _jsx("p", { children: error })] }));
    }
    if (!scanResult) {
        return (_jsx("div", { className: "card findings-panel empty-panel", children: _jsx("p", { children: "\u2728 No scan performed yet. Use the form above to start a security assessment." }) }));
    }
    const { findings, metadata, mode, target } = scanResult;
    const summary = metadata.summary;
    return (_jsxs("div", { className: "card findings-panel", children: [_jsxs("div", { className: "findings-header", children: [_jsx("h3", { children: "\uD83D\uDD0E Scan Results" }), _jsx(ReportExportButton, {})] }), _jsxs("div", { className: "scan-info", children: [_jsxs("p", { children: [_jsx("strong", { children: "Mode:" }), " ", mode === 'url-scan' ? 'URL Scan' : 'Project Scan'] }), _jsxs("p", { children: [_jsx("strong", { children: "Target:" }), " ", target || scanResult.scannedUrl] }), scanResult.finalUrl && _jsxs("p", { children: [_jsx("strong", { children: "Final URL:" }), " ", scanResult.finalUrl] }), scanResult.status && _jsxs("p", { children: [_jsx("strong", { children: "HTTP Status:" }), " ", scanResult.status] }), scanResult.title && _jsxs("p", { children: [_jsx("strong", { children: "Page Title:" }), " ", scanResult.title] })] }), _jsxs("div", { className: "summary-stats", children: [_jsxs("div", { className: "stat", children: ["Total Findings: ", _jsx("strong", { children: summary.total })] }), _jsx("div", { className: "stat-categories", children: Object.entries(summary.bySeverity).map(([sev, count]) => (_jsxs("span", { className: `stat-badge ${severityColor(sev)}`, children: [sev, ": ", count] }, sev))) })] }), findings.length === 0 ? (_jsx("p", { className: "no-findings", children: "\u2705 No security issues detected (based on heuristics)." })) : (_jsx("div", { className: "findings-list", children: findings.map((finding, idx) => (_jsxs("div", { className: `finding-item ${severityColor(finding.severity)}`, children: [_jsxs("div", { className: "finding-title", children: [_jsx("span", { className: `severity-dot ${severityColor(finding.severity)}` }), _jsx("strong", { children: finding.title }), _jsx("span", { className: "rule-id", children: finding.ruleId })] }), _jsxs("div", { className: "finding-meta", children: [_jsxs("span", { children: ["OWASP: ", finding.owaspCategory] }), _jsxs("span", { children: ["Confidence: ", finding.confidence] }), _jsxs("span", { children: ["Collector: ", finding.collector] })] }), _jsxs("div", { className: "finding-location", children: ["\uD83D\uDCCD ", finding.location || finding.target] }), finding.evidence.length > 0 && (_jsxs("div", { className: "finding-evidence", children: [_jsx("strong", { children: "Evidence:" }), _jsx("ul", { children: finding.evidence.slice(0, 3).map((e, i) => _jsx("li", { children: e }, i)) })] })), _jsxs("div", { className: "finding-remediation", children: [_jsx("strong", { children: "Remediation:" }), " ", finding.remediation] })] }, idx))) }))] }));
};

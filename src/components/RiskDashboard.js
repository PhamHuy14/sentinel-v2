import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useId } from 'react';
const SEV_W = { critical: 10, high: 7, medium: 4, low: 1 };
function calcRiskScore(findings) {
    if (!findings.length)
        return 0;
    return Math.min(100, findings.reduce((s, f) => s + (SEV_W[f.severity] || 0), 0));
}
function riskInfo(s) {
    if (s >= 70)
        return { label: 'CRITICAL RISK', color: 'var(--crit)' };
    if (s >= 40)
        return { label: 'HIGH RISK', color: 'var(--high)' };
    if (s >= 15)
        return { label: 'MEDIUM RISK', color: 'var(--med)' };
    if (s > 0)
        return { label: 'LOW RISK', color: 'var(--low)' };
    return { label: 'CLEAN', color: 'var(--low)' };
}
const Gauge = ({ score, color, clipId }) => {
    const R = 72, cx = 100, cy = 96;
    const circ = 2 * Math.PI * R;
    const halfC = Math.PI * R;
    const filled = (score / 100) * halfC;
    const offset = circ * 0.75;
    const rot = `rotate(-90, ${cx}, ${cy})`;
    return (_jsxs("svg", { viewBox: "0 0 200 104", width: "175", height: "91", style: { overflow: 'visible' }, children: [_jsx("defs", { children: _jsx("clipPath", { id: clipId, children: _jsx("rect", { x: "0", y: "0", width: "200", height: "96" }) }) }), _jsxs("g", { clipPath: `url(#${clipId})`, children: [_jsx("circle", { cx: cx, cy: cy, r: R, fill: "none", stroke: "var(--border)", strokeWidth: "13", strokeLinecap: "round", strokeDasharray: `${halfC} ${circ - halfC}`, strokeDashoffset: offset, transform: rot }), _jsx("circle", { cx: cx, cy: cy, r: R, fill: "none", stroke: color, strokeWidth: "13", strokeLinecap: "round", strokeDasharray: `${filled} ${circ - filled}`, strokeDashoffset: offset, transform: rot, style: { transition: 'stroke-dasharray 0.7s cubic-bezier(.4,0,.2,1)' } })] }), _jsx("text", { x: cx, y: cy - 7, textAnchor: "middle", fontSize: "30", fontWeight: "700", fontFamily: "var(--mono)", fill: "var(--text)", children: score }), _jsx("text", { x: cx, y: cy + 10, textAnchor: "middle", fontSize: "9", fill: "var(--text-3)", children: "/100" })] }));
};
// Risk Trend sparkline (compare with previous scan of same target in history)
const RiskTrend = ({ current, previous }) => {
    if (previous == null)
        return null;
    const diff = current - previous;
    const arrow = diff > 0 ? '▲' : diff < 0 ? '▼' : '–';
    const cls = diff > 0 ? 'trend-up' : diff < 0 ? 'trend-down' : 'trend-flat';
    return (_jsxs("div", { className: `rg-trend ${cls}`, children: [_jsx("span", { className: "rg-trend-arrow", children: arrow }), _jsxs("span", { className: "rg-trend-val", children: [Math.abs(diff), " vs prev"] })] }));
};
// Tech Stack badges
const TechStackPanel = ({ techStack }) => {
    if (!techStack?.length)
        return null;
    return (_jsxs("div", { className: "rg-tech-stack", children: [_jsx("div", { className: "rg-bars-hdr", children: "Tech Stack" }), _jsx("div", { className: "rg-tech-chips", children: techStack.map(t => _jsx("span", { className: "tech-chip", children: t }, t)) })] }));
};
// Attack Surface panel
const AttackSurfacePanel = ({ attackSurface }) => {
    if (!attackSurface)
        return null;
    const score = attackSurface.score;
    const cls = score >= 60 ? 'as-crit' : score >= 30 ? 'as-high' : 'as-ok';
    const top = attackSurface.exposedRoutes.slice(0, 5);
    return (_jsxs("div", { className: "rg-attack-surface", children: [_jsx("div", { className: "rg-bars-hdr", children: "Attack Surface" }), _jsxs("div", { className: `as-score-badge ${cls}`, children: [score, _jsx("span", { style: { fontSize: 10, fontWeight: 400 }, children: "/100" })] }), top.length > 0 && (_jsx("div", { className: "as-routes", children: top.map(r => (_jsxs("div", { className: "as-route-row", children: [_jsx("span", { className: "as-route-path", children: r.route }), _jsx("span", { className: `as-route-status ${r.status === 200 ? 'status-ok' : 'status-redir'}`, children: r.status })] }, r.route))) }))] }));
};
export const RiskDashboard = ({ scanResult }) => {
    const gaugeClipId = useId().replace(/:/g, '_'); // unique per instance
    const { findings, metadata } = scanResult;
    const score = calcRiskScore(findings);
    const { label, color } = riskInfo(score);
    const byCat = metadata.summary.byCategory;
    const maxCat = Math.max(1, ...Object.values(byCat));
    const bySev = metadata.summary.bySeverity;
    return (_jsxs("div", { className: "risk-dashboard", children: [_jsxs("div", { className: "rg-top-row", children: [_jsxs("div", { className: "rg-gauge-wrap", children: [_jsx(Gauge, { score: score, color: color, clipId: `rg-clip-${gaugeClipId}` }), _jsx("div", { className: "rg-risk-label", style: { color }, children: label }), _jsx("div", { className: "rg-mode-label", children: scanResult.mode === 'url-scan' ? 'URL Scan' : 'Project Scan' }), _jsx(RiskTrend, { current: score, previous: null })] }), _jsx("div", { className: "rg-sev-summary", children: ['critical', 'high', 'medium', 'low'].map((sev) => {
                            const n = bySev[sev] || 0;
                            return (_jsxs("div", { className: `rg-sev-box sev-box-${sev}`, children: [_jsx("span", { className: "rg-sev-n", children: n }), _jsx("span", { className: "rg-sev-label", children: sev.slice(0, 4).toUpperCase() })] }, sev));
                        }) }), Object.keys(byCat).length > 0 && (_jsxs("div", { className: "rg-bars", children: [_jsx("div", { className: "rg-bars-hdr", children: "By OWASP Category" }), Object.entries(byCat).sort((a, b) => b[1] - a[1]).map(([cat, count]) => (_jsxs("div", { className: "rg-bar-row", children: [_jsx("span", { className: "rg-bar-cat", children: cat }), _jsx("div", { className: "rg-bar-track", children: _jsx("div", { className: "rg-bar-fill", style: { width: `${(count / maxCat) * 100}%`, background: color } }) }), _jsx("span", { className: "rg-bar-n", children: count })] }, cat)))] }))] }), (metadata.techStack || metadata.attackSurface) && (_jsxs("div", { className: "rg-bottom-row", children: [_jsx(TechStackPanel, { techStack: metadata.techStack }), _jsx(AttackSurfacePanel, { attackSurface: metadata.attackSurface }), metadata.cspAnalysis && !metadata.cspAnalysis.present && (_jsxs("div", { className: "rg-csp-warn", children: [_jsx("span", { className: "rg-csp-icon", children: "\u26A0" }), _jsx("span", { children: "Content-Security-Policy header absent" })] })), metadata.cspAnalysis?.issues && metadata.cspAnalysis.issues.length > 0 && metadata.cspAnalysis.present && (_jsxs("div", { className: "rg-csp-warn", children: [_jsx("span", { className: "rg-csp-icon", children: "\u26A0" }), _jsxs("span", { children: ["CSP issues: ", metadata.cspAnalysis.issues[0]] })] }))] }))] }));
};

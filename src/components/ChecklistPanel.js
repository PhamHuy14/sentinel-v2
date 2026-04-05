import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useEffect } from 'react';
import { useStore } from '../store/useStore';
// OWASP Top 10 2025 — full list
const OWASP_CATS = [
    { id: 'A01', name: 'Broken Access Control' },
    { id: 'A02', name: 'Cryptographic Failures' },
    { id: 'A03', name: 'Injection' },
    { id: 'A04', name: 'Insecure Design' },
    { id: 'A05', name: 'Security Misconfiguration' },
    { id: 'A06', name: 'Vulnerable & Outdated Components' },
    { id: 'A07', name: 'ID & Authentication Failures' },
    { id: 'A08', name: 'Software & Data Integrity Failures' },
    { id: 'A09', name: 'Security Logging & Monitoring Failures' },
    { id: 'A10', name: 'Server-Side Request Forgery (SSRF)' },
];
const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };
function buildChecklistFromFindings(findings) {
    // Group findings by OWASP category
    const byCategory = {};
    for (const f of findings) {
        const key = f.owaspCategory?.toUpperCase() || 'OTHER';
        if (!byCategory[key])
            byCategory[key] = [];
        byCategory[key].push(f);
    }
    return OWASP_CATS.map(cat => {
        // Match A01, A01:2025, A1 etc.
        const hits = Object.entries(byCategory).filter(([k]) => k.includes(cat.id));
        const allFindings = hits.flatMap(([, fs]) => fs);
        const maxSev = allFindings.reduce((acc, f) => {
            return SEV_ORDER[f.severity] > SEV_ORDER[acc] ? f.severity : acc;
        }, 'low');
        return {
            ...cat,
            count: allFindings.length,
            severity: allFindings.length > 0 ? maxSev : null,
            findings: allFindings.slice(0, 3), // top 3 for preview
        };
    });
}
function sevColor(sev) {
    if (!sev)
        return 'var(--text-3)';
    if (sev === 'critical')
        return 'var(--crit)';
    if (sev === 'high')
        return 'var(--high)';
    if (sev === 'medium')
        return 'var(--med)';
    return 'var(--low)';
}
function sevBg(sev) {
    if (!sev)
        return 'var(--bg-input)';
    if (sev === 'critical')
        return 'var(--crit-bg)';
    if (sev === 'high')
        return 'var(--high-bg)';
    if (sev === 'medium')
        return 'var(--med-bg)';
    return 'var(--low-bg)';
}
export const ChecklistPanel = () => {
    const { checklist, loadChecklist, scanResult } = useStore();
    useEffect(() => {
        loadChecklist();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);
    // Use project scan result if available
    const projectScan = scanResult?.mode === 'project-scan' ? scanResult : null;
    const hasProjectScan = !!projectScan;
    const items = hasProjectScan ? buildChecklistFromFindings(projectScan.findings) : null;
    const covered = items ? items.filter(i => i.count > 0).length : 0;
    const total = OWASP_CATS.length;
    return (_jsxs(_Fragment, { children: [_jsxs("div", { className: "section", children: [_jsx("div", { className: "section-label", children: "OWASP Top 10 \u2014 2025" }), hasProjectScan ? (_jsxs(_Fragment, { children: [_jsxs("div", { className: "chk-coverage", children: [_jsxs("div", { className: "chk-coverage-hdr", children: [_jsx("span", { children: "Coverage" }), _jsxs("span", { className: "chk-coverage-frac", children: [covered, "/", total, " categories"] })] }), _jsx("div", { className: "chk-coverage-track", children: _jsx("div", { className: "chk-coverage-fill", style: { width: `${(covered / total) * 100}%` } }) }), _jsx("div", { className: "chk-coverage-label", children: covered === 0
                                            ? 'No issues detected across OWASP categories'
                                            : `${covered} categories with findings from Project Scan` })] }), _jsx("div", { className: "checklist-grid-adv", children: items.map(cat => (_jsxs("div", { className: `chk-item ${cat.count > 0 ? 'chk-item-hit' : ''}`, style: {
                                        borderColor: cat.count > 0 ? sevColor(cat.severity) + '55' : undefined,
                                        background: cat.count > 0 ? sevBg(cat.severity) : undefined,
                                    }, children: [_jsxs("div", { className: "chk-item-header", children: [_jsx("span", { className: "chk-id", style: { color: cat.count > 0 ? sevColor(cat.severity) : undefined }, children: cat.id }), cat.count > 0 && (_jsx("span", { className: "chk-badge", style: { color: sevColor(cat.severity), borderColor: sevColor(cat.severity) + '55' }, children: cat.count })), cat.count === 0 && (_jsx("span", { className: "chk-pass", children: "\u2713" }))] }), _jsx("div", { className: "chk-name", children: cat.name }), cat.count > 0 && cat.severity && (_jsx("div", { className: "chk-sev", style: { color: sevColor(cat.severity) }, children: cat.severity }))] }, cat.id))) })] })) : (_jsxs(_Fragment, { children: [_jsxs("div", { className: "chk-empty-hint", children: [_jsx("span", { className: "chk-empty-icon", children: "\uD83D\uDCC2" }), _jsxs("p", { children: ["Run a ", _jsx("strong", { children: "Project Scan" }), " to automatically populate this checklist with real findings mapped to each OWASP category."] })] }), _jsx("div", { className: "checklist-grid", children: (checklist?.categories ?? OWASP_CATS).map(cat => (_jsxs("div", { className: "checklist-item", children: [_jsx("div", { className: "checklist-id", children: cat.id }), _jsx("div", { className: "checklist-name", children: cat.name })] }, cat.id))) })] }))] }), hasProjectScan && projectScan.metadata?.techStack && projectScan.metadata.techStack.length > 0 && (_jsxs("div", { className: "section", style: { marginTop: '16px' }, children: [_jsx("div", { className: "section-label", children: "Context-Based Checklist" }), _jsxs("ul", { className: "design-q", children: [projectScan.metadata.techStack.includes('Node.js') || projectScan.metadata.techStack.includes('React') || projectScan.metadata.techStack.includes('Next.js') ? (_jsxs(_Fragment, { children: [_jsx("li", { children: "Check NPM packages for known vulnerabilities (npm audit)." }), _jsx("li", { children: "Verify JWT secret management and token expiration." }), _jsx("li", { children: "Ensure CORS is configured correctly for React/Next.js APIs." }), _jsx("li", { children: "Check for hardcoded secrets in `.env` files and `.js` source code." })] })) : null, projectScan.metadata.techStack.includes('Spring Boot') || projectScan.metadata.techStack.includes('Java') ? (_jsxs(_Fragment, { children: [_jsx("li", { children: "Verify Spring Actuator endpoints are properly secured and not exposing `/env` or `/heapdump`." }), _jsx("li", { children: "Check Maven/Gradle dependencies for known vulnerabilities." }), _jsx("li", { children: "Ensure proper validation for Spring Data REST endpoints." })] })) : null, projectScan.metadata.techStack.includes('PHP') || projectScan.metadata.techStack.includes('Laravel') ? (_jsxs(_Fragment, { children: [_jsx("li", { children: "Verify `APP_DEBUG` is false in production `.env`." }), _jsx("li", { children: "Check for open debugbar or telescope routes." }), _jsx("li", { children: "Ensure proper file upload validation to prevent RCE." })] })) : null, _jsxs("li", { children: ["Review `", projectScan.metadata.techStack.join(', '), "` specific configurations."] })] })] })), checklist?.designQuestions && checklist.designQuestions.length > 0 && (_jsxs("div", { className: "section", children: [_jsx("div", { className: "section-label", children: "Design Review" }), _jsx("ul", { className: "design-q", children: checklist.designQuestions.map((q, i) => (_jsx("li", { children: q }, i))) })] })), _jsx("button", { className: "btn-secondary", style: { width: '100%' }, onClick: () => window.owaspWorkbench?.openDocs?.('https://owasp.org/Top10/2025/'), children: "Open OWASP Docs" })] }));
};

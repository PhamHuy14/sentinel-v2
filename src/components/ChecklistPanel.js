import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useEffect, useState } from 'react';
import { useStore } from '../store/useStore';
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
export const CONTEXT_ITEM_DETAILS = {
    'chk-node-0': {
        todos: ['Chạy `npm audit` và fix critical/high vulnerabilities', 'Cập nhật dependencies lên version mới nhất', 'Dùng `npm audit --production` để focus vào production deps'],
        recommend: 'Tích hợp `npm audit` vào CI/CD pipeline. Dùng Snyk hoặc Dependabot để auto-detect vulnerabilities.',
    },
    'chk-node-1': {
        todos: ['Kiểm tra JWT secret không hardcode trong code', 'Đặt JWT expiration ngắn (15-60 phút)', 'Implement refresh token rotation', 'Blacklist token sau logout'],
        recommend: 'JWT secret phải >= 256-bit random. Dùng RS256 (asymmetric) thay vì HS256 nếu có nhiều service verify.',
    },
    'chk-node-2': {
        todos: ['Whitelist specific origins thay vì dùng `*`', 'Không allow credentials với wildcard origin', 'Test CORS với các origin khác nhau'],
        recommend: 'CORS configuration phải explicit. Tránh reflect Origin header mà không validate trước.',
    },
    'chk-node-3': {
        todos: ['Scan codebase tìm pattern: `password=`, `secret=`, `api_key=`', 'Dùng `.env` và add vào `.gitignore`', 'Rotate bất kỳ secret nào đã bị expose'],
        recommend: 'Dùng `git-secrets` hoặc `truffleHog` để scan git history. Secrets đã commit vào git phải được coi là compromised.',
    },
    'chk-java-0': {
        todos: ['Disable hoặc secure `/actuator/env`, `/actuator/heapdump`, `/actuator/trace`', 'Thêm Spring Security config cho actuator endpoints', 'Chỉ expose health + info nếu cần'],
        recommend: 'Trong production, chỉ expose `/actuator/health` và yêu cầu authentication. Không expose `/actuator/env` bao giờ.',
    },
    'chk-java-1': {
        todos: ['Chạy `mvn dependency-check:check` hoặc `gradle dependencyCheckAnalyze`', 'Update các dependency có CVE critical/high', 'Review OWASP Dependency Check report'],
        recommend: 'Tích hợp OWASP Dependency Check vào Maven/Gradle build. Fail build nếu có CVE score >= 7.0.',
    },
    'chk-java-2': {
        todos: ['Thêm `@PreAuthorize` cho REST endpoints', 'Validate input với Bean Validation (@Valid)', 'Disable Spring Data REST nếu không cần thiết'],
        recommend: 'Spring Data REST tự động expose repository. Dùng `@RepositoryRestResource(exported = false)` để disable, rồi expose manual endpoint có control tốt hơn.',
    },
    'chk-php-0': {
        todos: ['Set `APP_DEBUG=false` trong `.env` production', 'Kiểm tra `display_errors=Off` trong `php.ini`', 'Test xem error message có leak ra không'],
        recommend: 'Debug mode trong production là critical security risk — stack trace chứa path, DB query, credentials. Luôn dùng custom error page.',
    },
    'chk-php-1': {
        todos: ['Disable Laravel Debugbar trong production', 'Check Telescope routes có require auth không', 'Xóa hoặc restrict `/telescope` và `/_debugbar`'],
        recommend: 'Debugbar và Telescope chứa request history, queries, và có thể credentials. Chỉ enable trong local/staging với auth.',
    },
    'chk-php-2': {
        todos: ['Validate file extension (whitelist, không blacklist)', 'Validate MIME type thực sự (không trust Content-Type header)', 'Lưu file ngoài webroot hoặc dùng random filename', 'Scan virus nếu cho phép upload file executable'],
        recommend: 'Upload file là attack vector phổ biến nhất cho RCE. Không bao giờ trust tên file từ client. Dùng Flysystem + private disk.',
    },
};
const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };
export function buildChecklistFromFindings(findings) {
    const byCategory = {};
    for (const f of findings) {
        const key = f.owaspCategory?.toUpperCase() || 'OTHER';
        if (!byCategory[key])
            byCategory[key] = [];
        byCategory[key].push(f);
    }
    return OWASP_CATS.map(cat => {
        const hits = Object.entries(byCategory).filter(([k]) => k.includes(cat.id));
        const allFindings = hits.flatMap(([, fs]) => fs);
        const maxSev = allFindings.reduce((acc, f) => SEV_ORDER[f.severity] > SEV_ORDER[acc] ? f.severity : acc, 'low');
        return {
            ...cat,
            count: allFindings.length,
            severity: allFindings.length > 0 ? maxSev : null,
            findings: allFindings.slice(0, 3),
        };
    });
}
export function sevColor(sev) {
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
export function sevBg(sev) {
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
export const ChecklistItem = ({ id, label, hideCompleted, todos, recommend }) => {
    const { checkedChecklistItems, toggleChecklistItem } = useStore();
    const [expanded, setExpanded] = useState(false);
    const checked = checkedChecklistItems.includes(id);
    const hasDetails = !!(todos?.length || recommend);
    if (hideCompleted && checked)
        return null;
    return (_jsxs("div", { className: `chk-item-expandable ${checked ? 'chk-item-done' : ''}`, children: [_jsxs("div", { className: "chk-item-row", children: [_jsxs("label", { className: "chk-item-label-wrap", onClick: (e) => e.stopPropagation(), children: [_jsx("input", { type: "checkbox", checked: checked, onChange: () => toggleChecklistItem(id), className: "chk-checkbox-input" }), _jsx("span", { className: `chk-item-text ${checked ? 'chk-item-text-done' : ''}`, children: label })] }), hasDetails && (_jsx("button", { className: `chk-expand-btn ${expanded ? 'open' : ''}`, onClick: () => setExpanded(v => !v), title: expanded ? 'Thu gọn' : 'Xem todo & recommendations', children: expanded ? '▲' : '▼' }))] }), expanded && hasDetails && (_jsxs("div", { className: "chk-item-detail", children: [todos && todos.length > 0 && (_jsxs("div", { className: "chk-detail-section", children: [_jsx("div", { className: "chk-detail-label", children: "\u2705 Todo list" }), _jsx("ul", { className: "chk-todo-list", children: todos.map((t, i) => _jsx("li", { className: "chk-todo-item", children: t }, i)) })] })), recommend && (_jsxs("div", { className: "chk-detail-section", children: [_jsx("div", { className: "chk-detail-label", children: "\uD83D\uDCA1 Recommendation" }), _jsx("div", { className: "chk-recommend-text", children: recommend })] }))] }))] }));
};
// ─── Source banner ────────────────────────────────────────────────────────────
const ChecklistSourceBanner = ({ hasUrlLocal, hasProject, urlTarget }) => {
    if (!hasUrlLocal && !hasProject)
        return null;
    const isCombined = hasUrlLocal && hasProject;
    return (_jsxs("div", { style: {
            background: isCombined ? 'var(--accent-bg, rgba(99,102,241,0.08))' : 'var(--bg-card)',
            border: `1px solid ${isCombined ? 'var(--accent)' : 'var(--border)'}`,
            borderRadius: 8, padding: '10px 14px', marginBottom: 4,
            display: 'flex', flexDirection: 'column', gap: 6,
        }, children: [_jsx("div", { style: { display: 'flex', alignItems: 'center', gap: 8, fontWeight: 600, fontSize: 12 }, children: isCombined ? (_jsxs(_Fragment, { children: [_jsx("span", { style: { color: 'var(--accent)' }, children: "\uD83D\uDD17 Combined" }), _jsx("span", { style: { color: 'var(--text-3)', fontWeight: 400 }, children: "URL + Project" })] })) : hasUrlLocal ? (_jsxs(_Fragment, { children: [_jsx("span", { style: { color: 'var(--accent)' }, children: "\uD83C\uDF10 URL Scan" }), _jsx("span", { style: { color: 'var(--text-3)', fontWeight: 400, fontSize: 11 }, children: urlTarget })] })) : (_jsx("span", { style: { color: 'var(--accent)' }, children: "\uD83D\uDCC2 Project Scan" })) }), isCombined && (_jsxs("div", { style: { display: 'flex', gap: 6, flexWrap: 'wrap' }, children: [_jsxs("span", { style: { fontSize: 11, padding: '2px 8px', borderRadius: 20, background: 'var(--accent)', color: '#fff', fontWeight: 500 }, children: ["\uD83C\uDF10 ", urlTarget] }), _jsx("span", { style: { fontSize: 11, padding: '2px 8px', borderRadius: 20, background: 'var(--bg-input)', color: 'var(--text-2)', border: '1px solid var(--border)' }, children: "\uD83D\uDCC2 Project Scan" })] })), _jsxs("div", { style: { fontSize: 11, color: 'var(--text-3)', lineHeight: 1.5, borderTop: '1px solid var(--border)', paddingTop: 6, marginTop: 2 }, children: [_jsx("span", { style: { color: 'var(--med)', fontWeight: 600 }, children: "\u26A0\uFE0F " }), "Scan c\u1EA3 ", _jsx("strong", { children: "URL (localhost)" }), " l\u1EABn ", _jsx("strong", { children: "Project" }), " \u0111\u1EC3 t\u00ECm \u0111\u1EA7y \u0111\u1EE7 l\u1ED7 h\u1ED5ng."] })] }));
};
// ─── Main ChecklistPanel — chỉ hiện OWASP grid + Context checklist ────────────
export const ChecklistPanel = () => {
    const { loadChecklist, projectScanResult, urlScanResult, urlScanIsLocal, urlInput, getCombinedFindings, } = useStore();
    const [hideCompleted, setHideCompleted] = useState(false);
    useEffect(() => { loadChecklist(); }, []); // eslint-disable-line
    const hasProjectScan = !!projectScanResult;
    const hasUrlLocal = urlScanIsLocal && !!urlScanResult;
    const hasAny = hasProjectScan || hasUrlLocal;
    const urlTarget = urlScanResult?.scannedUrl || urlInput || '';
    if (!hasAny) {
        return (_jsxs("div", { className: "empty-state", children: [_jsx("div", { className: "empty-icon", children: "\uD83D\uDCC2" }), _jsxs("p", { children: ["Ch\u1EA1y ", _jsx("b", { children: "Project Scan" }), " ho\u1EB7c ", _jsx("b", { children: "URL Scan" }), " v\u1EDBi link ", _jsx("b", { children: "localhost" }), " \u0111\u1EC3 t\u1EA1o Checklist."] }), _jsxs("p", { style: { fontSize: 11, color: 'var(--text-3)', marginTop: 8, lineHeight: 1.5 }, children: [_jsx("span", { style: { color: 'var(--med)' }, children: "\u26A0\uFE0F" }), " N\u00EAn ch\u1EA1y ", _jsx("strong", { children: "c\u1EA3 hai" }), " \u0111\u1EC3 ph\u00E1t hi\u1EC7n \u0111\u1EA7y \u0111\u1EE7 l\u1ED7 h\u1ED5ng runtime v\u00E0 source code."] })] }));
    }
    const combinedFindings = getCombinedFindings();
    const items = buildChecklistFromFindings(combinedFindings);
    const covered = items.filter(i => i.count > 0).length;
    const total = OWASP_CATS.length;
    const techStack = projectScanResult?.metadata?.techStack || urlScanResult?.metadata?.techStack || [];
    const hasNode = techStack.some(t => ['Node.js', 'React', 'Next.js'].includes(t));
    const hasJava = techStack.some(t => ['Spring Boot', 'Java'].includes(t));
    const hasPHP = techStack.some(t => ['PHP', 'Laravel'].includes(t));
    const coverageLabel = (() => {
        if (covered === 0)
            return 'No issues detected';
        if (hasUrlLocal && hasProjectScan)
            return `${covered} categories — URL + Project`;
        if (hasUrlLocal)
            return `${covered} categories — URL Scan`;
        return `${covered} categories — Project Scan`;
    })();
    return (_jsxs("div", { style: { display: 'flex', flexDirection: 'column', gap: 14 }, children: [_jsx(ChecklistSourceBanner, { hasUrlLocal: hasUrlLocal, hasProject: hasProjectScan, urlTarget: urlTarget }), _jsxs("div", { className: "section", children: [_jsx("div", { className: "section-label", children: "OWASP Top 10 \u2014 2025" }), _jsxs("div", { className: "chk-coverage", children: [_jsxs("div", { className: "chk-coverage-hdr", children: [_jsx("span", { children: "Coverage" }), _jsxs("span", { className: "chk-coverage-frac", children: [covered, "/", total] })] }), _jsx("div", { className: "chk-coverage-track", children: _jsx("div", { className: "chk-coverage-fill", style: { width: `${(covered / total) * 100}%` } }) }), _jsx("div", { className: "chk-coverage-label", children: coverageLabel })] }), _jsx("div", { className: "checklist-grid-adv", children: items.map(cat => (_jsxs("div", { className: `chk-item ${cat.count > 0 ? 'chk-item-hit' : ''}`, style: { borderColor: cat.count > 0 ? sevColor(cat.severity) + '55' : undefined, background: cat.count > 0 ? sevBg(cat.severity) : undefined }, children: [_jsxs("div", { className: "chk-item-header", children: [_jsx("span", { className: "chk-id", style: { color: cat.count > 0 ? sevColor(cat.severity) : undefined }, children: cat.id }), cat.count > 0
                                            ? _jsx("span", { className: "chk-badge", style: { color: sevColor(cat.severity), borderColor: sevColor(cat.severity) + '55' }, children: cat.count })
                                            : _jsx("span", { className: "chk-pass", children: "\u2713" })] }), _jsx("div", { className: "chk-name", children: cat.name }), cat.count > 0 && cat.severity && (_jsx("div", { className: "chk-sev", style: { color: sevColor(cat.severity) }, children: cat.severity }))] }, cat.id))) })] }), techStack.length > 0 && (_jsxs("div", { className: "section", children: [_jsxs("div", { className: "chk-section-header", children: [_jsx("div", { className: "section-label", style: { marginBottom: 0 }, children: "Context-Based" }), _jsxs("button", { className: "btn-checklist-toggle", onClick: () => setHideCompleted(v => !v), children: [hideCompleted ? '👁️ Show' : '🙈 Hide', " Completed"] })] }), _jsxs("div", { className: "chk-items-list", children: [hasNode && (_jsxs(_Fragment, { children: [_jsx(ChecklistItem, { id: "chk-node-0", label: "NPM vulnerabilities (npm audit).", hideCompleted: hideCompleted, ...CONTEXT_ITEM_DETAILS['chk-node-0'] }), _jsx(ChecklistItem, { id: "chk-node-1", label: "JWT secret management & token expiration.", hideCompleted: hideCompleted, ...CONTEXT_ITEM_DETAILS['chk-node-1'] }), _jsx(ChecklistItem, { id: "chk-node-2", label: "CORS configuration for React/Next.js APIs.", hideCompleted: hideCompleted, ...CONTEXT_ITEM_DETAILS['chk-node-2'] }), _jsx(ChecklistItem, { id: "chk-node-3", label: "Hardcoded secrets in .env & source code.", hideCompleted: hideCompleted, ...CONTEXT_ITEM_DETAILS['chk-node-3'] })] })), hasJava && (_jsxs(_Fragment, { children: [_jsx(ChecklistItem, { id: "chk-java-0", label: "Spring Actuator kh\u00F4ng expose /env ho\u1EB7c /heapdump.", hideCompleted: hideCompleted, ...CONTEXT_ITEM_DETAILS['chk-java-0'] }), _jsx(ChecklistItem, { id: "chk-java-1", label: "Maven/Gradle dependencies CVE check.", hideCompleted: hideCompleted, ...CONTEXT_ITEM_DETAILS['chk-java-1'] }), _jsx(ChecklistItem, { id: "chk-java-2", label: "Spring Data REST endpoint validation.", hideCompleted: hideCompleted, ...CONTEXT_ITEM_DETAILS['chk-java-2'] })] })), hasPHP && (_jsxs(_Fragment, { children: [_jsx(ChecklistItem, { id: "chk-php-0", label: "APP_DEBUG=false trong .env production.", hideCompleted: hideCompleted, ...CONTEXT_ITEM_DETAILS['chk-php-0'] }), _jsx(ChecklistItem, { id: "chk-php-1", label: "Debugbar/Telescope routes kh\u00F4ng public.", hideCompleted: hideCompleted, ...CONTEXT_ITEM_DETAILS['chk-php-1'] }), _jsx(ChecklistItem, { id: "chk-php-2", label: "File upload validation \u0111\u1EC3 ng\u0103n RCE.", hideCompleted: hideCompleted, ...CONTEXT_ITEM_DETAILS['chk-php-2'] })] })), _jsx(ChecklistItem, { id: "chk-generic-0", label: `Review ${techStack.join(', ')} security configurations.`, hideCompleted: hideCompleted, todos: ['Đọc security guide chính thức của từng framework', 'Kiểm tra security config flags', 'Chạy framework-specific security linter/audit'], recommend: "Tham kh\u1EA3o OWASP Cheat Sheet Series t\u1EA1i cheatsheetseries.owasp.org." })] })] })), _jsx("button", { className: "btn-secondary", style: { width: '100%' }, onClick: () => window.owaspWorkbench?.openDocs?.('https://owasp.org/Top10/2025/'), children: "Open OWASP Docs" })] }));
};

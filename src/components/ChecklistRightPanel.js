import { jsxs as _jsxs, jsx as _jsx, Fragment as _Fragment } from "react/jsx-runtime";
import { useState } from 'react';
import { useStore } from '../store/useStore';
import { ChecklistItem } from './ChecklistPanel';
// ─── Design Review questions + details ────────────────────────────────────────
const DESIGN_QUESTIONS = [
    'Có threat model cho luồng đăng nhập, thanh toán và thao tác admin.',
    'Có abuse cases cho brute force, IDOR, privilege escalation, destructive action.',
    'Có xác định trust boundary giữa client, API, DB, bên thứ ba.',
    'Có thiết kế rate limiting / throttling cho luồng nhạy cảm.',
    'Có default deny / least privilege cho route và dữ liệu.',
    'Có fail-safe behavior khi lỗi timeout, parse lỗi, service phụ chết.',
    'Có data classification cho PII, credentials, tokens, secrets.',
    'Có review thiết kế bảo mật trước khi release.',
];
const DESIGN_QUESTION_DETAILS = {
    0: {
        todos: ['Vẽ sơ đồ luồng đăng nhập, thanh toán, thao tác admin', 'Xác định tài sản cần bảo vệ (data, operations)', 'Liệt kê các actor và quyền hạn của từng actor', 'Tài liệu hóa threat model (STRIDE hoặc PASTA)'],
        recommend: 'Dùng OWASP Threat Dragon hoặc draw.io để vẽ threat model. Ưu tiên luồng có tiền tệ và dữ liệu nhạy cảm trước.',
    },
    1: {
        todos: ['Liệt kê các abuse cases: brute force login, IDOR, privilege escalation', 'Viết test cases cho từng abuse case', 'Xác định rate limit phù hợp cho từng endpoint nhạy cảm', 'Thêm CAPTCHA hoặc lockout cho đăng nhập thất bại nhiều lần'],
        recommend: 'Mỗi user story nên có ít nhất 1 abuse case tương ứng. Dùng OWASP Testing Guide cho checklist kiểm thử.',
    },
    2: {
        todos: ['Vẽ sơ đồ trust boundary: client ↔ API ↔ DB ↔ 3rd party', 'Xác định dữ liệu nào được phép vượt boundary', 'Review mọi integration với bên thứ 3 (OAuth, payment, webhook)', 'Đảm bảo validate & sanitize tại mỗi boundary'],
        recommend: 'Dùng Data Flow Diagram (DFD) để visualize boundary. Mọi dữ liệu từ bên ngoài đều phải bị coi là untrusted.',
    },
    3: {
        todos: ['Implement rate limiting cho: login, register, forgot password, OTP', 'Implement rate limiting cho API endpoint nhạy cảm', 'Cấu hình response chậm dần (exponential backoff) khi fail nhiều', 'Log và alert khi phát hiện brute force pattern'],
        recommend: 'Dùng thư viện như express-rate-limit (Node), Bucket4j (Java). Rate limit nên áp dụng theo IP + account.',
    },
    4: {
        todos: ['Kiểm tra mọi route có require authentication mặc định', 'Áp dụng least privilege: user chỉ thấy dữ liệu của chính họ', 'Review admin endpoints có require role check không', 'Deny by default, whitelist những gì được phép'],
        recommend: 'Tránh kiểu "open by default, restrict later". Dùng middleware auth trước route handler, không check trong từng controller.',
    },
    5: {
        todos: ['Test behavior khi DB timeout, service phụ chết, parse lỗi', 'Đảm bảo không leak stack trace hay internal error ra ngoài', 'Implement graceful degradation cho các feature không critical', 'Log đầy đủ lỗi ở server, trả về generic message cho client'],
        recommend: 'Dùng circuit breaker pattern (Hystrix, Resilience4j). Tất cả exception phải được catch và handle — không để unhandled rejection.',
    },
    6: {
        todos: ['Phân loại dữ liệu: Public / Internal / Confidential / Secret', 'Mã hóa PII và credentials ở rest (AES-256) và transit (TLS 1.2+)', 'Không log PII, credentials, token, secrets', 'Review data retention policy và xóa dữ liệu sau khi hết hạn'],
        recommend: 'Dùng GDPR / PDPA làm baseline cho data classification. Secrets phải được lưu trong vault (HashiCorp Vault, AWS Secrets Manager).',
    },
    7: {
        todos: ['Tổ chức security design review trước sprint release', 'Checklist review bao gồm: auth, authz, input validation, crypto, logging', 'Có ít nhất 1 security engineer sign-off trước khi merge', 'Document các security decision và trade-off'],
        recommend: 'Tích hợp security review vào Definition of Done. Dùng OWASP ASVS Level 1 làm baseline tối thiểu cho mọi release.',
    },
};
// ─── Scan summary block ───────────────────────────────────────────────────────
function ScanSummaryBlock({ scanResult }) {
    const { findings, metadata } = scanResult;
    const bySev = metadata.summary.bySeverity;
    const byCat = metadata.summary.byCategory;
    const maxCat = Math.max(1, ...Object.values(byCat));
    return (_jsxs(_Fragment, { children: [_jsxs("div", { style: { display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10 }, children: [['critical', 'high', 'medium', 'low'].map(sev => {
                        const n = bySev[sev] || 0;
                        if (!n)
                            return null;
                        const cls = { critical: 'chip-crit', high: 'chip-high', medium: 'chip-med', low: 'chip-low' };
                        return _jsxs("span", { className: `sev-chip ${cls[sev]}`, children: [sev.slice(0, 4).toUpperCase(), " ", n] }, sev);
                    }), findings.length === 0 && _jsx("span", { style: { fontSize: 12, color: 'var(--text-3)' }, children: "No findings" })] }), Object.keys(byCat).length > 0 && (_jsxs("div", { style: { display: 'flex', flexDirection: 'column', gap: 5 }, children: [_jsx("div", { className: "rg-bars-hdr", children: "Ph\u00E2n b\u1ED5 theo OWASP Category" }), Object.entries(byCat).sort((a, b) => b[1] - a[1]).map(([cat, count]) => (_jsxs("div", { className: "rg-bar-row", children: [_jsx("span", { className: "rg-bar-cat", children: cat }), _jsx("div", { className: "rg-bar-track", children: _jsx("div", { className: "rg-bar-fill", style: { width: `${(count / maxCat) * 100}%`, background: 'var(--accent)' } }) }), _jsx("span", { className: "rg-bar-n", children: count })] }, cat)))] }))] }));
}
// ─── Main ChecklistRightPanel ─────────────────────────────────────────────────
export const ChecklistRightPanel = () => {
    const { projectScanResult, urlScanResult, urlScanIsLocal, urlInput, checklist } = useStore();
    const [hideCompleted, setHideCompleted] = useState(false);
    const hasProjectScan = !!projectScanResult;
    const hasUrlLocal = urlScanIsLocal && !!urlScanResult;
    const hasAny = hasProjectScan || hasUrlLocal;
    // Lấy design questions từ checklist data hoặc dùng default
    const designQuestions = checklist?.designQuestions?.length
        ? checklist.designQuestions
        : DESIGN_QUESTIONS;
    // Đếm progress
    const { checkedChecklistItems } = useStore();
    const designIds = designQuestions.map((_, i) => `design-${i}`);
    const doneCount = designIds.filter(id => checkedChecklistItems.includes(id)).length;
    if (!hasAny) {
        return (_jsxs("div", { className: "empty-state", children: [_jsx("div", { className: "empty-icon", children: "\u2611" }), _jsxs("p", { children: ["Ch\u1EA1y ", _jsx("strong", { style: { color: 'var(--accent)' }, children: "Project Scan" }), " ho\u1EB7c", ' ', _jsx("strong", { style: { color: 'var(--accent)' }, children: "URL Scan" }), " (localhost) \u0111\u1EC3 t\u1EA1o checklist."] }), _jsxs("p", { style: { fontSize: 12, color: 'var(--text-3)', marginTop: 10, lineHeight: 1.6 }, children: [_jsx("span", { style: { color: 'var(--med)' }, children: "\u26A0\uFE0F" }), " Ch\u1EA1y ", _jsx("strong", { children: "c\u1EA3 hai" }), " \u0111\u1EC3 ph\u00E1t hi\u1EC7n \u0111\u1EA7y \u0111\u1EE7 \u2014 URL Scan t\u00ECm l\u1ED7i runtime, Project Scan t\u00ECm l\u1ED7i trong source code."] })] }));
    }
    return (_jsx("div", { style: { display: 'flex', flexDirection: 'column', gap: 16 }, children: _jsxs("div", { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, alignItems: 'start' }, children: [_jsx("div", { style: { display: 'flex', flexDirection: 'column', gap: 12 }, children: _jsxs("div", { className: "section", style: { flex: 1 }, children: [_jsxs("div", { className: "chk-section-header", children: [_jsxs("div", { style: { display: 'flex', flexDirection: 'column', gap: 4 }, children: [_jsx("div", { className: "section-label", style: { marginBottom: 0 }, children: "Design Review" }), _jsxs("div", { style: { display: 'flex', alignItems: 'center', gap: 8 }, children: [_jsx("div", { style: { flex: 1, height: 4, background: 'var(--border)', borderRadius: 4, overflow: 'hidden' }, children: _jsx("div", { style: {
                                                                width: `${(doneCount / designQuestions.length) * 100}%`,
                                                                height: '100%', background: 'var(--accent)', borderRadius: 4,
                                                                transition: 'width 0.3s ease',
                                                            } }) }), _jsxs("span", { style: { fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }, children: [doneCount, "/", designQuestions.length] })] })] }), _jsxs("button", { className: "btn-checklist-toggle", onClick: () => setHideCompleted(v => !v), title: hideCompleted ? 'Show completed items' : 'Hide completed items', children: [hideCompleted ? '👁️ Show' : '🙈 Hide', " Completed"] })] }), _jsx("div", { className: "chk-items-list", style: { marginTop: 10 }, children: designQuestions.map((q, i) => (_jsx(ChecklistItem, { id: `design-${i}`, label: q, hideCompleted: hideCompleted, todos: DESIGN_QUESTION_DETAILS[i]?.todos, recommend: DESIGN_QUESTION_DETAILS[i]?.recommend }, `design-${i}`))) })] }) }), _jsxs("div", { style: { display: 'flex', flexDirection: 'column', gap: 12 }, children: [hasUrlLocal && urlScanResult && (_jsxs("div", { className: "section", children: [_jsxs("div", { className: "section-label", style: { display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }, children: ["\uD83C\uDF10 URL Scan", _jsx("span", { style: { fontSize: 11, padding: '2px 8px', borderRadius: 20, background: 'var(--accent)', color: '#fff', fontWeight: 500 }, children: "localhost" })] }), _jsx("div", { style: { fontSize: 12, color: 'var(--text-3)', marginBottom: 10 }, children: urlScanResult.scannedUrl || urlInput }), _jsx(ScanSummaryBlock, { scanResult: urlScanResult })] })), hasProjectScan && projectScanResult && (_jsxs("div", { className: "section", children: [_jsx("div", { className: "section-label", style: { marginBottom: 10 }, children: "\uD83D\uDCC2 Project Scan" }), _jsx(ScanSummaryBlock, { scanResult: projectScanResult }), projectScanResult.metadata?.scannedFiles !== undefined && (_jsxs("div", { className: "meta-table", style: { marginTop: 10 }, children: [_jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-key", children: "Files scanned" }), _jsx("span", { className: "meta-val", children: projectScanResult.metadata.scannedFiles })] }), projectScanResult.metadata.packageJsonFound !== undefined && (_jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-key", children: "package.json" }), _jsx("span", { className: `meta-val ${projectScanResult.metadata.packageJsonFound ? 'ok' : ''}`, children: projectScanResult.metadata.packageJsonFound ? 'Yes' : 'No' })] })), projectScanResult.metadata.configCount !== undefined && (_jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-key", children: "Config files" }), _jsx("span", { className: "meta-val", children: projectScanResult.metadata.configCount })] })), _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-key", children: "Total findings" }), _jsx("span", { className: "meta-val", children: projectScanResult.findings.length })] })] }))] })), hasUrlLocal && hasProjectScan && (_jsxs("div", { style: { background: 'var(--accent-bg, rgba(99,102,241,0.08))', border: '1px solid var(--accent)', borderRadius: 8, padding: '10px 14px', fontSize: 12, color: 'var(--text-2)', lineHeight: 1.6 }, children: [_jsx("span", { style: { color: 'var(--accent)', fontWeight: 600 }, children: "\uD83D\uDD17 Checklist k\u1EBFt h\u1EE3p." }), ' ', "Findings t\u1EEB c\u1EA3 hai ngu\u1ED3n \u0111\u00E3 \u0111\u01B0\u1EE3c g\u1ED9p \u2014 tr\u00F9ng l\u1EB7p ch\u1EC9 hi\u1EC7n m\u1ED9t l\u1EA7n."] })), (!hasUrlLocal || !hasProjectScan) && (_jsxs("div", { style: { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: '10px 14px', fontSize: 12, color: 'var(--text-3)', lineHeight: 1.6 }, children: [_jsx("span", { style: { color: 'var(--med)', fontWeight: 600 }, children: "\uD83D\uDCA1 Tip: " }), !hasUrlLocal
                                    ? 'Chạy thêm URL Scan (localhost) để phát hiện lỗi runtime và kết hợp vào checklist.'
                                    : 'Chạy thêm Project Scan để phát hiện lỗi source code và kết hợp vào checklist.'] }))] })] }) }));
};

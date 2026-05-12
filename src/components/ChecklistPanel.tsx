import React, { useEffect, useState } from 'react';
import { useStore } from '../store/useStore';
import { Finding } from '../types';

const OWASP_CATS = [
  { id: 'A01', name: 'Broken Access Control', desc: 'Lỗi phân quyền/kiểm soát truy cập (IDOR, bypass, thiếu kiểm tra quyền).' },
  { id: 'A02', name: 'Cryptographic Failures', desc: 'Lỗi mã hoá/bảo vệ dữ liệu nhạy cảm (HTTPS, key/secret, thuật toán yếu).' },
  { id: 'A03', name: 'Injection', desc: 'Lỗi chèn lệnh (SQLi, XSS, Command injection, SSTI...) do xử lý input không an toàn.' },
  { id: 'A04', name: 'Insecure Design', desc: 'Thiết kế thiếu kiểm soát bảo mật (thiếu rate limit, flow không an toàn, threat model).' },
  { id: 'A05', name: 'Security Misconfiguration', desc: 'Cấu hình sai/thiếu (CORS, headers, debug mode, dịch vụ/endpoint bị lộ).' },
  { id: 'A06', name: 'Vulnerable & Outdated Components', desc: 'Thư viện/phụ thuộc có CVE hoặc phiên bản cũ, không còn được vá.' },
  { id: 'A07', name: 'ID & Authentication Failures', desc: 'Lỗi xác thực/phiên (JWT, session, mật khẩu, MFA, reset password).' },
  { id: 'A08', name: 'Software & Data Integrity Failures', desc: 'Rủi ro integrity (supply-chain, update, CI/CD, deserialization không an toàn).' },
  { id: 'A09', name: 'Security Logging & Monitoring Failures', desc: 'Thiếu log/giám sát cảnh báo (khó phát hiện tấn công, thiếu audit trail).' },
  { id: 'A10', name: 'Server-Side Request Forgery (SSRF)', desc: 'Server bị ép gọi tới tài nguyên nội bộ/metadata thông qua URL do user điều khiển.' },
];

export const CONTEXT_ITEM_DETAILS: Record<string, { todos: string[]; recommend: string }> = {
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

const SEV_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export function buildChecklistFromFindings(findings: Finding[]) {
  const byCategory: Record<string, Finding[]> = {};
  for (const f of findings) {
    const key = f.owaspCategory?.toUpperCase() || 'OTHER';
    if (!byCategory[key]) byCategory[key] = [];
    byCategory[key].push(f);
  }
  return OWASP_CATS.map(cat => {
    const hits = Object.entries(byCategory).filter(([k]) => {
      if (k.includes(cat.id)) return true;
      if (k.includes(cat.name.toUpperCase())) return true;
      // Map legacy formats like A1 instead of A01
      const legacyId = cat.id.replace('A0', 'A');
      if (legacyId !== cat.id && k.includes(legacyId)) return true;
      return false;
    });
    const allFindings: Finding[] = hits.flatMap(([, fs]) => fs);
    const maxSev = allFindings.reduce((acc, f) =>
      SEV_ORDER[f.severity] > SEV_ORDER[acc] ? f.severity : acc, 'low' as string);
    return {
      ...cat,
      count: allFindings.length,
      severity: allFindings.length > 0 ? maxSev : null,
      findings: allFindings.slice(0, 3),
    };
  });
}

export function sevColor(sev: string | null): string {
  if (!sev) return 'var(--text-3)';
  if (sev === 'critical') return 'var(--crit)';
  if (sev === 'high')     return 'var(--high)';
  if (sev === 'medium')   return 'var(--med)';
  return 'var(--low)';
}

export function sevBg(sev: string | null): string {
  if (!sev) return 'var(--bg-input)';
  if (sev === 'critical') return 'var(--crit-bg)';
  if (sev === 'high')     return 'var(--high-bg)';
  if (sev === 'medium')   return 'var(--med-bg)';
  return 'var(--low-bg)';
}

// ─── Expandable checklist item (exported for reuse in ChecklistRightPanel) ───
interface ChecklistItemProps {
  id: string;
  label: string;
  hideCompleted: boolean;
  todos?: string[];
  recommend?: string;
}

export const ChecklistItem: React.FC<ChecklistItemProps> = ({ id, label, hideCompleted, todos, recommend }) => {
  const { checkedChecklistItems, toggleChecklistItem } = useStore();
  const [expanded, setExpanded] = useState(false);
  const checked = checkedChecklistItems.includes(id);
  const hasDetails = !!(todos?.length || recommend);

  if (hideCompleted && checked) return null;

  return (
    <div className={`chk-item-expandable ${checked ? 'chk-item-done' : ''}`}>
      <div className="chk-item-row">
        <label className="chk-item-label-wrap" onClick={(e) => e.stopPropagation()}>
          <input
            type="checkbox"
            checked={checked}
            onChange={() => toggleChecklistItem(id)}
            className="chk-checkbox-input"
          />
          <span className="chk-item-icon" aria-hidden="true" />
          <span className={`chk-item-text ${checked ? 'chk-item-text-done' : ''}`}>
            {label}
          </span>
        </label>
        {hasDetails && (
          <button
            className={`chk-expand-btn ${expanded ? 'open' : ''}`}
            onClick={() => setExpanded(v => !v)}
            title={expanded ? 'Thu gọn' : 'Xem todo & khuyến nghị'}
          >
            {'>'}
          </button>
        )}
      </div>
      {expanded && hasDetails && (
        <div className="chk-item-detail">
          {todos && todos.length > 0 && (
            <div className="chk-detail-section">
              <div className="chk-detail-label">Việc cần làm</div>
              <ul className="chk-todo-list">
                {todos.map((t, i) => <li key={i} className="chk-todo-item">{t}</li>)}
              </ul>
            </div>
          )}
          {recommend && (
            <div className="chk-detail-section">
              <div className="chk-detail-label">Khuyến nghị</div>
              <div className="chk-recommend-text">{recommend}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// ─── Source banner ────────────────────────────────────────────────────────────
const ChecklistSourceBanner: React.FC<{
  hasUrlLocal: boolean;
  hasProject: boolean;
  urlTarget: string;
}> = ({ hasUrlLocal, hasProject, urlTarget }) => {
  if (!hasUrlLocal && !hasProject) return null;
  const isCombined = hasUrlLocal && hasProject;

  const sourceLabel = isCombined
    ? 'URL (localhost) + Mã nguồn'
    : hasUrlLocal
      ? 'URL (localhost)'
      : 'Mã nguồn';

  return (
    <div className="onboarding-banner" style={{ marginBottom: 4 }}>
      <div className="onboarding-banner-title">Nguồn dữ liệu cho Checklist</div>
      <div className="onboarding-banner-text">
        Đang dùng kết quả từ: <strong>{sourceLabel}</strong>
        {hasUrlLocal && urlTarget ? <span> — {urlTarget}</span> : null}
        .
        {isCombined ? ' Nên chạy cả hai để có checklist đầy đủ hơn.' : ''}
      </div>
    </div>
  );
};

// ─── Main ChecklistPanel — chỉ hiện OWASP grid + Context checklist ────────────
export const ChecklistPanel: React.FC = () => {
  const {
    loadChecklist,
    projectScanResult, urlScanResult, urlScanIsLocal, urlInput,
    getCombinedFindings,
  } = useStore();
  const [hideCompleted, setHideCompleted] = useState(false);

  useEffect(() => {
    loadChecklist();
  }, [loadChecklist]);

  const hasProjectScan = !!projectScanResult;
  const hasUrlLocal    = urlScanIsLocal && !!urlScanResult;
  const hasAny         = hasProjectScan || hasUrlLocal;
  const urlTarget      = urlScanResult?.scannedUrl || urlInput || '';

  if (!hasAny) {
    return (
      <div className="empty-state">
        <div className="empty-state-title">Chưa có Checklist</div>
        <div className="empty-state-steps">
          <div className="empty-state-step">
            <span className="empty-state-step-num">1</span>
            <span>Chạy <strong>Project Scan</strong> hoặc <strong>URL Scan</strong> (localhost)</span>
          </div>
          <div className="empty-state-step">
            <span className="empty-state-step-num">2</span>
            <span>Mở lại tab Checklist để xem gợi ý xử lý</span>
          </div>
        </div>
        <div className="empty-state-actions">
          <button
            className="btn-link"
            onClick={() => window.dispatchEvent(new Event('sentinel:open-shortcuts'))}
          >
            Xem hướng dẫn nhanh →
          </button>
        </div>
      </div>
    );
  }

  const combinedFindings = getCombinedFindings();
  const items    = buildChecklistFromFindings(combinedFindings);
  const covered  = items.filter(i => i.count > 0).length;
  const total    = OWASP_CATS.length;

  const techStack = projectScanResult?.metadata?.techStack || urlScanResult?.metadata?.techStack || [];
  const hasNode   = techStack.some(t => ['Node.js','React','Next.js'].includes(t));
  const hasJava   = techStack.some(t => ['Spring Boot','Java'].includes(t));
  const hasPHP    = techStack.some(t => ['PHP','Laravel'].includes(t));

  const coverageLabel = (() => {
    if (covered === 0) return 'Chưa phát hiện vấn đề nào theo OWASP Top 10';
    if (hasUrlLocal && hasProjectScan) return `${covered}/${total} danh mục — URL (localhost) + Mã nguồn`;
    if (hasUrlLocal) return `${covered}/${total} danh mục — URL (localhost)`;
    return `${covered}/${total} danh mục — Mã nguồn`;
  })();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <ChecklistSourceBanner hasUrlLocal={hasUrlLocal} hasProject={hasProjectScan} urlTarget={urlTarget} />

      <div className="onboarding-banner">
        <div className="onboarding-banner-title">Cách dùng Checklist</div>
        <div className="onboarding-banner-text">
          Checklist giúp bạn chuyển kết quả scan thành các việc cần làm. Hãy ưu tiên xử lý các danh mục có số lượng finding cao và mức độ nghiêm trọng lớn.
        </div>
      </div>

      {/* OWASP Top 10 Grid */}
      <div className="section">
        <div className="section-label">OWASP Top 10</div>
        <div className="chk-coverage">
          <div className="chk-coverage-hdr">
            <span>Độ bao phủ</span>
            <span className="chk-coverage-frac">{covered}/{total}</span>
          </div>
          <div className="chk-coverage-track">
            <div className="chk-coverage-fill" style={{ width: `${(covered / total) * 100}%` }} />
          </div>
          <div className="chk-coverage-label">{coverageLabel}</div>
        </div>
        <div className="checklist-grid-adv">
          {items.map(cat => (
            <div key={cat.id} className={`chk-item ${cat.count > 0 ? 'chk-item-hit' : ''}`}
              style={{ borderColor: cat.count > 0 ? sevColor(cat.severity) + '55' : undefined, background: cat.count > 0 ? sevBg(cat.severity) : undefined }}>
              <div className="chk-item-header">
                <span className="chk-id" style={{ color: cat.count > 0 ? sevColor(cat.severity) : undefined }}>{cat.id}</span>
                {cat.count > 0
                  ? <span className="chk-badge" style={{ color: sevColor(cat.severity), borderColor: sevColor(cat.severity) + '55' }}>{cat.count}</span>
                  : <span className="chk-pass">✓</span>}
              </div>
              <div className="chk-name">{cat.name}</div>
              {cat.desc && <div className="chk-desc">{cat.desc}</div>}
              {cat.count > 0 && cat.severity && (
                <div className="chk-sev" style={{ color: sevColor(cat.severity) }}>{cat.severity.toUpperCase()}</div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Context-Based Checklist */}
      {techStack.length > 0 && (
        <div className="section">
          <div className="chk-section-header">
            <div className="section-label" style={{ marginBottom: 0 }}>Gợi ý theo công nghệ</div>
            <button className="btn-checklist-toggle" onClick={() => setHideCompleted(v => !v)}>
              {hideCompleted ? 'Hiện tất cả' : 'Ẩn mục đã xong'}
            </button>
          </div>
          <div className="chk-items-list">
            {hasNode && (<>
              <ChecklistItem id="chk-node-0" label="NPM vulnerabilities (npm audit)." hideCompleted={hideCompleted} {...CONTEXT_ITEM_DETAILS['chk-node-0']} />
              <ChecklistItem id="chk-node-1" label="JWT secret management & token expiration." hideCompleted={hideCompleted} {...CONTEXT_ITEM_DETAILS['chk-node-1']} />
              <ChecklistItem id="chk-node-2" label="CORS configuration for React/Next.js APIs." hideCompleted={hideCompleted} {...CONTEXT_ITEM_DETAILS['chk-node-2']} />
              <ChecklistItem id="chk-node-3" label="Hardcoded secrets in .env & source code." hideCompleted={hideCompleted} {...CONTEXT_ITEM_DETAILS['chk-node-3']} />
            </>)}
            {hasJava && (<>
              <ChecklistItem id="chk-java-0" label="Spring Actuator không expose /env hoặc /heapdump." hideCompleted={hideCompleted} {...CONTEXT_ITEM_DETAILS['chk-java-0']} />
              <ChecklistItem id="chk-java-1" label="Maven/Gradle dependencies CVE check." hideCompleted={hideCompleted} {...CONTEXT_ITEM_DETAILS['chk-java-1']} />
              <ChecklistItem id="chk-java-2" label="Spring Data REST endpoint validation." hideCompleted={hideCompleted} {...CONTEXT_ITEM_DETAILS['chk-java-2']} />
            </>)}
            {hasPHP && (<>
              <ChecklistItem id="chk-php-0" label="APP_DEBUG=false trong .env production." hideCompleted={hideCompleted} {...CONTEXT_ITEM_DETAILS['chk-php-0']} />
              <ChecklistItem id="chk-php-1" label="Debugbar/Telescope routes không public." hideCompleted={hideCompleted} {...CONTEXT_ITEM_DETAILS['chk-php-1']} />
              <ChecklistItem id="chk-php-2" label="File upload validation để ngăn RCE." hideCompleted={hideCompleted} {...CONTEXT_ITEM_DETAILS['chk-php-2']} />
            </>)}
            <ChecklistItem
              id="chk-generic-0"
              label={`Review ${techStack.join(', ')} security configurations.`}
              hideCompleted={hideCompleted}
              todos={['Đọc security guide chính thức của từng framework', 'Kiểm tra security config flags', 'Chạy framework-specific security linter/audit']}
              recommend="Tham khảo OWASP Cheat Sheet Series tại cheatsheetseries.owasp.org."
            />
          </div>
        </div>
      )}

      <button
        className="btn-secondary"
        style={{ width: '100%' }}
        onClick={() => window.owaspWorkbench?.openDocs?.('https://owasp.org/Top10/2025/')}
      >
        Mở tài liệu OWASP
      </button>
    </div>
  );
};
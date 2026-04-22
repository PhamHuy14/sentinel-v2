import React, { useState } from 'react';
import { useStore } from '../store/useStore';
import { ScanResult } from '../types';
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

const DESIGN_QUESTION_DETAILS: Record<number, { todos: string[]; recommend: string }> = {
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
function ScanSummaryBlock({ scanResult }: { scanResult: ScanResult }) {
  const { findings, metadata } = scanResult;
  const bySev = metadata.summary.bySeverity;
  const byCat = metadata.summary.byCategory;
  const maxCat = Math.max(1, ...Object.values(byCat));

  return (
    <>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
        {(['critical','high','medium','low'] as const).map(sev => {
          const n = bySev[sev] || 0;
          if (!n) return null;
          const cls: Record<string, string> = { critical: 'chip-crit', high: 'chip-high', medium: 'chip-med', low: 'chip-low' };
          return <span key={sev} className={`sev-chip ${cls[sev]}`}>{sev.slice(0,4).toUpperCase()} {n}</span>;
        })}
        {findings.length === 0 && <span style={{ fontSize: 12, color: 'var(--text-3)' }}>Không có findings</span>}
      </div>
      {Object.keys(byCat).length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
          <div className="rg-bars-hdr">Phân bổ theo OWASP Category</div>
          {Object.entries(byCat).sort((a,b) => b[1]-a[1]).map(([cat, count]) => (
            <div key={cat} className="rg-bar-row">
              <span className="rg-bar-cat">{cat}</span>
              <div className="rg-bar-track">
                <div className="rg-bar-fill" style={{ width: `${(count/maxCat)*100}%`, background: 'var(--accent)' }} />
              </div>
              <span className="rg-bar-n">{count}</span>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

// ─── Main ChecklistRightPanel ─────────────────────────────────────────────────
export const ChecklistRightPanel: React.FC = () => {
  const { projectScanResult, urlScanResult, urlScanIsLocal, urlInput, checklist } = useStore();
  const [hideCompleted, setHideCompleted] = useState(false);

  const hasProjectScan = !!projectScanResult;
  const hasUrlLocal    = urlScanIsLocal && !!urlScanResult;
  const hasAny         = hasProjectScan || hasUrlLocal;

  // Lấy design questions từ checklist data hoặc dùng default
  const designQuestions = checklist?.designQuestions?.length
    ? checklist.designQuestions
    : DESIGN_QUESTIONS;

  // Đếm progress
  const { checkedChecklistItems } = useStore();
  const designIds = designQuestions.map((_, i) => `design-${i}`);
  const doneCount = designIds.filter(id => checkedChecklistItems.includes(id)).length;
  const completionRate = Math.round((doneCount / Math.max(1, designQuestions.length)) * 100);

  if (!hasAny) {
    return (
      <div className="empty-state">
        <div className="empty-icon">☑</div>
        <p>
          Chạy <strong style={{ color: 'var(--accent)' }}>Project Scan</strong> hoặc{' '}
          <strong style={{ color: 'var(--accent)' }}>URL Scan</strong> (localhost) để tạo checklist.
        </p>
        <p style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 10, lineHeight: 1.6 }}>
          <span style={{ color: 'var(--med)' }}>⚠️</span> Chạy <strong>cả hai</strong> để phát hiện đầy đủ —
          URL Scan tìm lỗi runtime, Project Scan tìm lỗi trong source code.
        </p>
      </div>
    );
  }

  return (
    <div className="checklist-shell checklist-shell-v3">
      <div className="checklist-summary-grid">
        {hasUrlLocal && urlScanResult && (
          <div className="section checklist-summary-card">
            <div className="checklist-summary-head">
              <div className="section-label" style={{ marginBottom: 0 }}>URL Scan</div>
              <span className="checklist-summary-badge">localhost</span>
            </div>
            <div className="checklist-summary-target">
              {urlScanResult.scannedUrl || urlInput}
            </div>
            <ScanSummaryBlock scanResult={urlScanResult} />
          </div>
        )}

        {hasProjectScan && projectScanResult && (
          <div className="section checklist-summary-card">
            <div className="checklist-summary-head">
              <div className="section-label" style={{ marginBottom: 0 }}>Project Scan</div>
            </div>
            <ScanSummaryBlock scanResult={projectScanResult} />
            {projectScanResult.metadata?.scannedFiles !== undefined && (
              <div className="meta-table" style={{ marginTop: 10 }}>
                <div className="meta-row">
                  <span className="meta-key">Số file đã quét</span>
                  <span className="meta-val">{projectScanResult.metadata.scannedFiles}</span>
                </div>
                {projectScanResult.metadata.packageJsonFound !== undefined && (
                  <div className="meta-row">
                    <span className="meta-key">package.json</span>
                    <span className={`meta-val ${projectScanResult.metadata.packageJsonFound ? 'ok' : ''}`}>
                      {projectScanResult.metadata.packageJsonFound ? 'Có' : 'Không'}
                    </span>
                  </div>
                )}
                {projectScanResult.metadata.configCount !== undefined && (
                  <div className="meta-row">
                    <span className="meta-key">File cấu hình</span>
                    <span className="meta-val">{projectScanResult.metadata.configCount}</span>
                  </div>
                )}
                <div className="meta-row">
                  <span className="meta-key">Tổng số findings</span>
                  <span className="meta-val">{projectScanResult.findings.length}</span>
                </div>
              </div>
            )}
          </div>
        )}

        <div className="checklist-summary-tip section">
          {hasUrlLocal && hasProjectScan ? (
            <>
              <span className="checklist-tip-title">Checklist kết hợp.</span>{' '}
              Findings từ cả hai nguồn đã được gộp, mục trùng lặp chỉ hiển thị một lần.
            </>
          ) : (
            <>
              <span className="checklist-tip-title">Tip:</span>{' '}
              {!hasUrlLocal
                ? 'Chạy thêm URL Scan (localhost) để phát hiện lỗi runtime và kết hợp vào checklist.'
                : 'Chạy thêm Project Scan để phát hiện lỗi source code và kết hợp vào checklist.'}
            </>
          )}
        </div>
      </div>

      <div className="section checklist-review-panel">
        <div className="chk-section-header checklist-review-head">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0, flex: 1 }}>
            <div className="section-label" style={{ marginBottom: 0 }}>Đánh giá thiết kế</div>
            <div className="checklist-progress-row">
              <div className="checklist-progress-track">
                <div
                  style={{
                    width: `${(doneCount / designQuestions.length) * 100}%`,
                    height: '100%'
                  }}
                  className="checklist-progress-fill"
                />
              </div>
              <span className="checklist-progress-badge">
                {doneCount}/{designQuestions.length} · {completionRate}%
              </span>
            </div>
          </div>
          <button
            className="btn-checklist-toggle"
            onClick={() => setHideCompleted(v => !v)}
            title={hideCompleted ? 'Hiện mục đã hoàn thành' : 'Ẩn mục đã hoàn thành'}
          >
            {hideCompleted ? 'Hiện đủ' : 'Ẩn đã xong'}
          </button>
        </div>

        <div className="chk-items-list" style={{ marginTop: 10 }}>
          {designQuestions.map((q, i) => (
            <ChecklistItem
              key={`design-${i}`}
              id={`design-${i}`}
              label={q}
              hideCompleted={hideCompleted}
              todos={DESIGN_QUESTION_DETAILS[i]?.todos}
              recommend={DESIGN_QUESTION_DETAILS[i]?.recommend}
            />
          ))}
        </div>
      </div>
    </div>
  );
};

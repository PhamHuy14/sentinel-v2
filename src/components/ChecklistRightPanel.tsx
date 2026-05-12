import React, { useMemo, useState } from 'react';
import { useStore } from '../store/useStore';
import { Finding, ScanResult } from '../types';
import { formatOwaspCategory } from '../utils/owasp';
import { ChecklistItem, sevColor } from './ChecklistPanel';

const SEV_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

const DESIGN_QUESTIONS = [
  'Có threat model cho login, thanh toán, admin và thao tác destructive.',
  'Có abuse cases cho brute force, IDOR, privilege escalation và SSRF.',
  'Có trust boundary rõ ràng giữa client, API, DB và bên thứ ba.',
  'Có rate limiting/throttling cho endpoint nhạy cảm.',
  'Có default deny và least privilege cho route và dữ liệu.',
  'Có fail-safe behavior khi timeout, parse lỗi hoặc service phụ bị lỗi.',
  'Có data classification cho PII, token, credentials và secret.',
  'Có security review trước release và ghi lại decision quan trọng.',
];

const DESIGN_DETAILS: Record<number, { todos: string[]; recommend: string }> = {
  0: {
    todos: ['Vẽ data flow cho luồng nhạy cảm', 'Xác định tài sản cần bảo vệ', 'Ghi threat và control tương ứng'],
    recommend: 'Bắt đầu với STRIDE cho luồng có auth/admin/payment.',
  },
  1: {
    todos: ['Viết abuse case tương ứng với user story', 'Thêm test cho IDOR/brute force', 'Gán owner cho từng control'],
    recommend: 'Checklist tốt nhất là checklist có test hoặc bằng chứng kèm theo.',
  },
  2: {
    todos: ['Đánh dấu input untrusted tại mọi boundary', 'Validate server-side', 'Review OAuth/webhook/payment integration'],
    recommend: 'Mỗi boundary nên có validation, auth, logging và error handling rõ ràng.',
  },
  3: {
    todos: ['Rate limit login/register/reset password', 'Kết hợp IP + account key', 'Cảnh báo khi có pattern bất thường'],
    recommend: 'Dùng backoff mềm thay vì lockout cứng nếu trải nghiệm người dùng quan trọng.',
  },
  4: {
    todos: ['Mặc định route phải cần auth', 'Check role/permission ở server', 'Không đưa authorization logic vào client'],
    recommend: 'Policy/guard tập trung giúp tránh bỏ sót endpoint mới.',
  },
  5: {
    todos: ['Trả generic error cho client', 'Log chi tiết ở server', 'Test timeout và malformed input'],
    recommend: 'Fail closed với authz/payment/admin flow.',
  },
  6: {
    todos: ['Không log secret/PII', 'Mã hóa dữ liệu nhạy cảm', 'Đặt retention và xóa dữ liệu hết hạn'],
    recommend: 'Secret nên nằm trong vault hoặc environment của main process, không vào renderer bundle.',
  },
  7: {
    todos: ['Đặt security review trong Definition of Done', 'Ghi risk acceptance nếu chưa fix', 'Review lại sau mỗi release lớn'],
    recommend: 'Dùng OWASP ASVS Level 1 làm baseline thực tế.',
  },
};

function ScanSummaryBlock({ scanResult }: { scanResult: ScanResult }) {
  const bySev = scanResult.metadata.summary.bySeverity || {};
  const byCat = scanResult.metadata.summary.byCategory || {};
  const maxCat = Math.max(1, ...Object.values(byCat));

  return (
    <>
      <div className="checklist-severity-row">
        {(['critical', 'high', 'medium', 'low'] as const).map((sev) => {
          const count = bySev[sev] || 0;
          return (
            <span key={sev} className="checklist-severity-pill" style={{ color: sevColor(sev), borderColor: `${sevColor(sev)}55` }}>
              {sev.slice(0, 4).toUpperCase()} {count}
            </span>
          );
        })}
      </div>

      {Object.keys(byCat).length > 0 && (
        <div className="checklist-bars">
          {Object.entries(byCat).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([category, count]) => (
            <div key={category} className="rg-bar-row">
              <span className="rg-bar-cat">{category}</span>
              <div className="rg-bar-track">
                <div className="rg-bar-fill" style={{ width: `${(count / maxCat) * 100}%` }} />
              </div>
              <span className="rg-bar-n">{count}</span>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

function buildFindingActions(findings: Finding[]) {
  return findings
    .slice()
    .sort((a, b) => {
      const severityDiff = SEV_ORDER[b.severity] - SEV_ORDER[a.severity];
      if (severityDiff !== 0) return severityDiff;
      return a.ruleId.localeCompare(b.ruleId);
    })
    .slice(0, 16)
    .map((finding) => ({
      id: `finding-action::${finding.ruleId}::${finding.target}::${finding.location}`.toLowerCase(),
      severity: finding.severity,
      label: `${finding.ruleId} - ${finding.title}`,
      meta: `${formatOwaspCategory(finding.owaspCategory)} | ${finding.collector}`,
      todos: [
        finding.target ? `Xác minh target: ${finding.target}` : 'Xác minh phạm vi ảnh hưởng.',
        finding.location ? `Kiểm tra vị trí: ${finding.location}` : 'Xác định vị trí code/config/runtime liên quan.',
        finding.evidence?.[0] ? `Đối chiếu evidence: ${finding.evidence[0]}` : 'Bổ sung bằng chứng tái hiện nếu cần.',
      ],
      recommend: finding.remediation || 'Lập fix plan, thêm test/regression và quét lại sau khi sửa.',
    }));
}

export const ChecklistRightPanel: React.FC = () => {
  const {
    projectScanResult,
    urlScanResult,
    checklist,
    checkedChecklistItems,
    getCombinedFindings,
  } = useStore();
  const [hideCompleted, setHideCompleted] = useState(false);

  const hasProjectScan = Boolean(projectScanResult);
  const hasUrlScan = Boolean(urlScanResult);
  const hasAny = hasProjectScan || hasUrlScan;
  const combinedFindings = getCombinedFindings();
  const findingActions = useMemo(() => buildFindingActions(combinedFindings), [combinedFindings]);
  const designQuestions = checklist?.designQuestions?.length ? checklist.designQuestions : DESIGN_QUESTIONS;
  const designIds = designQuestions.map((_, index) => `design-${index}`);
  const doneCount = designIds.filter((id) => checkedChecklistItems.includes(id)).length;
  const completionRate = Math.round((doneCount / Math.max(1, designQuestions.length)) * 100);

  if (!hasAny) {
    return (
      <div className="rp-empty">
        <div className="rp-empty-steps">
          <div className="rp-empty-step">
            <div className="rp-empty-num">1</div>
            <div className="rp-empty-text">Chạy URL Scan hoặc Project Scan</div>
          </div>
          <div className="rp-empty-arrow">→</div>
          <div className="rp-empty-step">
            <div className="rp-empty-num">2</div>
            <div className="rp-empty-text">Checklist sẽ xuất hiện tại đây</div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="checklist-shell checklist-shell-v3">
      <div className="checklist-summary-grid">
        {urlScanResult && (
          <div className="section checklist-summary-card">
            <div className="checklist-summary-head">
              <div className="section-label" style={{ marginBottom: 0 }}>URL Scan</div>
              <span className="checklist-summary-badge">runtime</span>
            </div>
            <div className="checklist-summary-target">{urlScanResult.scannedUrl || urlScanResult.finalUrl}</div>
            <ScanSummaryBlock scanResult={urlScanResult} />
          </div>
        )}

        {projectScanResult && (
          <div className="section checklist-summary-card">
            <div className="checklist-summary-head">
              <div className="section-label" style={{ marginBottom: 0 }}>Project Scan</div>
              <span className="checklist-summary-badge">source</span>
            </div>
            <ScanSummaryBlock scanResult={projectScanResult} />
            <div className="meta-table checklist-mini-meta">
              <div className="meta-row"><span className="meta-key">Files</span><span className="meta-val">{projectScanResult.metadata.scannedFiles ?? 0}</span></div>
              <div className="meta-row"><span className="meta-key">Config</span><span className="meta-val">{projectScanResult.metadata.configCount ?? 0}</span></div>
              <div className="meta-row"><span className="meta-key">Tech</span><span className="meta-val">{projectScanResult.metadata.techStack?.join(', ') || 'N/A'}</span></div>
            </div>
          </div>
        )}

        <div className="section checklist-summary-tip">
          <span className="checklist-tip-title">Logic hiện tại: </span>
          Checklist lấy findings từ cả URL Scan và Project Scan, dedupe theo rule/category/severity, rồi tạo backlog ưu tiên theo severity.
        </div>
      </div>

      <div className="section checklist-action-panel">
        <div className="chk-section-header checklist-review-head">
          <div>
            <div className="section-label" style={{ marginBottom: 2 }}>Việc cần xử lý từ findings</div>
            <div className="checklist-muted">{findingActions.length} mục ưu tiên cao nhất được tạo từ kết quả quét.</div>
          </div>
          <button type="button" className="btn-checklist-toggle" onClick={() => setHideCompleted((v) => !v)}>
            {hideCompleted ? 'Hiện đã xong' : 'Ẩn đã xong'}
          </button>
        </div>

        {findingActions.length > 0 ? (
          <div className="chk-items-list">
            {findingActions.map((action) => (
              <ChecklistItem
                key={action.id}
                id={action.id}
                label={action.label}
                meta={action.meta}
                severity={action.severity}
                hideCompleted={hideCompleted}
                todos={action.todos}
                recommend={action.recommend}
              />
            ))}
          </div>
        ) : (
          <div className="checklist-clean-state">
            Không có finding nào cần xử lý. Vẫn nên hoàn tất phần đánh giá thiết kế bên dưới.
          </div>
        )}
      </div>

      <div className="section checklist-review-panel">
        <div className="chk-section-header checklist-review-head">
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="section-label" style={{ marginBottom: 4 }}>Đánh giá thiết kế</div>
            <div className="checklist-progress-row">
              <div className="checklist-progress-track">
                <div className="checklist-progress-fill" style={{ width: `${completionRate}%` }} />
              </div>
              <span className="checklist-progress-badge">{doneCount}/{designQuestions.length} - {completionRate}%</span>
            </div>
          </div>
        </div>

        <div className="chk-items-list">
          {designQuestions.map((question, index) => (
            <ChecklistItem
              key={`design-${index}`}
              id={`design-${index}`}
              label={question}
              hideCompleted={hideCompleted}
              todos={DESIGN_DETAILS[index]?.todos}
              recommend={DESIGN_DETAILS[index]?.recommend}
            />
          ))}
        </div>
      </div>
    </div>
  );
};

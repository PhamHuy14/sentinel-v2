import React, { useEffect } from 'react';
import { useStore } from '../store/useStore';
import { Finding } from '../types';

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

const SEV_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

function buildChecklistFromFindings(findings: Finding[]) {
  // Group findings by OWASP category
  const byCategory: Record<string, Finding[]> = {};
  for (const f of findings) {
    const key = f.owaspCategory?.toUpperCase() || 'OTHER';
    if (!byCategory[key]) byCategory[key] = [];
    byCategory[key].push(f);
  }

  return OWASP_CATS.map(cat => {
    // Match A01, A01:2025, A1 etc.
    const hits = Object.entries(byCategory).filter(([k]) => k.includes(cat.id));
    const allFindings: Finding[] = hits.flatMap(([, fs]) => fs);
    const maxSev = allFindings.reduce((acc, f) => {
      return SEV_ORDER[f.severity] > SEV_ORDER[acc] ? f.severity : acc;
    }, 'low' as string);

    return {
      ...cat,
      count: allFindings.length,
      severity: allFindings.length > 0 ? maxSev : null,
      findings: allFindings.slice(0, 3), // top 3 for preview
    };
  });
}

function sevColor(sev: string | null): string {
  if (!sev) return 'var(--text-3)';
  if (sev === 'critical') return 'var(--crit)';
  if (sev === 'high')     return 'var(--high)';
  if (sev === 'medium')   return 'var(--med)';
  return 'var(--low)';
}

function sevBg(sev: string | null): string {
  if (!sev) return 'var(--bg-input)';
  if (sev === 'critical') return 'var(--crit-bg)';
  if (sev === 'high')     return 'var(--high-bg)';
  if (sev === 'medium')   return 'var(--med-bg)';
  return 'var(--low-bg)';
}

const CheckboxItem: React.FC<{ id: string; label: string }> = ({ id, label }) => {
  const { checkedChecklistItems, toggleChecklistItem } = useStore();
  const checked = checkedChecklistItems.includes(id);
  return (
    <label style={{ display: 'flex', gap: 8, alignItems: 'flex-start', cursor: 'pointer', marginBottom: 6 }}>
      <input 
        type="checkbox" 
        checked={checked} 
        onChange={() => toggleChecklistItem(id)} 
        style={{ marginTop: 3, cursor: 'pointer' }}
      />
      <span style={{ opacity: checked ? 0.6 : 1, textDecoration: checked ? 'line-through' : 'none', flex: 1, fontSize: 13, color: 'var(--text-2)' }}>
        {label}
      </span>
    </label>
  );
};

export const ChecklistPanel: React.FC = () => {
  const { checklist, loadChecklist, projectScanResult } = useStore();

  useEffect(() => {
    loadChecklist();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const projectScan = projectScanResult;
  const hasProjectScan = !!projectScan;

  if (!hasProjectScan) {
    return (
      <div className="empty-state">
        <div className="empty-icon">📂</div>
        <p>Vui lòng chọn mục tiêu và nhấn &quot;Start Scan&quot; ở chế độ <b>Project Scan</b> để tạo Checklist động theo ngữ cảnh dự án.</p>
      </div>
    );
  }

  const items = buildChecklistFromFindings(projectScan.findings);
  const covered = items.filter(i => i.count > 0).length;
  const total   = OWASP_CATS.length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Header summary */}
      <div className="section">
        <div className="section-label">OWASP Top 10 — 2025</div>

        {/* Coverage bar */}
        <div className="chk-coverage">
          <div className="chk-coverage-hdr">
            <span>Coverage</span>
            <span className="chk-coverage-frac">{covered}/{total} categories</span>
          </div>
          <div className="chk-coverage-track">
            <div
              className="chk-coverage-fill"
              style={{ width: `${(covered / total) * 100}%` }}
            />
          </div>
          <div className="chk-coverage-label">
            {covered === 0
              ? 'No issues detected across OWASP categories'
              : `${covered} categories with findings from Project Scan`}
          </div>
        </div>

        {/* Category list */}
        <div className="checklist-grid-adv">
          {items.map(cat => (
            <div
              key={cat.id}
              className={`chk-item ${cat.count > 0 ? 'chk-item-hit' : ''}`}
              style={{
                borderColor: cat.count > 0 ? sevColor(cat.severity) + '55' : undefined,
                background: cat.count > 0 ? sevBg(cat.severity) : undefined,
              }}
            >
              <div className="chk-item-header">
                <span className="chk-id" style={{ color: cat.count > 0 ? sevColor(cat.severity) : undefined }}>
                  {cat.id}
                </span>
                {cat.count > 0 && (
                  <span
                    className="chk-badge"
                    style={{ color: sevColor(cat.severity), borderColor: sevColor(cat.severity) + '55' }}
                  >
                    {cat.count}
                  </span>
                )}
                {cat.count === 0 && (
                  <span className="chk-pass">✓</span>
                )}
              </div>
              <div className="chk-name">{cat.name}</div>
              {cat.count > 0 && cat.severity && (
                <div className="chk-sev" style={{ color: sevColor(cat.severity) }}>
                  {cat.severity}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Context-Based Project Checklist */}
      {hasProjectScan && projectScan.metadata?.techStack && projectScan.metadata.techStack.length > 0 && (
        <div className="section" style={{ marginTop: '16px' }}>
          <div className="section-label">Context-Based Checklist</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 10 }}>
            {projectScan.metadata.techStack.includes('Node.js') || projectScan.metadata.techStack.includes('React') || projectScan.metadata.techStack.includes('Next.js') ? (
              <>
                <CheckboxItem id="chk-node-0" label="Check NPM packages for known vulnerabilities (npm audit)." />
                <CheckboxItem id="chk-node-1" label="Verify JWT secret management and token expiration." />
                <CheckboxItem id="chk-node-2" label="Ensure CORS is configured correctly for React/Next.js APIs." />
                <CheckboxItem id="chk-node-3" label="Check for hardcoded secrets in `.env` files and `.js` source code." />
              </>
            ) : null}
            {projectScan.metadata.techStack.includes('Spring Boot') || projectScan.metadata.techStack.includes('Java') ? (
              <>
                <CheckboxItem id="chk-java-0" label="Verify Spring Actuator endpoints are properly secured and not exposing `/env` or `/heapdump`." />
                <CheckboxItem id="chk-java-1" label="Check Maven/Gradle dependencies for known vulnerabilities." />
                <CheckboxItem id="chk-java-2" label="Ensure proper validation for Spring Data REST endpoints." />
              </>
            ) : null}
            {projectScan.metadata.techStack.includes('PHP') || projectScan.metadata.techStack.includes('Laravel') ? (
              <>
                <CheckboxItem id="chk-php-0" label="Verify `APP_DEBUG` is false in production `.env`." />
                <CheckboxItem id="chk-php-1" label="Check for open debugbar or telescope routes." />
                <CheckboxItem id="chk-php-2" label="Ensure proper file upload validation to prevent RCE." />
              </>
            ) : null}
            {/* Generic item if no specific match, or common items */}
            <CheckboxItem id="chk-generic-0" label={`Review ${projectScan.metadata.techStack.join(', ')} specific configurations.`} />
          </div>
        </div>
      )}

      {/* Design Review questions — always shown */}
      {checklist?.designQuestions && checklist.designQuestions.length > 0 && (
        <div className="section">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 10 }}>
            {checklist.designQuestions.map((q, i) => (
              <CheckboxItem key={`design-${i}`} id={`design-${i}`} label={q} />
            ))}
          </div>
        </div>
      )}

      <button
        className="btn-secondary"
        style={{ width: '100%' }}
        onClick={() => window.owaspWorkbench?.openDocs?.('https://owasp.org/Top10/2025/')}
      >
        Open OWASP Docs
      </button>
    </div>
  );
};

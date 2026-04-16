import React, { useId } from 'react';
import { ScanResult, Finding } from '../types';

interface Props { scanResult: ScanResult }

const SEV_W: Record<string, number> = { critical: 10, high: 7, medium: 4, low: 1 };

function calcRiskScore(findings: Finding[]): number {
  if (!findings.length) return 0;
  return Math.min(100, findings.reduce((s, f) => s + (SEV_W[f.severity] || 0), 0));
}

function riskInfo(s: number) {
  if (s >= 70) return { label: 'RỦI RO NGHIÊM TRỌNG', color: 'var(--crit)' };
  if (s >= 40) return { label: 'RỦI RO CAO',          color: 'var(--high)' };
  if (s >= 15) return { label: 'RỦI RO TRUNG BÌNH',   color: 'var(--med)'  };
  if (s >  0)  return { label: 'RỦI RO THẤP',         color: 'var(--low)'  };
  return              { label: 'AN TOÀN',             color: 'var(--low)'  };
}

const Gauge: React.FC<{ score: number; color: string; clipId: string }> = ({ score, color, clipId }) => {
  const R  = 72, cx = 100, cy = 96;
  const circ  = 2 * Math.PI * R;
  const halfC = Math.PI * R;
  const filled = (score / 100) * halfC;
  const offset = circ * 0.75;
  const rot    = `rotate(-90, ${cx}, ${cy})`;

  return (
    <svg viewBox="0 0 200 104" width="175" height="91" style={{ overflow: 'visible' }}>
      <defs><clipPath id={clipId}><rect x="0" y="0" width="200" height="96" /></clipPath></defs>
      <g clipPath={`url(#${clipId})`}>
        <circle cx={cx} cy={cy} r={R} fill="none" stroke="var(--border)" strokeWidth="13" strokeLinecap="round"
          strokeDasharray={`${halfC} ${circ - halfC}`} strokeDashoffset={offset} transform={rot} />
        <circle cx={cx} cy={cy} r={R} fill="none" stroke={color} strokeWidth="13" strokeLinecap="round"
          strokeDasharray={`${filled} ${circ - filled}`} strokeDashoffset={offset} transform={rot}
          style={{ transition: 'stroke-dasharray 0.7s cubic-bezier(.4,0,.2,1)' }} />
      </g>
      <text x={cx} y={cy - 7} textAnchor="middle" fontSize="30" fontWeight="700" fontFamily="var(--mono)" fill="var(--text)">{score}</text>
      <text x={cx} y={cy + 10} textAnchor="middle" fontSize="9" fill="var(--text-3)">/100</text>
    </svg>
  );
};

// Xu hướng rủi ro so với lần quét trước của cùng mục tiêu
const RiskTrend: React.FC<{ current: number; previous?: number | null }> = ({ current, previous }) => {
  if (previous == null) return null;
  const diff  = current - previous;
  const arrow = diff > 0 ? '▲' : diff < 0 ? '▼' : '–';
  const cls   = diff > 0 ? 'trend-up' : diff < 0 ? 'trend-down' : 'trend-flat';
  return (
    <div className={`rg-trend ${cls}`}>
      <span className="rg-trend-arrow">{arrow}</span>
      <span className="rg-trend-val">{Math.abs(diff)} so với lần trước</span>
    </div>
  );
};

// Nhãn công nghệ phát hiện được
const TechStackPanel: React.FC<{ techStack?: string[] }> = ({ techStack }) => {
  if (!techStack?.length) return null;
  return (
    <div className="rg-tech-stack">
      <div className="rg-bars-hdr">Ngăn xếp công nghệ</div>
      <div className="rg-tech-chips">
        {techStack.map(t => <span key={t} className="tech-chip">{t}</span>)}
      </div>
    </div>
  );
};

// Panel bề mặt tấn công
const AttackSurfacePanel: React.FC<{ attackSurface?: { score: number; exposedRoutes: { route: string; status: number; weight: number }[] } }> = ({ attackSurface }) => {
  if (!attackSurface) return null;
  const score = attackSurface.score;
  const cls   = score >= 60 ? 'as-crit' : score >= 30 ? 'as-high' : 'as-ok';
  const top   = attackSurface.exposedRoutes.slice(0, 5);

  return (
    <div className="rg-attack-surface">
      <div className="rg-bars-hdr">Bề mặt tấn công</div>
      <div className={`as-score-badge ${cls}`}>{score}<span style={{ fontSize: 10, fontWeight: 400 }}>/100</span></div>
      {top.length > 0 && (
        <div className="as-routes">
          {top.map(r => (
            <div key={r.route} className="as-route-row">
              <span className="as-route-path">{r.route}</span>
              <span className={`as-route-status ${r.status === 200 ? 'status-ok' : 'status-redir'}`}>{r.status}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export const RiskDashboard: React.FC<Props> = ({ scanResult }) => {
  const gaugeClipId = useId().replace(/:/g, '_'); // unique per instance
  const { findings, metadata } = scanResult;
  const score   = calcRiskScore(findings);
  const { label, color } = riskInfo(score);
  const byCat   = metadata.summary.byCategory;
  const maxCat  = Math.max(1, ...Object.values(byCat));
  const bySev   = metadata.summary.bySeverity;

  return (
    <div className="risk-dashboard">
      {/* Hàng 1: Gauge + severity + danh mục */}
      <div className="rg-top-row">
        {/* Đồng hồ rủi ro */}
        <div className="rg-gauge-wrap">
          <Gauge score={score} color={color} clipId={`rg-clip-${gaugeClipId}`} />
          <div className="rg-risk-label" style={{ color }}>{label}</div>
          <div className="rg-mode-label">{scanResult.mode === 'url-scan' ? 'URL Scan' : 'Project Scan'}</div>
          <RiskTrend current={score} previous={null} />
        </div>

        {/* Tổng hợp mức độ nghiêm trọng */}
        <div className="rg-sev-summary">
          {(['critical', 'high', 'medium', 'low'] as const).map((sev) => {
            const n = bySev[sev] || 0;
            return (
              <div key={sev} className={`rg-sev-box sev-box-${sev}`}>
                <span className="rg-sev-n">{n}</span>
                <span className="rg-sev-label">{sev.slice(0, 4).toUpperCase()}</span>
              </div>
            );
          })}
        </div>

        {/* Biểu đồ theo danh mục */}
        {Object.keys(byCat).length > 0 && (
          <div className="rg-bars">
            <div className="rg-bars-hdr">Theo danh mục OWASP</div>
            {Object.entries(byCat).sort((a, b) => b[1] - a[1]).map(([cat, count]) => (
              <div key={cat} className="rg-bar-row">
                <span className="rg-bar-cat">{cat}</span>
                <div className="rg-bar-track">
                  <div className="rg-bar-fill" style={{ width: `${(count / maxCat) * 100}%`, background: color }} />
                </div>
                <span className="rg-bar-n">{count}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Hàng 2: tech stack + bề mặt tấn công */}
      {(metadata.techStack || metadata.attackSurface) && (
        <div className="rg-bottom-row">
          <TechStackPanel techStack={metadata.techStack} />
          <AttackSurfacePanel attackSurface={metadata.attackSurface} />
          {metadata.cspAnalysis && !metadata.cspAnalysis.present && (
            <div className="rg-csp-warn">
              <span className="rg-csp-icon">⚠</span>
              <span>Thiếu header Content-Security-Policy</span>
            </div>
          )}
          {metadata.cspAnalysis?.issues && metadata.cspAnalysis.issues.length > 0 && metadata.cspAnalysis.present && (
            <div className="rg-csp-warn">
              <span className="rg-csp-icon">⚠</span>
              <span>Vấn đề CSP: {metadata.cspAnalysis.issues[0]}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

import React, { useState } from 'react';
import { useStore } from '../store/useStore';

const DEPTH_OPTIONS = [
  { value: 0, label: '0 — Chỉ URL gốc', desc: 'Chỉ quét URL chính' },
  { value: 1, label: '1 cấp',           desc: 'Theo các liên kết sâu 1 cấp (khuyến nghị)' },
  { value: 2, label: '2 cấp',           desc: 'Crawl sâu hơn, chậm hơn nhưng bao phủ nhiều bề mặt hơn' },
];

const BUDGET_OPTIONS = [
  { value: 30,  label: '30 yêu cầu',  desc: 'Quét nhanh, các kiểm tra cốt lõi' },
  { value: 60,  label: '60 yêu cầu',  desc: 'Cân bằng, khuyến nghị sử dụng' },
  { value: 100, label: '100 yêu cầu', desc: 'Quét kỹ hơn, nhiều bài test injection hơn' },
  { value: 200, label: '200 yêu cầu', desc: 'Quét chuyên sâu, bao phủ tốt nhất nhưng chậm nhất' },
];

export const UrlScanForm: React.FC = () => {
  const {
    urlInput, setUrlInput, authConfig, setAuthConfig,
    performUrlScan, isLoading,
    crawlDepth, setCrawlDepth, requestBudget, setRequestBudget,
  } = useStore();
  const [showAuth, setShowAuth] = useState(false);

  return (
    <>
      <div className="section">
        <div className="section-label">Mục tiêu</div>

        <div className="field">
          <label className="field-label">URL</label>
          <div className="input-clear-row">
            <input
              type="text"
              placeholder="https://example.com"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              disabled={isLoading}
              onKeyDown={(e) => e.key === 'Enter' && !isLoading && performUrlScan()}
            />
            {urlInput && (
              <button
                type="button"
                className="btn-clear"
                title="Xóa URL"
                disabled={isLoading}
                onClick={() => setUrlInput('')}
              >
                ✕
              </button>
            )}
          </div>
        </div>

        <div className="field-row">
          <div className="field">
            <label className="field-label field-label-inline">
              Độ sâu crawl
              <span className="field-help" title={DEPTH_OPTIONS.find(o => o.value === crawlDepth)?.desc}>?</span>
            </label>
            <select value={crawlDepth} onChange={(e) => setCrawlDepth(Number(e.target.value))} disabled={isLoading}>
              {DEPTH_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>
          <div className="field">
            <label className="field-label field-label-inline">
              Số lượng request
              <span className="field-help" title={BUDGET_OPTIONS.find(o => o.value === requestBudget)?.desc}>?</span>
            </label>
            <select value={requestBudget} onChange={(e) => setRequestBudget(Number(e.target.value))} disabled={isLoading}>
              {BUDGET_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>
        </div>

        {/* Gợi ý cấu hình scan */}
        <div className="scan-profile-hint">
          {crawlDepth >= 2 || requestBudget >= 100
            ? '🔴 Quét kỹ — có thể mất 60–120 giây'
            : crawlDepth === 1 && requestBudget >= 60
            ? '🟡 Quét cân bằng — khoảng 30–60 giây'
            : '🟢 Quét nhanh — khoảng 10–30 giây'}
        </div>
      </div>

      <div className="section">
        <button
          type="button"
          className={`collapsible-btn ${showAuth ? 'open' : ''}`}
          onClick={() => setShowAuth(!showAuth)}
        >
          <span>Xác thực</span>
          <span className={`collapsible-icon ${showAuth ? 'open' : ''}`}>▶</span>
        </button>

        {showAuth && (
          <div className="collapsible-body">
            <div className="field">
              <label className="field-label">Cookie</label>
              <input type="text" placeholder="session=abc123; token=xyz"
                value={authConfig.cookie} onChange={(e) => setAuthConfig({ cookie: e.target.value })} disabled={isLoading} />
            </div>
            <div className="field">
              <label className="field-label">Token Bearer</label>
              <input type="text" placeholder="eyJhbGci..."
                value={authConfig.bearerToken} onChange={(e) => setAuthConfig({ bearerToken: e.target.value })} disabled={isLoading} />
            </div>
            <div className="field">
              <label className="field-label">Header Authorization</label>
              <input type="text" placeholder="Basic dXNlcjpwYXNz"
                value={authConfig.authorization} onChange={(e) => setAuthConfig({ authorization: e.target.value })} disabled={isLoading} />
            </div>
            <div className="field">
              <label className="field-label">Header tùy chỉnh (JSON)</label>
              <textarea
                placeholder='{"X-API-Key": "abc123"}'
                value={typeof authConfig.customHeaders === 'string'
                  ? authConfig.customHeaders
                  : JSON.stringify(authConfig.customHeaders || {}, null, 2)}
                onChange={(e) => setAuthConfig({ customHeaders: e.target.value })}
                disabled={isLoading} rows={2}
              />
            </div>
          </div>
        )}
      </div>

      <button className="btn-primary" onClick={performUrlScan} disabled={isLoading}>
        {isLoading ? 'Đang quét…' : 'Bắt đầu quét'}
      </button>
    </>
  );
};

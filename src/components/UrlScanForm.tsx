import React, { useState } from 'react';
import { useStore } from '../store/useStore';

const DEPTH_OPTIONS = [
  { value: 0, label: '0 — Index only', desc: 'Only scan the main URL' },
  { value: 1, label: '1 level',        desc: 'Follow links 1 level deep (recommended)' },
  { value: 2, label: '2 levels',       desc: 'Deeper crawl — slower, more surface coverage' },
];

const BUDGET_OPTIONS = [
  { value: 30,  label: '30 requests',  desc: 'Fast scan, essential checks' },
  { value: 60,  label: '60 requests',  desc: 'Balanced — recommended' },
  { value: 100, label: '100 requests', desc: 'Thorough — more injection tests' },
  { value: 200, label: '200 requests', desc: 'Deep dive — best coverage, slowest' },
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
        <div className="section-label">Target</div>

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
                title="Clear URL"
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
            <label className="field-label">
              Crawl Depth
              <span className="field-help" title={DEPTH_OPTIONS.find(o => o.value === crawlDepth)?.desc}>?</span>
            </label>
            <select value={crawlDepth} onChange={(e) => setCrawlDepth(Number(e.target.value))} disabled={isLoading}>
              {DEPTH_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>
          <div className="field">
            <label className="field-label">
              Request Budget
              <span className="field-help" title={BUDGET_OPTIONS.find(o => o.value === requestBudget)?.desc}>?</span>
            </label>
            <select value={requestBudget} onChange={(e) => setRequestBudget(Number(e.target.value))} disabled={isLoading}>
              {BUDGET_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>
        </div>

        {/* Scan profile hint */}
        <div className="scan-profile-hint">
          {crawlDepth >= 2 || requestBudget >= 100
            ? '🔴 Thorough scan — may take 60–120s'
            : crawlDepth === 1 && requestBudget >= 60
            ? '🟡 Balanced scan — ~30–60s'
            : '🟢 Quick scan — ~10–30s'}
        </div>
      </div>

      <div className="section">
        <button
          type="button"
          className={`collapsible-btn ${showAuth ? 'open' : ''}`}
          onClick={() => setShowAuth(!showAuth)}
        >
          <span>Authentication</span>
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
              <label className="field-label">Bearer Token</label>
              <input type="text" placeholder="eyJhbGci..."
                value={authConfig.bearerToken} onChange={(e) => setAuthConfig({ bearerToken: e.target.value })} disabled={isLoading} />
            </div>
            <div className="field">
              <label className="field-label">Authorization Header</label>
              <input type="text" placeholder="Basic dXNlcjpwYXNz"
                value={authConfig.authorization} onChange={(e) => setAuthConfig({ authorization: e.target.value })} disabled={isLoading} />
            </div>
            <div className="field">
              <label className="field-label">Custom Headers (JSON)</label>
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
        {isLoading ? 'Scanning…' : 'Start Scan'}
      </button>
    </>
  );
};
